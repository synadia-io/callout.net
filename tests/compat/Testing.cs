// Copyright (c) Synadia Communications, Inc. All rights reserved.
// Licensed under the Apache License, Version 2.0.

#pragma warning disable

using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using NATS.Client.Core;
using NATS.Jwt;
using NATS.Jwt.Models;
using NATS.Net;
using NATS.NKeys;
using Synadia.AuthCallout;

namespace Compat;

public class Testing
{
    private const string SubjectServiceAll = ".test.service.>";
    private const string SubjectServiceStop = ".test.service.stop";
    private const string SubjectServiceSync = ".test.service.sync";
    private const string SubjectDriverConnected = ".test.driver.connected";
    private const string SubjectDriverError = ".test.driver.error";
    private const string SubjectDriverSync = ".test.driver.sync";
    private const string SubjectDriverVars = ".test.driver.vars";

    private const string LogName = "SERV";
    private const string EnvCompatDebug = "X_COMPAT_DEBUG";
    private const string CompatRoot = ".compat.root";
    private readonly string[] _args;
    private readonly string _cwd;
    private readonly string _exe;
    private readonly int _debug;

    public Testing(string[] args)
    {
        _args = args;
        _exe = Path.GetFullPath(Process.GetCurrentProcess().MainModule!.FileName);
        _cwd = SetCurrentDirectoryToProjectRoot();
        _debug = GetDebugFlagValue();
        Log(1, $"Starting...");
        Log(3, $"Exe path {_exe}");
    }

    private static string SetCurrentDirectoryToProjectRoot()
    {
        var cwd = new DirectoryInfo(Directory.GetCurrentDirectory());

        while (cwd!.GetFiles().All(f => f.Name != CompatRoot))
        {
            cwd = cwd.Parent;
        }

        Directory.SetCurrentDirectory(cwd.FullName);

        return cwd.FullName;
    }

    bool WillLog(int level) => level <= _debug;

    void Log(int level, string message)
    {
        if (WillLog(level))
        {
            Console.WriteLine($"[{LogName}] [{level}] {message}");
        }
    }

    void Err(string message)
    {
        Console.Error.WriteLine($"[{LogName}] ERROR {message}");
    }

    private int GetDebugFlagValue()
    {
        string? debugString = Environment.GetEnvironmentVariable(EnvCompatDebug);
        if (debugString == null)
        {
            return 0;
        }

        debugString = debugString.Trim().ToLowerInvariant();
        if (Regex.IsMatch(debugString, @"^(-|\+)?\s*\d+$"))
        {
            return int.Parse(debugString);
        }

        return Regex.IsMatch(debugString, @"^(false|no|off)$") ? 0 : 1;
    }

    public int Run()
    {
        Log(3, $"Args: {string.Join(" ", _args)}");

        if (_args.Length > 0 && _args[0] == "-r")
        {
            Log(1, "Running tests...");
            if (_args.Length > 2)
            {
                string suitName = _args[1];
                string natsCoordinationUrl = _args[2];
                try
                {
                    Log(3, $"Starting auth service for '{suitName}' on '{natsCoordinationUrl}'");
                    StartAuthServiceAndWaitForTests(suitName, natsCoordinationUrl);

                    Log(1, "Tests completed");
                    return 0;
                }
                catch (Exception e1)
                {
                    Err($"Error starting auth service: {e1}");
                    return 1;
                }
            }
            else
            {
                Err("No NATS tests coordination URL provided");
                return 1;
            }
        }

        var go = new Go(_cwd, _exe);
        int e = go.Test();

        Log(1, "Bye!");

        return e;
    }

    private static async Task InitializeAndStartAuthServiceAndWait(T t, NatsAuthServiceOpts opts)
    {
        await using var service = new NatsAuthService(t.connection.CreateServicesContext(), opts);
        await service.StartAsync(t.cts.Token);
        await t.nt.RequestAsync<string>(t.Subject(SubjectDriverConnected), cancellationToken: t.cts.Token);
        await t.tcs.Task;
    }

    private Func<Exception, CancellationToken, ValueTask> CreateAuthServiceErrorHandler(T t) => async (e, ct) =>
    {
        Log(1, $"Auth error: {e}");
        await t.nt.PublishAsync(t.Subject(SubjectDriverError), e.Message, cancellationToken: ct);
    };

    private void StartAuthServiceAndWaitForTests(string suitName, string natsCoordinationUrl)
    {
        string[] parts = suitName.Split('/');
        string env = parts[0];
        string name = parts[1];
        string Subject(string subject) => suitName + subject;

        Log(2, $"Connecting to '{natsCoordinationUrl}' for env:{env} name:{name} ...");

        Task.Run(async () =>
        {
            await using var nt = new NatsConnection(new NatsOpts { Url = natsCoordinationUrl });
            var rttTest = await nt.PingAsync();
            Log(1, $"Ping to test coordination server {natsCoordinationUrl}: {rttTest}");
            var cts = new CancellationTokenSource();
            var tcs = new TaskCompletionSource();
            var serviceSub = Task.Run(async () =>
            {
                await foreach (NatsMsg<string> m in nt.SubscribeAsync<string>(Subject(SubjectServiceAll),
                                   cancellationToken: cts.Token))
                {
                    if (m.Subject == Subject(SubjectServiceSync))
                    {
                        await m.ReplyAsync("Ok", cancellationToken: cts.Token);
                    }
                    else if (m.Subject == Subject(SubjectServiceStop))
                    {
                        Log(2, "Stopping test service");
                        await cts.CancelAsync();
                        tcs.TrySetResult();
                        break;
                    }
                }
            }, cts.Token);

            var jsonMsg = await nt.RequestAsync<string>(Subject(SubjectDriverVars), cancellationToken: cts.Token);

            if (WillLog(4))
            {
                Log(4, JsonNode.Parse(jsonMsg.Data).ToString());
            }

            CompatVars cv = CompatVars.FromJson(suitName, jsonMsg.Data);

            await using var connection = new NatsConnection(new()
            {
                Url = cv.Url,
                AuthOpts = new NatsAuthOpts { Username = cv.Username, Password = cv.Password, Token = cv.Token, },
            });
            var rtt = await connection.PingAsync(cts.Token);
            Log(3, $"Connection RTT {rtt}");

            Log(3, $"{cv}");

            var t = new T
            {
                suitName = suitName,
                name = name,
                env = env,
                cv = cv,
                cts = cts,
                tcs = tcs,
                nt = nt,
                connection = connection,
                jwt = new NatsJwt(),
            };

            MethodInfo? methodInfo = GetType().GetMethod(name);
            if (methodInfo == null)
            {
                throw new Exception($"No test method found for '{name}'");
            }

            Log(2, $"Calling test method '{name}'");
            await (Task)methodInfo.Invoke(this, [t]);

            await serviceSub;
        }).Wait();

        Log(2, "Service stopped");
    }

    public async Task TestEncryptionMismatch(T t)
    {
        ValueTask<string> Authorizer(NatsAuthorizationRequest r, CancellationToken cancellationToken)
        {
            throw new Exception("checks at the handler should stop the request before it gets here");
        }

        ValueTask<string> ResponseSigner(NatsAuthorizationResponseClaims r, CancellationToken cancellationToken)
        {
            throw new Exception("checks at the handler should stop the request before it gets here");
        }

        NatsAuthServiceOpts opts = new(Authorizer, ResponseSigner)
        {
            ErrorHandler = CreateAuthServiceErrorHandler(t),

            // do the opposite of the server setup so that when server is sending encrypted
            // data, the client is not able to decrypt it and vice versa.
            EncryptionKey = t.cv.Ekp == null ? KeyPair.CreatePair(PrefixByte.Curve) : null,
        };

        await InitializeAndStartAuthServiceAndWait(t, opts);
    }

    public async Task TestSetupOK(T t)
    {
        ValueTask<string> Authorizer(NatsAuthorizationRequest r, CancellationToken cancellationToken)
        {
            Log(2, $"Auth user: {r.NatsConnectOptions.Username}");
            NatsUserClaims user = t.jwt.NewUserClaims(r.UserNKey);
            user.Audience = t.cv.Audience;
            user.User.Pub.Allow = [t.cv.UserInfoSubj];
            user.User.Sub.Allow = ["_INBOX.>"];
            user.Expires = DateTimeOffset.Now + TimeSpan.FromSeconds(90);
            return ValueTask.FromResult(t.jwt.EncodeUserClaims(user, t.cv.AccountKeys["A"]));
        }

        ValueTask<string> ResponseSigner(NatsAuthorizationResponseClaims r, CancellationToken cancellationToken)
        {
            return ValueTask.FromResult(t.jwt.EncodeAuthorizationResponseClaims(r, t.cv.AccountKeys["A"]));
        }

        NatsAuthServiceOpts opts = new(Authorizer, ResponseSigner)
        {
            ErrorHandler = CreateAuthServiceErrorHandler(t), EncryptionKey = t.cv.Ekp,
        };

        await InitializeAndStartAuthServiceAndWait(t, opts);
    }
}

public record T
{
    public CompatVars cv { get; init; }
    public CancellationTokenSource cts { get; init; }
    public TaskCompletionSource tcs { get; init; }
    public NatsConnection nt { get; init; }
    public NatsConnection connection { get; init; }
    public string name { get; init; }
    public string suitName { get; init; }
    public NatsJwt jwt { get; init; }
    public string env { get; init; }

    public string Subject(string suffix)
    {
        return suitName + suffix;
    }
}

public record CompatVars
{
    public string SuitName { get; init; }
    public string Name { get; init; }
    public string Env { get; init; }
    public string Url { get; init; }
    public string Username { get; init; }
    public string Password { get; init; }
    public string Token { get; init; }
    public string Audience { get; init; }
    public string UserInfoSubj { get; init; }

    public Dictionary<string, KeyPair> AccountKeys { get; init; }
    public KeyPair? Ekp { get; init; }

    public static CompatVars FromJson(string suitName, string jsonString)
    {
        string[] parts = suitName.Split('/');
        string env = parts[0];
        string name = parts[1];

        var json = JsonNode.Parse(jsonString);
        if (json == null)
        {
            throw new Exception("Failed to parse JSON");
        }

        Dictionary<string, KeyPair> keys = new();
        foreach ((string? key, JsonNode? value) in json["account_keys"].AsObject())
        {
            if (string.IsNullOrWhiteSpace(key) || value == null) continue;
            string seed = value["seed"]!.GetValue<string>();
            string pk = value["pk"]!.GetValue<string>();
            if (!string.IsNullOrEmpty(seed))
            {
                var kp = KeyPair.FromSeed(seed);
                if (pk != kp.GetPublicKey())
                {
                    throw new Exception("Invalid account key");
                }

                keys[key] = kp;
            }
        }

        KeyPair? ekp = null;
        string encryptionSeed = json["encryption_key"]!["seed"]!.GetValue<string>();
        string encryptionPk = json["encryption_key"]!["pk"]!.GetValue<string>();
        if (!string.IsNullOrEmpty(encryptionSeed))
        {
            ekp = KeyPair.FromSeed(encryptionSeed);
            if (encryptionPk != ekp.GetPublicKey())
            {
                throw new Exception("Invalid encryption key");
            }
        }

        return new CompatVars
        {
            SuitName = suitName,
            Name = name,
            Env = env,
            Url = json!["nats_urls"]!.AsArray().First().GetValue<string>(),
            Username = json["nats_opts"]!["user"]!.GetValue<string>(),
            Password = json["nats_opts"]!["password"]!.GetValue<string>(),
            Token = json["nats_opts"]!["token"]!.GetValue<string>(),
            Audience = json["audience"]!.GetValue<string>(),
            UserInfoSubj = json["user_info_subj"]!.GetValue<string>(),
            Dir = json["dir"]!.GetValue<string>(),
            NscDir = json["nsc_dir"]!.GetValue<string>(),
            Ekp = ekp,
            AccountKeys = keys,
        };
    }

    public string NscDir { get; init; }

    public string Dir { get; init; }
}

class NscStore
{
    private readonly DirectoryInfo _dir;
    private readonly DirectoryInfo _stores;
    private readonly DirectoryInfo _keys;

    public NscStore(string dir)
    {
        _dir = new DirectoryInfo(dir);
        _stores = new DirectoryInfo(Path.Combine(dir, "stores"));
        _keys = new DirectoryInfo(Path.Combine(dir, "keys", "keys"));
    }

    public IEnumerable<NscOperator> LoadOperators()
    {
        foreach (DirectoryInfo d in _stores.GetDirectories())
        {
            yield return NscOperator.Load(this, d);
        }
    }

    public KeyPair? LoadKey(string? pk)
    {
        if (pk == null)
        {
            return null;
        }

        string nk = Path.Combine(_keys.FullName, pk[..1], pk[1..3], $"{pk}.nk");
        KeyPair kp = KeyPair.FromSeed(File.ReadAllText(nk));
        if (kp.GetPublicKey() != pk)
        {
            throw new Exception($"Load key error: invalid key {pk}");
        }

        return kp;
    }

    public JsonNode LoadJwtPayload(DirectoryInfo dir)
    {
        return LoadJwtPayload(dir.GetFiles().First(f => f.Extension == ".jwt"));
    }

    public JsonNode LoadJwtPayload(FileInfo file)
    {
        string jwt = file.OpenText().ReadToEnd();
        return JsonNode.Parse(EncodingUtils.FromBase64UrlEncoded(jwt.Split('.')[1]));
    }

    public (KeyPair Issuer, KeyPair Subject) GetIssuerAndSubjectKeys(JsonNode json)
    {
        string iss = json["iss"].GetValue<string>();
        string sub = json["sub"].GetValue<string>();
        return (LoadKey(iss), LoadKey(sub));
    }
}

record NscEntry
{
    public string Name { get; init; }
    public KeyPair Issuer { get; init; }
    public KeyPair Subject { get; init; }
    public JsonNode JwtPayload { get; init; }
}

record NscOperator : NscEntry
{
    public static NscOperator Load(NscStore store, DirectoryInfo dir)
    {
        var payload = store.LoadJwtPayload(dir);
        (KeyPair issuer, KeyPair subject) = store.GetIssuerAndSubjectKeys(payload);

        var systemAccount = store.LoadKey(payload["nats"]?["system_account"]?.GetValue<string>());

        var accounts = new List<NscAccount>();
        foreach (DirectoryInfo d in dir.GetDirectories().First(f => f.Name == "accounts").GetDirectories())
        {
            accounts.Add(NscAccount.Load(store, d));
        }

        return new NscOperator
        {
            Name = dir.Name,
            JwtPayload = payload,
            Issuer = issuer,
            Subject = subject,
            Accounts = accounts,
            SystemAccount = systemAccount,
        };
    }

    public KeyPair? SystemAccount { get; init; }
    public List<NscAccount> Accounts { get; init; } = new();
}

record NscAccount : NscEntry
{
    public List<NscUser> Users { get; init; } = new();

    public List<KeyPair> SigningKeys { get; init; } = new();

    public List<KeyPair> AuthorizationAllowedAccounts { get; init; } = new();

    public List<KeyPair> AuthorizationAuthUsers { get; init; } = new();

    public static NscAccount Load(NscStore store, DirectoryInfo dir)
    {
        var payload = store.LoadJwtPayload(dir);
        (KeyPair issuer, KeyPair subject) = store.GetIssuerAndSubjectKeys(payload);

        var signingKeys = new List<KeyPair>();
        if (payload["nats"]?["signing_keys"]?.AsArray() is { } keysArray)
        {
            foreach (JsonNode? jsonNode in keysArray)
            {
                if (jsonNode == null)
                {
                    continue;
                }
                string? key = jsonNode.GetValue<string>();
                KeyPair? signingKey = store.LoadKey(key);
                if (signingKey != null)
                {
                    signingKeys.Add(signingKey);
                }
            }
        }

        var authorizationAllowedAccounts = new List<KeyPair>();
        if (payload["nats"]?["authorization"]?["allowed_accounts"]?.AsArray() is { } keysArray2)
        {
            foreach (JsonNode? jsonNode in keysArray2)
            {
                if (jsonNode == null)
                {
                    continue;
                }
                string? key = jsonNode.GetValue<string>();
                KeyPair? signingKey = store.LoadKey(key);
                if (signingKey != null)
                {
                    authorizationAllowedAccounts.Add(signingKey);
                }
            }
        }

        var authorizationAuthUsers = new List<KeyPair>();
        if (payload["nats"]?["authorization"]?["auth_users"]?.AsArray() is { } keysArray3)
        {
            foreach (JsonNode? jsonNode in keysArray3)
            {
                if (jsonNode == null)
                {
                    continue;
                }
                string? key = jsonNode.GetValue<string>();
                KeyPair? signingKey = store.LoadKey(key);
                if (signingKey != null)
                {
                    authorizationAuthUsers.Add(signingKey);
                }
            }
        }

        var users = new List<NscUser>();
        DirectoryInfo usersDir = dir.GetDirectories().FirstOrDefault(f => f.Name == "users");
        if (usersDir != null)
        {
            foreach (FileInfo j in usersDir.GetFiles().Where(f => f.Extension == ".jwt"))
            {
                users.Add(NscUser.Load(store, j));
            }
        }

        return new NscAccount
        {
            Name = dir.Name,
            JwtPayload = payload,
            SigningKeys = signingKeys,
            AuthorizationAllowedAccounts = authorizationAllowedAccounts,
            AuthorizationAuthUsers = authorizationAuthUsers,
            Issuer = issuer,
            Subject = subject,
            Users = users,
        };
    }
}

record NscUser : NscEntry
{
    public static NscUser Load(NscStore store, FileInfo file)
    {
        var payload = store.LoadJwtPayload(file);
        (KeyPair issuer, KeyPair subject) = store.GetIssuerAndSubjectKeys(payload);
        return new NscUser
        {
            Name = file.Name, JwtPayload = payload, Issuer = issuer, Subject = subject,
        };
    }
}
