// Copyright (c) Synadia Communications, Inc. All rights reserved.
// Licensed under the Apache License, Version 2.0.

#pragma warning disable

using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
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

        if (_args.Length == 0)
        {
            var go = new Go(_cwd, _exe);
            int e = go.Test();
            return e;
        }
        else if (_args.Length > 0 && _args[0] == "-r")
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
        else
        {
            Err("""
                Usage:
                Run tests: (starts Go test)
                  compat
                Run tests with auth service: (called from Go test)
                  compat -r <suitName> <natsCoordinationUrl>
                """);
            return 1;
        }
    }

    private static async Task InitializeAndStartAuthServiceAndWait(TestContext t, NatsAuthServiceOpts opts)
    {
        await using var service = new NatsAuthService(t.connection.CreateServicesContext(), opts);
        await service.StartAsync(t.cts.Token);
        await t.nt.RequestAsync<string>(t.Subject(SubjectDriverConnected), cancellationToken: t.cts.Token);
        await t.tcs.Task;
    }

    private Func<Exception, CancellationToken, ValueTask> CreateAuthServiceErrorHandler(TestContext t) => async (e, ct) =>
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

            NatsAuthOpts authOpts;
            if (string.IsNullOrWhiteSpace(cv.ServiceCreds))
            {
                authOpts = new NatsAuthOpts { Username = cv.Username, Password = cv.Password };
            }
            else
            {
                authOpts = new NatsAuthOpts { CredsFile = cv.ServiceCreds };
            }

            await using var connection = new NatsConnection(new()
            {
                Url = cv.Url,
                AuthOpts = authOpts,
            });
            var rtt = await connection.PingAsync(cts.Token);
            Log(3, $"Connection RTT {rtt}");

            Log(3, $"{cv}");

            var t = new TestContext
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

    public async Task TestEncryptionMismatch(TestContext t)
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

    public async Task TestSetupOK(TestContext t)
    {
        async ValueTask<string> Authorizer(NatsAuthorizationRequest r, CancellationToken cancellationToken)
        {
            Log(2, $"Auth user: {r.NatsConnectOptions.Username}");
            NatsUserClaims user = t.jwt.NewUserClaims(r.UserNKey);
            user.Audience = t.cv.Audience;
            user.User.Pub.Allow = [t.cv.UserInfoSubj];
            user.User.Sub.Allow = ["_INBOX.>"];
            user.Expires = DateTimeOffset.Now + TimeSpan.FromSeconds(90);

            return t.Encoder.Encode(user);
        }

        async ValueTask<string> ResponseSigner(NatsAuthorizationResponseClaims r, CancellationToken cancellationToken)
        {
            return t.Encoder.Encode(r);
        }

        NatsAuthServiceOpts opts = new(Authorizer, ResponseSigner)
        {
            ErrorHandler = CreateAuthServiceErrorHandler(t),
            EncryptionKey = t.cv.Ekp,
        };

        await InitializeAndStartAuthServiceAndWait(t, opts);
    }

    public async Task TestAbortRequest(TestContext t)
    {
        async ValueTask<string> Authorizer(NatsAuthorizationRequest r, CancellationToken cancellationToken)
        {
            Log(2, $"Auth user: {r.NatsConnectOptions.Username}");

            if (r.NatsConnectOptions.Username == "blacklisted")
            {
                throw new Exception("abort request");
            }

            if (r.NatsConnectOptions.Username == "errorme")
            {
                throw new Exception("service error: testing errorme");
            }

            if (r.NatsConnectOptions.Username == "blank")
            {
                return "";
            }

            NatsUserClaims user = t.jwt.NewUserClaims(r.UserNKey);
            user.Audience = t.cv.Audience;
            user.User.Pub.Allow = [t.cv.UserInfoSubj];
            user.User.Sub.Allow = ["_INBOX.>"];
            user.Expires = DateTimeOffset.Now + TimeSpan.FromSeconds(90);

            return t.Encoder.Encode(user);
        }

        async ValueTask<string> ResponseSigner(NatsAuthorizationResponseClaims r, CancellationToken cancellationToken)
        {
            return t.Encoder.Encode(r);
        }

        NatsAuthServiceOpts opts = new(Authorizer, ResponseSigner)
        {
            ErrorHandler = CreateAuthServiceErrorHandler(t),
            EncryptionKey = t.cv.Ekp,
        };

        await InitializeAndStartAuthServiceAndWait(t, opts);
    }
}
