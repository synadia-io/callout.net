﻿// Copyright (c) Synadia Communications, Inc. All rights reserved.
// Licensed under the Apache License, Version 2.0.

#pragma warning disable

using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using NATS.Client.Core;
using NATS.Jwt;
using NATS.Jwt.Models;
using NATS.Net;
using NATS.NKeys;
using Synadia.AuthCallout;

namespace Compat;

public class Testing
{
    private const string compatTestEncryptionMismatch = "TestEncryptionMismatch";
    private const string compatTestAuthorizerIsRequired = "TestAuthorizerIsRequired";
    private const string compatTestSignerOrKeys = "TestSignerOrKeys";
    private const string compatTestResponseSignerMustBeSeed = "TestResponseSignerMustBeSeed";
    private const string compatTestResponseSignerMustBeAccount = "TestResponseSignerMustBeAccount";
    private const string compatRestResponseSignerIssuerMustBeAccount = "RestResponseSignerIssuerMustBeAccount";
    private const string compatTestResponseSignerIssuerCouldBeSeed = "TestResponseSignerIssuerCouldBeSeed";
    private const string compatTestResponseSignerIssuer = "TestResponseSignerIssuer";
    private const string compatTestResponseSignerIssuerBadType = "TestResponseSignerIssuerBadType";
    private const string compatTestEncryptKey = "TestEncryptKey";
    private const string compatTestEncryptKeyMustBeSeed = "TestEncryptKeyMustBeSeed";
    private const string compatTestSetupOK = "TestSetupOK";
    private const string compatTestAbortRequest = "TestAbortRequest";
    private const string compatTestBadGenerate = "TestBadGenerate";
    private const string compatTestBadPermissions = "TestBadPermissions";
    private const string compatTestBadEncryption = "TestBadEncryption";
    private const string compatTestAsyncWorkers = "TestAsyncWorkers";
    private const string compatTestErrorHandler = "TestErrorHandler";
    private const string compatTestUserErrorHandler = "TestUserErrorHandler";

    private const string BasicAccountEnv = "basic_account_env";
    private const string BasicEncryptedEnv = "basic_encrypted_env";
    private const string DelegatedEnv = "delegated_env";
    private const string DelegatedKeysEnv = "delegated_keys_env";

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

    void Log(int level, string message)
    {
        if (level <= _debug)
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
            var testSub = Task.Run(async () =>
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

            var jsonString = await nt.RequestAsync<string>(Subject(SubjectDriverVars), cancellationToken: cts.Token);
            var json = JsonNode.Parse(jsonString.Data);

            string url;
            string username;
            string password;
            string token;
            string audience;
            string userInfoSubj;
            KeyPair? akp = null;
            KeyPair? ekp = null;
            try
            {
                url = json!["nats_urls"]!.AsArray().First().GetValue<string>();
                username = json["nats_opts"]!["user"]!.GetValue<string>();
                password = json["nats_opts"]!["password"]!.GetValue<string>();
                audience = json["audience"]!.GetValue<string>();
                userInfoSubj = json["user_info_subj"]!.GetValue<string>();
                token = json["nats_opts"]!["token"]!.GetValue<string>();
                string accountSeed = json["account_key"]!["seed"]!.GetValue<string>();
                string accountPk = json["account_key"]!["pk"]!.GetValue<string>();
                if (!string.IsNullOrEmpty(accountSeed))
                {
                    akp = KeyPair.FromSeed(accountSeed);
                    if (accountPk != akp.GetPublicKey())
                    {
                        throw new Exception("Invalid account key");
                    }
                }

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
            }
            catch (Exception e)
            {
                Err($"Error parsing JSON: {e}");
                return;
            }

            Log(3, $$"""
                     VARS:
                         name: {{name}}
                         connecting to server: {{url}}
                         username: {{username}}
                         password: {{password}}
                         token: {{token}}
                         account seed: {{akp.GetSeed()}}
                         account key: {{akp.GetPublicKey()}}
                     """);

            await using var connection = new NatsConnection(new NatsOpts
            {
                Url = url, AuthOpts = new NatsAuthOpts { Username = username, Password = password, Token = token, },
            });
            var rtt = await connection.PingAsync(cts.Token);
            Log(3, $"Connection RTT {rtt}");

            var jwt = new NatsJwt();

            ValueTask<string> Authorizer(NatsAuthorizationRequest r, CancellationToken cancellationToken)
            {
                if (name == compatTestSetupOK)
                {
                    Log(2, $"Auth user: {r.NatsConnectOptions.Username}");
                    NatsUserClaims user = jwt.NewUserClaims(r.UserNKey);
                    user.Audience = audience;
                    user.User.Pub.Allow = [userInfoSubj];
                    user.User.Sub.Allow = ["_INBOX.>"];
                    user.Expires = DateTimeOffset.Now + TimeSpan.FromSeconds(90);
                    return ValueTask.FromResult(jwt.EncodeUserClaims(user, akp));
                }

                if (name == compatTestEncryptionMismatch)
                {
                    // checks at the handler should stop the request before it gets here
                    throw new Exception("Unexpected callback");
                }

                throw new Exception($"Can't find Authorizer for name {name}");
            }

            ValueTask<string> ResponseSigner(NatsAuthorizationResponseClaims r, CancellationToken cancellationToken)
            {
                if (name == compatTestSetupOK)
                {
                    return ValueTask.FromResult(jwt.EncodeAuthorizationResponseClaims(r, akp));
                }

                if (name == compatTestEncryptionMismatch)
                {
                    // checks at the handler should stop the request before it gets here
                    throw new Exception("Unexpected callback");
                }

                throw new Exception($"Can't find ResponseSigner for name {name}");
            }

            NatsAuthServiceOpts opts;
            if (name == compatTestSetupOK)
            {
                opts = new NatsAuthServiceOpts(Authorizer, ResponseSigner)
                {
                    ErrorHandler = async (e, ct) =>
                    {
                        Log(1, $"Auth error: {e}");
                        await nt.PublishAsync(Subject(SubjectDriverError), e.Message, cancellationToken: ct);
                    },
                    EncryptionKey = ekp,
                };
            }
            else if (name == compatTestEncryptionMismatch)
            {
                opts = new NatsAuthServiceOpts(Authorizer, ResponseSigner)
                {
                    ErrorHandler = async (e, ct) =>
                    {
                        Log(1, $"Auth error: {e}");
                        await nt.PublishAsync(Subject(SubjectDriverError), e.Message, cancellationToken: ct);
                    },
                    // do the opposite of the server setup so that when server is sending encrypted
                    // data, the client is not able to decrypt it and vice versa.
                    EncryptionKey = ekp == null ? KeyPair.CreatePair(PrefixByte.Curve) : null,
                };
            }
            else
            {
                throw new Exception($"Can't find options for name {name}");
            }

            await using var service = new NatsAuthService(connection.CreateServicesContext(), opts);

            await service.StartAsync(cts.Token);

            await nt.RequestAsync<string>(Subject(SubjectDriverConnected), cancellationToken: cts.Token);

            await tcs.Task;
            await testSub;
        }).Wait();

        Log(2, "Service stopped");
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
}

// Borrowed from https://stackoverflow.com/questions/3342941/kill-child-process-when-parent-process-is-killed/37034966#37034966

/// <summary>
/// Allows processes to be automatically killed if this parent process unexpectedly quits.
/// This feature requires Windows 8 or greater. On Windows 7, nothing is done.</summary>
/// <remarks>References:
///  https://stackoverflow.com/a/4657392/386091
///  https://stackoverflow.com/a/9164742/386091. </remarks>
#pragma warning disable SA1204
#pragma warning disable SA1129
#pragma warning disable SA1201
#pragma warning disable SA1117
#pragma warning disable SA1400
#pragma warning disable SA1311
#pragma warning disable SA1308
#pragma warning disable SA1413
#pragma warning disable SA1121
public static class ChildProcessTracker
{
    /// <summary>
    /// Add the process to be tracked. If our current process is killed, the child processes
    /// that we are tracking will be automatically killed, too. If the child process terminates
    /// first, that's fine, too.</summary>
    /// <param name="process"></param>
    public static void AddProcess(Process process)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return;
        }

        if (s_jobHandle != IntPtr.Zero)
        {
            var success = AssignProcessToJobObject(s_jobHandle, process.Handle);
            if (!success && !process.HasExited)
            {
                throw new Win32Exception();
            }
        }
    }

    [RequiresDynamicCode("Calls System.Runtime.InteropServices.Marshal.SizeOf(Type)")]
    static ChildProcessTracker()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return;
        }

        // This feature requires Windows 8 or later. To support Windows 7, requires
        //  registry settings to be added if you are using Visual Studio plus an
        //  app.manifest change.
        //  https://stackoverflow.com/a/4232259/386091
        //  https://stackoverflow.com/a/9507862/386091
        if (Environment.OSVersion.Version < new Version(6, 2))
        {
            return;
        }

        // The job name is optional (and can be null), but it helps with diagnostics.
        //  If it's not null, it has to be unique. Use SysInternals' Handle command-line
        //  utility: handle -a ChildProcessTracker
        var jobName = "ChildProcessTracker" + Process.GetCurrentProcess().Id;
        s_jobHandle = CreateJobObject(IntPtr.Zero, jobName);

        var info = new JOBOBJECT_BASIC_LIMIT_INFORMATION();

        // This is the key flag. When our process is killed, Windows will automatically
        //  close the job handle, and when that happens, we want the child processes to
        //  be killed, too.
        info.LimitFlags = JOBOBJECTLIMIT.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

        var extendedInfo = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        extendedInfo.BasicLimitInformation = info;

        var length = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
        var extendedInfoPtr = Marshal.AllocHGlobal(length);
        try
        {
            Marshal.StructureToPtr(extendedInfo, extendedInfoPtr, false);

            if (!SetInformationJobObject(s_jobHandle, JobObjectInfoType.ExtendedLimitInformation,
                    extendedInfoPtr, (uint)length))
            {
                throw new Win32Exception();
            }
        }
        finally
        {
            Marshal.FreeHGlobal(extendedInfoPtr);
        }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string name);

    [DllImport("kernel32.dll")]
    static extern bool SetInformationJobObject(IntPtr job, JobObjectInfoType infoType,
        IntPtr lpJobObjectInfo, uint cbJobObjectInfoLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    // Windows will automatically close any open job handles when our process terminates.
    //  This can be verified by using SysInternals' Handle utility. When the job handle
    //  is closed, the child processes will be killed.
    private static readonly IntPtr s_jobHandle;
}

public enum JobObjectInfoType
{
    AssociateCompletionPortInformation = 7,
    BasicLimitInformation = 2,
    BasicUIRestrictions = 4,
    EndOfJobTimeInformation = 6,
    ExtendedLimitInformation = 9,
    SecurityLimitInformation = 5,
    GroupInformation = 11
}

[StructLayout(LayoutKind.Sequential)]
public struct JOBOBJECT_BASIC_LIMIT_INFORMATION
{
    public long PerProcessUserTimeLimit;
    public long PerJobUserTimeLimit;
    public JOBOBJECTLIMIT LimitFlags;
    public UIntPtr MinimumWorkingSetSize;
    public UIntPtr MaximumWorkingSetSize;
    public uint ActiveProcessLimit;
    public long Affinity;
    public uint PriorityClass;
    public uint SchedulingClass;
}

[Flags]
public enum JOBOBJECTLIMIT : uint
{
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
}

[StructLayout(LayoutKind.Sequential)]
public struct IO_COUNTERS
{
    public ulong ReadOperationCount;
    public ulong WriteOperationCount;
    public ulong OtherOperationCount;
    public ulong ReadTransferCount;
    public ulong WriteTransferCount;
    public ulong OtherTransferCount;
}

[StructLayout(LayoutKind.Sequential)]
public struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
{
    public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
    public IO_COUNTERS IoInfo;
    public UIntPtr ProcessMemoryLimit;
    public UIntPtr JobMemoryLimit;
    public UIntPtr PeakProcessMemoryUsed;
    public UIntPtr PeakJobMemoryUsed;
}
