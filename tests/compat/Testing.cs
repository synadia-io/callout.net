// Copyright (c) Synadia Communications, Inc. All rights reserved.
// Licensed under the Apache License, Version 2.0.

#pragma warning disable

using System.ComponentModel;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Text.Json.Nodes;
using NATS.Client.Core;
using NATS.Jwt;
using NATS.Jwt.Models;
using NATS.Net;
using NATS.NKeys;
using Synadia.AuthCallout;

namespace Compat;

public class Testing
{
    private const string CompatRoot = ".compat.root";
    private readonly string[] _args;
    private readonly string _cwd;
    private readonly string _exe;

    public Testing(string[] args)
    {
        _args = args;
        _exe = Path.GetFullPath(Process.GetCurrentProcess().MainModule!.FileName);
        Console.WriteLine($">>> EXE: {Process.GetCurrentProcess().MainModule!.FileName}");
        Console.WriteLine($">>> EXE: {_exe}");
        _cwd = SetCurrentDirectoryToProjectRoot();
    }

    public int Run()
    {
        if (_args.Length > 0 && _args[0] == "-r")
        {
            Console.WriteLine(">>> Running tests");
            if (_args.Length > 1 && _args[1] == "-")
            {
                string? b64 = Console.In.ReadLine();
                if (b64 != null)
                {
                    var json = JsonNode.Parse(Convert.FromBase64String(b64));
                    Console.WriteLine($"JSON: {json}");
                    Console.WriteLine(">>> end of JSON");
                    Connect(json);
                }
                else
                {
                    Console.Error.WriteLine("Expected JSON data in stdin");
                    return 1;
                }
            }
            else
            {
                Console.Error.WriteLine("No JSON data provided");
                return 1;
            }

            return 0;
        }

        var go = new Go(_cwd, _exe);
        int e = go.Test();

        Console.WriteLine("Bye!");

        return e;
    }

    private void Connect(JsonNode? json)
    {
        Console.WriteLine("Connecting...");

        string url;
        string username;
        string password;
        string token;
        string audience;
        string userInfoSubj;
        KeyPair akp;
        try
        {
            url = json!["nats_urls"]!
                .AsArray()
                .Select(x => x!.GetValue<string>())
                .First();

            // .First(x => x.Contains("127.0.0.1"));
            username = json["nats_opts"]!["user"]!.GetValue<string>();
            password = json["nats_opts"]!["password"]!.GetValue<string>();
            audience = json["audience"]!.GetValue<string>();
            userInfoSubj = json["user_info_subj"]!.GetValue<string>();
            token = json["nats_opts"]!["token"]!.GetValue<string>();
            string accountSeed = json["account_key"]!["seed"]!.GetValue<string>();
            string accountPk = json["account_key"]!["pk"]!.GetValue<string>();
            akp = KeyPair.FromSeed(accountSeed);
            if (accountPk != akp.GetPublicKey())
            {
                throw new Exception("Invalid account key");
            }
        }
        catch (Exception e)
        {
            Console.Error.WriteLine($"Error parsing JSON: {e}");
            return;
        }

        Console.WriteLine($"""
                           >>> Connecting to NATS server: {url}
                               username: {username}
                               password: {password}
                               token: {token}
                               account seed: {akp.GetSeed()}
                               account key: {akp.GetPublicKey()}
                           """);

        Task.Run(async () =>
        {
            await using var connection = new NatsConnection(new NatsOpts
            {
                Url = url,
                AuthOpts = new NatsAuthOpts
                {
                    Username = username,
                    Password = password,
                    Token = token,
                },
            });
            var rtt = await connection.PingAsync();
            Console.WriteLine($"RTT: {rtt}");

            var jwt = new NatsJwt();

            ValueTask<string> Authorizer(NatsAuthorizationRequest r)
            {
                Console.WriteLine($">>> USER CONNECTING: {r.NatsConnectOptions.Username}");

                NatsUserClaims user = jwt.NewUserClaims(r.UserNKey);
                user.Audience = audience;
                user.User.Pub.Allow = [userInfoSubj];
                user.User.Sub.Allow = ["_INBOX.>"];
                user.Expires = DateTimeOffset.Now + TimeSpan.FromSeconds(90);
                return ValueTask.FromResult(jwt.EncodeUserClaims(user, akp));
            }

            ValueTask<string> ResponseSigner(NatsAuthorizationResponseClaims r)
            {
                return ValueTask.FromResult(jwt.EncodeAuthorizationResponseClaims(r, akp));
            }

            var opts = new NatsAuthServiceOpts(Authorizer, ResponseSigner)
            {
                ErrorHandler = e =>
                {
                    Console.WriteLine($"ERROR: {e}");
                    return default;
                },
            };

            await using var service = new NatsAuthService(connection.CreateServicesContext(), opts);

            await service.StartAsync();

            new ManualResetEventSlim().Wait();
        }).Wait();

        Console.WriteLine("CONNECT DONE");
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
