// Copyright (c) Synadia Communications, Inc. All rights reserved.
// Licensed under the Apache License, Version 2.0.

#pragma warning disable

using System.Diagnostics;

namespace Compat;

public class Go
{
    private readonly string _cwd;
    private readonly string _exe;

    public Go(string cwd, string exe)
    {
        _cwd = cwd;
        _exe = exe;
    }

    public int Test() => GoExe("test -v");

    private int GoExe(string args)
    {
        var go = new Process
        {
            StartInfo = new ProcessStartInfo
            {
                FileName = "go",
                Arguments = args,
                WorkingDirectory = _cwd,
                EnvironmentVariables =
                {
                    ["X_COMPAT_EXE"] = _exe,
                },
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardError = true,
                RedirectStandardOutput = true,
            },
        };

        go.OutputDataReceived += (s, e) => { Console.WriteLine(e.Data); };
        go.ErrorDataReceived += (s, e) => { Console.WriteLine(e.Data); };

        go.Start();

        ChildProcessTracker.AddProcess(go);

        go.BeginErrorReadLine();
        go.BeginOutputReadLine();

        var timeout = TimeSpan.FromMinutes(5);

        if (!go.WaitForExit(timeout))
        {
            go.Kill();
            Console.Error.WriteLine($"Go timed out after {timeout} killing process");
            return 4;
        }

        return go.ExitCode;
    }
}
