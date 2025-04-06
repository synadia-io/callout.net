// Copyright (c) Synadia Communications, Inc. All rights reserved.
// Licensed under the Apache License, Version 2.0.

#pragma warning disable

//
// COMPATIBILITY TESTS
//
// To run compatibility tests, run this application without any arguments.
// You must have the Go SDK installed and available in your PATH.
//
// Alternatively, you can run the Go tests in a terminal with the following commands:
//
// powershell:
//  $env:X_COMPAT_EXE = "bin/Debug/net8.0/compat"
//  $env:X_COMPAT_DEBUG = 0
//
// sh/bash:
//  export X_COMPAT_EXE=bin/Debug/net8.0/compat
//  export X_COMPAT_DEBUG=0
//
// both shells:
//  cd tests/compat
//  dotnet build
//  go test -v
//

using Compat;

// var store = new NscStore("C:\\Users\\mtmk\\.local\\share\\nats\\nsc");
// foreach (NscOperator op in store.LoadOperators())
// {
//     Console.WriteLine(op);
//     foreach (NscAccount acc in op.Accounts)
//     {
//         Console.WriteLine(acc);
//         foreach (NscUser user in acc.Users)
//         {
//             Console.WriteLine(user);
//         }
//     }
// }
// return 1;

var t = new Testing(args);
return t.Run();
