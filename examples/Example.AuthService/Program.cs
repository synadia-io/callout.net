// Copyright (c) Synadia Communications, Inc. All rights reserved.
// Licensed under the Apache License, Version 2.0.

using NATS.Client.Core;
using NATS.Jwt;
using NATS.Jwt.Models;
using NATS.Net;
using NATS.NKeys;
using Synadia.AuthCallout;

// See this for setup instructions:
// https://github.com/synadia-io/callout.go/blob/main/examples/delegated/README.md
Console.WriteLine("Starting Auth Server");

string creds = "/tmp/DA/service.creds";
string calloutIssuer = "/tmp/DA/C.nk";
string issuer = "/tmp/DA/A.nk";

KeyPair ckp = KeyPair.FromSeed(File.ReadAllText(calloutIssuer));
KeyPair akp = KeyPair.FromSeed(File.ReadAllText(issuer));
var jwt = new NatsJwt();

await using var connection = new NatsConnection(new NatsOpts { AuthOpts = new NatsAuthOpts { CredsFile = creds } });

ValueTask<string> Authorizer(NatsAuthorizationRequest r)
{
    NatsUserClaims user = jwt.NewUserClaims(r.UserNKey);

    if (r.NatsConnectOptions.Name == "bad")
    {
        return ValueTask.FromResult(string.Empty);
    }

    return ValueTask.FromResult(jwt.EncodeUserClaims(user, akp));
}

ValueTask<string> ResponseSigner(NatsAuthorizationResponseClaims r)
{
    return ValueTask.FromResult(jwt.EncodeAuthorizationResponseClaims(r, ckp));
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

Console.WriteLine("Press enter to exit");
Console.ReadLine();
