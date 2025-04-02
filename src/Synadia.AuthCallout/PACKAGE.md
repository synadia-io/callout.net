# Auth Callout Service

This library implements a small framework for writing AuthCallout services for NATS.

```csharp
string calloutIssuer = "/path/to/seed/file/C.nk";
string issuer = "/path/to/seed/file/A.nk";

KeyPair ckp = KeyPair.FromSeed(File.ReadAllText(calloutIssuer));
KeyPair akp = KeyPair.FromSeed(File.ReadAllText(issuer));
var jwt = new NatsJwt();

await using var connection = new NatsConnection(new NatsOpts { AuthOpts = new NatsAuthOpts { CredsFile = "/path/to/service.creds" } });

async ValueTask<string> Authorizer(NatsAuthorizationRequest r)
{
    NatsUserClaims user = jwt.NewUserClaims(r.UserNKey);
    return jwt.EncodeUserClaims(user, akp);
}

async ValueTask<string> ResponseSigner(NatsAuthorizationResponseClaims r)
{
    return jwt.EncodeAuthorizationResponseClaims(r, ckp);
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
```

See also [NATS Auth Callout documentation](https://docs.nats.io/running-a-nats-service/configuration/securing_nats/auth_callout).
