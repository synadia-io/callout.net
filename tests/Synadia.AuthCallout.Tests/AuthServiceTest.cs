// Copyright (c) Synadia Communications, Inc. All rights reserved.
// Licensed under the Apache License, Version 2.0.

using System.Text;
using NATS.Client.Core;
using NATS.Jwt;
using NATS.Jwt.Models;
using NATS.Net;
using NATS.NKeys;

namespace Synadia.AuthCallout.Tests;

public class AuthServiceTest(ITestOutputHelper output)
{
    [Fact]
    public async Task Connect_with_jwt()
    {
        var jwt = new NatsJwt();
        var okp = KeyPair.CreatePair(PrefixByte.Operator);
        var opk = okp.GetPublicKey();
        var oc = jwt.NewOperatorClaims(opk);
        oc.Name = "Example Operator";
        var oskp = KeyPair.CreatePair(PrefixByte.Operator);
        var ospk = oskp.GetPublicKey();
        oc.Operator.SigningKeys = [ospk];
        var operatorJwt = jwt.EncodeOperatorClaims(oc, okp);

        var akp = KeyPair.CreatePair(PrefixByte.Account);
        var apk = akp.GetPublicKey();
        var ac = jwt.NewAccountClaims(apk);
        ac.Name = "Example Account";
        var askp = KeyPair.CreatePair(PrefixByte.Account);
        var aspk = askp.GetPublicKey();
        ac.Account.SigningKeys = [aspk];
        var accountJwt = jwt.EncodeAccountClaims(ac, oskp);

        string conf = $$"""
                        operator: {{operatorJwt}}
                        resolver: MEMORY
                        resolver_preload: {
                                {{apk}}: {{accountJwt}}
                        }
                        """;
        const string confPath = $"server_{nameof(Connect_with_jwt)}.conf";
        File.WriteAllText(confPath, conf);
        await using var server = await NatsServerProcess.StartAsync(logger: Logger, config: confPath);

        var ukp = KeyPair.CreatePair(PrefixByte.User);
        var upk = ukp.GetPublicKey();
        var uc = jwt.NewUserClaims(upk);
        uc.User.IssuerAccount = apk;
        var userJwt = jwt.EncodeUserClaims(uc, askp);
        var userSeed = ukp.GetSeed();

        var authOpts = new NatsAuthOpts { Jwt = userJwt, Seed = userSeed };
        var opts = new NatsOpts { Url = server.Url, AuthOpts = authOpts };
        await using var nats = new NatsConnection(opts);
        await nats.PingAsync();
    }

    [Fact]
    public async Task Connect_with_callout()
    {
        var jwt = new NatsJwt();

        var akp = KeyPair.CreatePair(PrefixByte.Account);
        var apk = akp.GetPublicKey();

        string conf = $$"""
                        accounts {
                          AUTH: { users: [ { user: auth } ] }
                          SYS: { users: [ { user: sys } ] }
                        }
                        system_account: SYS
                        authorization {
                          auth_callout {
                            issuer: "{{apk}}"
                            auth_users: [ auth, sys ]
                            account: AUTH
                          }
                        }
                        """;
        const string confPath = $"server_{nameof(Connect_with_callout)}.conf";
        File.WriteAllText(confPath, conf);
        await using var server = await NatsServerProcess.StartAsync(logger: Logger, config: confPath);

        await using var authNats = new NatsConnection(new NatsOpts { Url = server.Url, AuthOpts = new NatsAuthOpts { Username = "auth" } });
        await authNats.PingAsync();

        var opts = new NatsAuthServiceOpts(
            authorizer: (r, ct) =>
            {
                NatsUserClaims user = jwt.NewUserClaims(r.UserNKey);
                user.Audience = "AUTH";
                user.Name = Convert.ToBase64String(Encoding.UTF8.GetBytes("User1"));
                user.User.Pub.Allow = [">"];
                user.User.Sub.Allow = [">"];

                if (r.NatsConnectOptions.Name == "bad")
                {
                    return ValueTask.FromResult(new NatsAuthorizerResult(string.Empty, 401, "Unauthorized"));
                }

                return ValueTask.FromResult(new NatsAuthorizerResult(jwt.EncodeUserClaims(user, akp)));
            },
            responseSigner: (r, ct) => ValueTask.FromResult(jwt.EncodeAuthorizationResponseClaims(r, akp)))
        {
            ErrorHandler = (e, ct) =>
            {
                output.WriteLine($"SERVICE ERROR: {e}");
                return default;
            },
        };
        var service = new NatsAuthService(authNats.CreateServicesContext(), opts);
        await service.StartAsync();

        await Task.Delay(1000);

        await using var client1 = new NatsConnection(new NatsOpts { Url = server.Url, AuthOpts = new NatsAuthOpts { Username = "bob" } });
        await client1.PingAsync();

        await using var client2 = new NatsConnection(new NatsOpts { Name = "bad", Url = server.Url, AuthOpts = new NatsAuthOpts { Username = "bob" } });
        var exception = await Assert.ThrowsAsync<NatsException>(async () => await client2.ConnectAsync());
        Assert.NotNull(exception.InnerException);
        output.WriteLine($"ERROR: {exception}");

        // TODO: this sometimes comes as NatsServerException: Server error: Authorization Violation
        // var serverException = exception.InnerException;
        // Assert.IsType<TimeoutException>(serverException);
    }

    [Fact]
    public async Task Connect_with_callout_with_xkey()
    {
        var jwt = new NatsJwt();

        var xkp = KeyPair.CreatePair(PrefixByte.Curve);

        var akp = KeyPair.CreatePair(PrefixByte.Account);
        var apk = akp.GetPublicKey();

        string conf = $$"""
                        accounts {
                          AUTH: { users: [ { user: auth } ] }
                          SYS: { users: [ { user: sys } ] }
                        }
                        system_account: SYS
                        authorization {
                          auth_callout {
                            issuer: "{{apk}}"
                            auth_users: [ auth, sys ]
                            account: AUTH
                            xkey: "{{xkp.GetPublicKey()}}"
                          }
                        }
                        """;
        const string confPath = $"server_{nameof(Connect_with_callout_with_xkey)}.conf";
        File.WriteAllText(confPath, conf);
        await using var server = await NatsServerProcess.StartAsync(logger: Logger, config: confPath);

        await using var authNats = new NatsConnection(new NatsOpts { Url = server.Url, AuthOpts = new NatsAuthOpts { Username = "auth" } });
        await authNats.PingAsync();

        var opts = new NatsAuthServiceOpts(
            authorizer: (r, ct) =>
            {
                NatsUserClaims user = jwt.NewUserClaims(r.UserNKey);
                user.Audience = "AUTH";
                user.Name = Convert.ToBase64String(Encoding.UTF8.GetBytes("User1"));
                user.User.Pub.Allow = [">"];
                user.User.Sub.Allow = [">"];

                if (r.NatsConnectOptions.Name == "bad")
                {
                    return ValueTask.FromResult(new NatsAuthorizerResult(string.Empty, 401, "Unauthorized"));
                }

                return ValueTask.FromResult(new NatsAuthorizerResult(jwt.EncodeUserClaims(user, akp)));
            },
            responseSigner: (r, ct) => ValueTask.FromResult(jwt.EncodeAuthorizationResponseClaims(r, akp)))
        {
            EncryptionKey = xkp,
            ErrorHandler = (e, ct) =>
            {
                output.WriteLine($"SERVICE ERROR: {e}");
                return default;
            },
        };
        var service = new NatsAuthService(authNats.CreateServicesContext(), opts);
        await service.StartAsync();

        await Task.Delay(1000);

        await using var client1 = new NatsConnection(new NatsOpts { Url = server.Url, AuthOpts = new NatsAuthOpts { Username = "bob" } });
        await client1.PingAsync();

        await using var client2 = new NatsConnection(new NatsOpts { Name = "bad", Url = server.Url, AuthOpts = new NatsAuthOpts { Username = "bob" } });
        var exception = await Assert.ThrowsAsync<NatsException>(async () => await client2.ConnectAsync());
        Assert.NotNull(exception.InnerException);
        output.WriteLine($"ERROR: {exception}");

        // TODO: this sometimes comes as NatsServerException: Server error: Authorization Violation
        // var serverException = exception.InnerException;
        // Assert.IsType<TimeoutException>(serverException);
    }

    private void Logger(string logMessage)
    {
        // output.WriteLine($"LOG: {logMessage}");
    }
}
