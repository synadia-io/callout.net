// Copyright (c) Synadia Communications, Inc. All rights reserved.
// Licensed under the Apache License, Version 2.0.

using System.Text;
using Microsoft.Extensions.Logging;
using NATS.Client.Services;
using NATS.Jwt;
using NATS.Jwt.Models;

namespace Synadia.AuthCallout;

/// <summary>
/// Represents an implementation of the INatsAuthService interface, providing functionality for handling
/// authentication requests in a NATS Auth Callout environment. This service processes incoming requests,
/// performs JWT-based authentication, supports encryption for secure token transmission, and handles
/// response generation. It also manages the lifecycle of NATS service components, including initialization
/// and disposal of resources.
/// </summary>
public class NatsAuthService : INatsAuthService
{
    private const string ExpectedAudience = "nats-authorization-request";
    private const string NatsServerXKeyHeader = "Nats-Server-Xkey";
    private const string SysRequestUserAuthSubj = "$SYS.REQ.USER.AUTH";
    private readonly INatsSvcContext _svc;
    private readonly NatsAuthServiceOpts _opts;
    private readonly NatsJwt _natsJwt = new();
    private readonly ILogger<NatsAuthService> _logger;
    private INatsSvcServer? _server;

    /// <summary>
    /// Initializes a new instance of the <see cref="NatsAuthService"/> class.
    /// </summary>
    /// <param name="svc">NATS Service Context.</param>
    /// <param name="opts">Service Options.</param>
    public NatsAuthService(INatsSvcContext svc, NatsAuthServiceOpts opts)
    {
        _svc = svc;
        _opts = opts;
        _logger = _svc.Connection.Opts.LoggerFactory.CreateLogger<NatsAuthService>();
    }

    /// <inheritdoc />
    public async ValueTask StartAsync(CancellationToken cancellationToken = default)
    {
        _server = await _svc.AddServiceAsync("auth-server", "1.0.0", cancellationToken: cancellationToken);
        await _server.AddEndpointAsync<byte[]>(
            handler: async msg =>
            {
                try
                {
                    NatsAuthServiceResponse res = await ProcessRequestAsync(msg, cancellationToken);
                    if (res.ErrorCode == 0)
                    {
                        await msg.ReplyAsync(res.Token, cancellationToken: cancellationToken);
                    }
                    else
                    {
                        await msg.ReplyErrorAsync(res.ErrorCode, "Unauthorized", res.Token, cancellationToken: cancellationToken);
                    }
                }
                catch (NatsAuthServiceAuthException e)
                {
                    _logger.LogInformation(e, "Auth error");
                    await CallErrorHandlerAsync(e, cancellationToken);
                    await msg.ReplyErrorAsync(401, "Unauthorized", cancellationToken: cancellationToken);
                }
                catch (NatsAuthServiceException e)
                {
                    _logger.LogWarning(e, "Service error");
                    await CallErrorHandlerAsync(e, cancellationToken);
                    await msg.ReplyErrorAsync(400, e.Message, cancellationToken: cancellationToken);
                }
                catch (Exception e)
                {
                    _logger.LogError(e, "Generic error");
                    await CallErrorHandlerAsync(e, cancellationToken);
                    await msg.ReplyErrorAsync(400, e.Message, cancellationToken: cancellationToken);
                }
            },
            name: "auth-request-handler",
            subject: SysRequestUserAuthSubj,
            cancellationToken: cancellationToken);
    }

    /// <inheritdoc />
    public async ValueTask<NatsAuthServiceResponse> ProcessRequestAsync(
        NatsSvcMsg<byte[]> msg,
        CancellationToken cancellationToken = default)
    {
        var (isEncrypted, req) = DecodeJwt(msg);
        var res = new NatsAuthorizationResponseClaims { Subject = req.UserNKey, Audience = req.NatsServer.Id, };

        NatsAuthorizerResult authResult = await _opts.Authorizer(req, cancellationToken);

        if (authResult is { Token: "", ErrorCode: 0 })
        {
            throw new NatsAuthServiceAuthException(
                "Error authorizing: authorizer didn't generate a JWT and no error was provided");
        }

        if (authResult.ErrorCode != 0 || authResult.ErrorMsg != string.Empty)
        {
            res.AuthorizationResponse.Error = authResult.ErrorMsg;
        }
        else
        {
            res.AuthorizationResponse.Jwt = authResult.Token;
        }

        string tokenString = await _opts.ResponseSigner(res, cancellationToken);
        byte[] token = Encoding.ASCII.GetBytes(tokenString);

        if (isEncrypted)
        {
            byte[] seal = _opts.EncryptionKey!.Seal(token, req.NatsServer.XKey);
            token = seal;
        }

        return new NatsAuthServiceResponse(token, authResult.ErrorCode);
    }

    /// <summary>
    /// Disposes the resources used by the NatsAuthService asynchronously, including releasing
    /// any associated server resources.
    /// </summary>
    /// <returns>A task that represents the asynchronous dispose operation.</returns>
    public async ValueTask DisposeAsync()
    {
        if (_server != null)
        {
            await _server.DisposeAsync();
        }
    }

    private async Task CallErrorHandlerAsync(Exception exception, CancellationToken cancellationToken)
    {
        if (_opts.ErrorHandler is { } errorHandler)
        {
            try
            {
                await errorHandler(exception, cancellationToken);
            }
            catch (Exception e)
            {
                _logger.LogError(e, "Auth error handler");
            }
        }
    }

    private (bool IsEncrypted, NatsAuthorizationRequest Request) DecodeJwt(NatsSvcMsg<byte[]> msg)
    {
        byte[] data = msg.Data!;
        string jwt = Encoding.ASCII.GetString(data);

        if (jwt.Length < 4)
        {
            throw new NatsAuthServiceException($"Bad request: payload too short: {jwt.Length}");
        }

        bool isEncrypted = !jwt.StartsWith("eyJ0");

        if (isEncrypted && _opts.EncryptionKey == null)
        {
            throw new NatsAuthServiceException("Bad request: encryption mismatch: payload is encrypted");
        }

        if (!isEncrypted && _opts.EncryptionKey != null)
        {
            throw new NatsAuthServiceException("Bad request: encryption mismatch: payload is not encrypted");
        }

        if (isEncrypted)
        {
            if (msg.Headers == null)
            {
                throw new NatsAuthServiceException("No encryption headers found");
            }

            var serverKey = msg.Headers[NatsServerXKeyHeader];
            byte[] open = _opts.EncryptionKey!.Open(data, serverKey);
            jwt = Encoding.ASCII.GetString(open);
        }

        NatsAuthorizationRequestClaims arc = _natsJwt.DecodeClaims<NatsAuthorizationRequestClaims>(jwt);

        if (!arc.Issuer.StartsWith("N"))
        {
            throw new NatsAuthServiceException($"Bad request: expected server: {arc.Issuer}");
        }

        if (arc.Issuer != arc.AuthorizationRequest.NatsServer.Id)
        {
            throw new NatsAuthServiceException(
                $"Bad request: issuers don't match: {arc.Issuer} != {arc.AuthorizationRequest.NatsServer.Id}");
        }

        if (arc.Audience != ExpectedAudience)
        {
            throw new NatsAuthServiceException($"Bad request: unexpected audience: {arc.Audience}");
        }

        return (isEncrypted, arc.AuthorizationRequest);
    }
}
