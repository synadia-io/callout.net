// Copyright (c) Synadia Communications, Inc. All rights reserved.
// Licensed under the Apache License, Version 2.0.

using NATS.Jwt.Models;
using NATS.NKeys;

namespace Synadia.AuthCallout;

/// <summary>
/// Represents options for configuring the NATS authentication service.
/// </summary>
public record NatsAuthServiceOpts
{
    /// <summary>
    /// Initializes a new instance of the <see cref="NatsAuthServiceOpts"/> class.
    /// </summary>
    /// <param name="authorizer">Authorizer callback.</param>
    /// <param name="responseSigner">Response signer callback.</param>
    public NatsAuthServiceOpts(
        Func<NatsAuthorizationRequest, CancellationToken, ValueTask<string>> authorizer,
        Func<NatsAuthorizationResponseClaims, CancellationToken, ValueTask<string>> responseSigner)
    {
        Authorizer = authorizer;
        ResponseSigner = responseSigner;
    }

    /// <summary>
    /// Gets an encryption key used for sealing and opening protected data.
    /// It is an optional configuration that must be provided if the
    /// callout is configured to use encryption.
    /// </summary>
    public KeyPair? EncryptionKey { get; init; }

    /// <summary>
    /// Gets a function that processes authorization request and issues user JWTs.
    /// </summary>
    public Func<NatsAuthorizationRequest, CancellationToken, ValueTask<string>> Authorizer { get; init; }

    /// <summary>
    /// Gets a function that performs the signing of the <see cref="NatsAuthorizationResponseClaims"/>.
    /// </summary>
    public Func<NatsAuthorizationResponseClaims, CancellationToken, ValueTask<string>> ResponseSigner { get; init; }

    /// <summary>
    /// Gets a delegate for handling exceptions that occur during authorization.
    /// </summary>
    public Func<Exception, CancellationToken, ValueTask>? ErrorHandler { get; init; }
}
