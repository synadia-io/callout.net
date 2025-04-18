// Copyright (c) Synadia Communications, Inc. All rights reserved.
// Licensed under the Apache License, Version 2.0.

using NATS.Client.Services;

namespace Synadia.AuthCallout;

/// <summary>
/// Provides an interface for an authentication service in a NATS Auth Callout environment. This service handles
/// authentication requests using JWT tokens and supports encryption for secure communication.
/// It allows for starting the service, processing incoming requests, and resource cleanup.
/// </summary>
public interface INatsAuthService : IAsyncDisposable
{
    /// <summary>
    /// Starts the NatsAuthService asynchronously by initializing the service and setting up the necessary endpoints
    /// for handling authentication requests.
    /// </summary>
    /// <param name="cancellationToken">A cancellation token to observe while waiting for the operation to complete.</param>
    /// <returns>A task that represents the asynchronous start operation.</returns>
    ValueTask StartAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Processes an incoming request asynchronously by decoding the JWT, authorizing the request, and optionally encrypting
    /// the response before returning it.
    /// </summary>
    /// <param name="msg">The incoming request message containing the data to process.</param>
    /// <param name="cancellationToken">A cancellation token to observe while waiting for the operation to complete.</param>
    /// <returns>A task that represents the asynchronous operation, containing the processed response as a NatsAuthServiceResponse with the JWT token and error code.</returns>
    ValueTask<NatsAuthServiceResponse> ProcessRequestAsync(NatsSvcMsg<byte[]> msg, CancellationToken cancellationToken = default);
}
