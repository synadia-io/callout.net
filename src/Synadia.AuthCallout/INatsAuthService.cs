﻿// Copyright (c) Synadia Communications, Inc. All rights reserved.
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
    /// <returns>A task that represents the asynchronous start operation.</returns>
    ValueTask StartAsync();

    /// <summary>
    /// Processes an incoming request asynchronously by decoding the JWT, authorizing the request, and optionally encrypting
    /// the response before returning it.
    /// </summary>
    /// <param name="msg">The incoming request message containing the data to process.</param>
    /// <returns>A task that represents the asynchronous operation, containing the processed response as a byte array.</returns>
    ValueTask<byte[]> ProcessRequestAsync(NatsSvcMsg<byte[]> msg);
}
