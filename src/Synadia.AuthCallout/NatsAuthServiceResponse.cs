// Copyright (c) Synadia Communications, Inc. All rights reserved.
// Licensed under the Apache License, Version 2.0.

namespace Synadia.AuthCallout;

/// <summary>
/// Represents the response from a NATS authentication service operation.
/// </summary>
/// <param name="Token">The JWT token as a byte array that can be used for authentication.</param>
/// <param name="ErrorCode">An error code indicating the result of the authentication operation. 0 indicates success.</param>
public record NatsAuthServiceResponse(byte[] Token, int ErrorCode);
