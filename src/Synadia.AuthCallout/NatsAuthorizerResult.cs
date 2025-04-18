// Copyright (c) Synadia Communications, Inc. All rights reserved.
// Licensed under the Apache License, Version 2.0.

namespace Synadia.AuthCallout;

/// <summary>
/// Represents the result of a NATS authorization operation.
/// </summary>
/// <param name="Token">The user JWT Token string representing the authenticated user.</param>
/// <param name="ErrorCode">Optional error code if authorization failed. 0 if successful.</param>
/// <param name="ErrorMsg">Optional error message if authorization failed. Empty string if successful.</param>
public record NatsAuthorizerResult(string Token, int ErrorCode = 0, string ErrorMsg = "");
