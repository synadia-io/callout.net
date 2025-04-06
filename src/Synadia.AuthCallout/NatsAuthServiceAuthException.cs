// Copyright (c) Synadia Communications, Inc. All rights reserved.
// Licensed under the Apache License, Version 2.0.

namespace Synadia.AuthCallout;

/// <summary>
/// Represents an exception that occurs specifically during the authentication process in the NATS authorization service
/// when additional user-related context is involved.
/// </summary>
public class NatsAuthServiceAuthException : Exception
{
    /// <summary>
    /// Initializes a new instance of the <see cref="NatsAuthServiceAuthException"/> class.
    /// Creates an instance.
    /// </summary>
    /// <param name="message">Error message.</param>
    public NatsAuthServiceAuthException(string message)
        : base(message)
    {
    }
}
