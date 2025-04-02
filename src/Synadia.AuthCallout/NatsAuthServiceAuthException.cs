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
    /// <param name="user">Related user ID.</param>
    public NatsAuthServiceAuthException(string message, string user)
        : base(message)
    {
        User = user;
    }

    /// <summary>
    /// Gets the user identifier associated with the exception.
    /// Represents the user-related context involved in the authentication process where the exception was thrown.
    /// </summary>
    public string User { get; }
}
