// Copyright (c) Synadia Communications, Inc. All rights reserved.
// Licensed under the Apache License, Version 2.0.

namespace Synadia.AuthCallout;

/// <summary>
/// Represents an exception thrown during the authentication process in the NATS authorization service.
/// </summary>
public class NatsAuthServiceException : Exception
{
    /// <summary>
    /// Initializes a new instance of the <see cref="NatsAuthServiceException"/> class.
    /// </summary>
    /// <param name="message">Error message.</param>
    public NatsAuthServiceException(string message)
        : base(message)
    {
    }
}
