# Callout .NET

[![License Apache 2](https://img.shields.io/badge/License-Apache2-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)
[![NuGet](https://img.shields.io/nuget/v/Synadia.AuthCallout.svg?cacheSeconds=3600)](https://www.nuget.org/packages/Synadia.AuthCallout)
[![Build](https://github.com/synadia-io/callout.net/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/synadia-io/callout.net/actions/workflows/test.yml?query=branch%3Amain)

### Preview

This is a preview version of the library. The API is subject to change.
The library is not yet ready for production use.

> [!CAUTION]
> ### Important Disclaimer
>
> This repository provides functionality built on top of NATS JWT APIs using .NET.
> However, at this time NATS JWT .NET is _not_ a supported API.
> Use at your own risk.
>
> See also [NATS JWT .NET](https://github.com/nats-io/jwt.net) library for more information.

This library implements a small framework for writing AuthCallout services for NATS.

See also the [Go implementation](https://github.com/synadia-io/callout.go) where this codebase is based on.
