// Copyright (c) Synadia Communications, Inc. All rights reserved.
// Licensed under the Apache License, Version 2.0.

#pragma warning disable

using System.Text.Json.Nodes;
using NATS.Client.Core;
using NATS.Jwt;
using NATS.Jwt.Models;
using NATS.NKeys;

namespace Compat;

public record TestContext
{
    public CompatVars cv { get; init; }
    public CancellationTokenSource cts { get; init; }
    public TaskCompletionSource tcs { get; init; }
    public NatsConnection nt { get; init; }
    public NatsConnection connection { get; init; }
    public string name { get; init; }
    public string suitName { get; init; }
    public NatsJwt jwt { get; init; }
    public string env { get; init; }

    public IClaimsEncoder Encoder
    {
        get
        {
            if (env.StartsWith("TestDelegated"))
            {
                return new DelegatedClaimsEncoder(this);
            }
            else
            {
                return new BasicClaimsEncoder(this);
            }
        }
    }

    public string Subject(string suffix)
    {
        return suitName + suffix;
    }
}

public record CompatVars
{
    public string SuitName { get; init; }
    public string Name { get; init; }
    public string Env { get; init; }
    public string Url { get; init; }
    public string Username { get; init; }
    public string Password { get; init; }
    public string Audience { get; init; }
    public string UserInfoSubj { get; init; }

    public Dictionary<string, KeyPair> AccountKeys { get; init; }
    public KeyPair? Ekp { get; init; }

    public string ServiceCreds { get; init; }

    public string NscDir { get; init; }

    public string Dir { get; init; }

    public static CompatVars FromJson(string suitName, string jsonString)
    {
        string[] parts = suitName.Split('/');
        string env = parts[0];
        string name = parts[1];

        var json = JsonNode.Parse(jsonString);
        if (json == null)
        {
            throw new Exception("Failed to parse JSON");
        }

        Dictionary<string, KeyPair> keys = new();
        foreach ((string? key, JsonNode? value) in json["account_keys"].AsObject())
        {
            if (string.IsNullOrWhiteSpace(key) || value == null) continue;
            string seed = value["seed"]!.GetValue<string>();
            string pk = value["pk"]!.GetValue<string>();
            if (!string.IsNullOrEmpty(seed))
            {
                var kp = KeyPair.FromSeed(seed);
                if (pk != kp.GetPublicKey())
                {
                    throw new Exception("Invalid account key");
                }

                keys[key] = kp;
            }
        }

        KeyPair? ekp = null;
        string encryptionSeed = json["encryption_key"]!["seed"]!.GetValue<string>();
        string encryptionPk = json["encryption_key"]!["pk"]!.GetValue<string>();
        if (!string.IsNullOrEmpty(encryptionSeed))
        {
            ekp = KeyPair.FromSeed(encryptionSeed);
            if (encryptionPk != ekp.GetPublicKey())
            {
                throw new Exception("Invalid encryption key");
            }
        }

        return new CompatVars
        {
            SuitName = suitName,
            Name = name,
            Env = env,
            Url = json["nats_opts"]!["urls"]!.AsArray().First().GetValue<string>(),
            Username = json["nats_opts"]!["user"]!.GetValue<string>(),
            Password = json["nats_opts"]!["password"]!.GetValue<string>(),
            Audience = json["audience"]!.GetValue<string>(),
            UserInfoSubj = json["user_info_subj"]!.GetValue<string>(),
            Dir = json["dir"]!.GetValue<string>(),
            NscDir = json["nsc_dir"]!.GetValue<string>(),
            ServiceCreds = json["service_creds"]!.GetValue<string>(),
            Ekp = ekp,
            AccountKeys = keys,
        };
    }
}

public interface IClaimsEncoder
{
    string Encode(NatsUserClaims claims);
    string Encode(NatsAuthorizationResponseClaims claims);
}

public class BasicClaimsEncoder : IClaimsEncoder
{
    private readonly TestContext _t;

    public BasicClaimsEncoder(TestContext t)
    {
        _t = t;
    }

    public string Encode(NatsUserClaims claims)
    {
        return _t.jwt.EncodeUserClaims(claims, _t.cv.AccountKeys["A"]);
    }

    public string Encode(NatsAuthorizationResponseClaims claims)
    {
        return _t.jwt.EncodeAuthorizationResponseClaims(claims, _t.cv.AccountKeys["A"]);
    }
}

public class DelegatedClaimsEncoder : IClaimsEncoder
{
    private readonly TestContext _t;

    public DelegatedClaimsEncoder(TestContext t)
    {
        _t = t;
    }

    public string Encode(NatsUserClaims claims)
    {
        var store = new NscStore(_t.cv.NscDir);
        var op = store.LoadOperators().First(o => o.Name == "O");
        var a = op.Accounts.First(a => a.Name == "A");
        claims.User.IssuerAccount = a.Subject.GetPublicKey();
        return _t.jwt.EncodeUserClaims(claims, a.SigningKeys[0]);
    }

    public string Encode(NatsAuthorizationResponseClaims claims)
    {
        var store = new NscStore(_t.cv.NscDir);
        var op = store.LoadOperators().First(o => o.Name == "O");
        var c = op.Accounts.First(a => a.Name == "C");
        claims.AuthorizationResponse.IssuerAccount = c.Subject.GetPublicKey();
        return _t.jwt.EncodeAuthorizationResponseClaims(claims, c.SigningKeys[0]);
    }
}
