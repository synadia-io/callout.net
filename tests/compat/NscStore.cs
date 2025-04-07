// Copyright (c) Synadia Communications, Inc. All rights reserved.
// Licensed under the Apache License, Version 2.0.

#pragma warning disable

using System.Text.Json.Nodes;
using NATS.Jwt;
using NATS.NKeys;

namespace Compat;

#pragma warning disable
class NscStore
{
    private readonly DirectoryInfo _dir;
    private readonly DirectoryInfo _stores;
    private readonly DirectoryInfo _keys;

    public NscStore(string dir)
    {
        _dir = new DirectoryInfo(dir);
        _stores = new DirectoryInfo(Path.Combine(dir, "stores"));
        _keys = new DirectoryInfo(Path.Combine(dir, "keys", "keys"));
    }

    public IEnumerable<NscOperator> LoadOperators()
    {
        foreach (DirectoryInfo d in _stores.GetDirectories())
        {
            yield return NscOperator.Load(this, d);
        }
    }

    public KeyPair? LoadKey(string? pk)
    {
        if (pk == null)
        {
            return null;
        }

        string nk = Path.Combine(_keys.FullName, pk[..1], pk[1..3], $"{pk}.nk");
        KeyPair kp = KeyPair.FromSeed(File.ReadAllText(nk));
        if (kp.GetPublicKey() != pk)
        {
            throw new Exception($"Load key error: invalid key {pk}");
        }

        return kp;
    }

    public JsonNode LoadJwtPayload(DirectoryInfo dir)
    {
        return LoadJwtPayload(dir.GetFiles().First(f => f.Extension == ".jwt"));
    }

    public JsonNode LoadJwtPayload(FileInfo file)
    {
        string jwt = file.OpenText().ReadToEnd();
        return JsonNode.Parse(EncodingUtils.FromBase64UrlEncoded(jwt.Split('.')[1]));
    }

    public (KeyPair Issuer, KeyPair Subject) GetIssuerAndSubjectKeys(JsonNode json)
    {
        string iss = json["iss"].GetValue<string>();
        string sub = json["sub"].GetValue<string>();
        return (LoadKey(iss), LoadKey(sub));
    }
}

record NscEntry
{
    public string Name { get; init; }
    public KeyPair Issuer { get; init; }
    public KeyPair Subject { get; init; }
    public JsonNode JwtPayload { get; init; }
}

record NscOperator : NscEntry
{
    public static NscOperator Load(NscStore store, DirectoryInfo dir)
    {
        var payload = store.LoadJwtPayload(dir);
        (KeyPair issuer, KeyPair subject) = store.GetIssuerAndSubjectKeys(payload);

        var systemAccount = store.LoadKey(payload["nats"]?["system_account"]?.GetValue<string>());

        var accounts = new List<NscAccount>();
        foreach (DirectoryInfo d in dir.GetDirectories().First(f => f.Name == "accounts").GetDirectories())
        {
            accounts.Add(NscAccount.Load(store, d));
        }

        return new NscOperator
        {
            Name = dir.Name,
            JwtPayload = payload,
            Issuer = issuer,
            Subject = subject,
            Accounts = accounts,
            SystemAccount = systemAccount,
        };
    }

    public KeyPair? SystemAccount { get; init; }
    public List<NscAccount> Accounts { get; init; } = new();
}

record NscAccount : NscEntry
{
    public List<NscUser> Users { get; init; } = new();

    public List<KeyPair> SigningKeys { get; init; } = new();

    public List<KeyPair> AuthorizationAllowedAccounts { get; init; } = new();

    public List<KeyPair> AuthorizationAuthUsers { get; init; } = new();

    public static NscAccount Load(NscStore store, DirectoryInfo dir)
    {
        var payload = store.LoadJwtPayload(dir);
        (KeyPair issuer, KeyPair subject) = store.GetIssuerAndSubjectKeys(payload);

        var signingKeys = new List<KeyPair>();
        if (payload["nats"]?["signing_keys"]?.AsArray() is { } keysArray)
        {
            foreach (JsonNode? jsonNode in keysArray)
            {
                if (jsonNode == null)
                {
                    continue;
                }

                string? key = jsonNode.GetValue<string>();
                KeyPair? signingKey = store.LoadKey(key);
                if (signingKey != null)
                {
                    signingKeys.Add(signingKey);
                }
            }
        }

        var authorizationAllowedAccounts = new List<KeyPair>();
        if (payload["nats"]?["authorization"]?["allowed_accounts"]?.AsArray() is { } keysArray2)
        {
            foreach (JsonNode? jsonNode in keysArray2)
            {
                if (jsonNode == null)
                {
                    continue;
                }

                string? key = jsonNode.GetValue<string>();
                KeyPair? signingKey = store.LoadKey(key);
                if (signingKey != null)
                {
                    authorizationAllowedAccounts.Add(signingKey);
                }
            }
        }

        var authorizationAuthUsers = new List<KeyPair>();
        if (payload["nats"]?["authorization"]?["auth_users"]?.AsArray() is { } keysArray3)
        {
            foreach (JsonNode? jsonNode in keysArray3)
            {
                if (jsonNode == null)
                {
                    continue;
                }

                string? key = jsonNode.GetValue<string>();
                KeyPair? signingKey = store.LoadKey(key);
                if (signingKey != null)
                {
                    authorizationAuthUsers.Add(signingKey);
                }
            }
        }

        var users = new List<NscUser>();
        DirectoryInfo usersDir = dir.GetDirectories().FirstOrDefault(f => f.Name == "users");
        if (usersDir != null)
        {
            foreach (FileInfo j in usersDir.GetFiles().Where(f => f.Extension == ".jwt"))
            {
                users.Add(NscUser.Load(store, j));
            }
        }

        return new NscAccount
        {
            Name = dir.Name,
            JwtPayload = payload,
            SigningKeys = signingKeys,
            AuthorizationAllowedAccounts = authorizationAllowedAccounts,
            AuthorizationAuthUsers = authorizationAuthUsers,
            Issuer = issuer,
            Subject = subject,
            Users = users,
        };
    }
}

record NscUser : NscEntry
{
    public static NscUser Load(NscStore store, FileInfo file)
    {
        var payload = store.LoadJwtPayload(file);
        (KeyPair issuer, KeyPair subject) = store.GetIssuerAndSubjectKeys(payload);
        return new NscUser
        {
            Name = file.Name,
            JwtPayload = payload,
            Issuer = issuer,
            Subject = subject,
        };
    }
}
