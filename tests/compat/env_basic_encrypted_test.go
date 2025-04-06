// Copyright 2025 Synadia Communications, Inc
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package compat

import (
	"testing"

	"github.com/aricart/nst.go"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"github.com/stretchr/testify/require"
)

type BasicEncryptedEnv struct {
	t    *testing.T
	dir  *nst.TestDir
	akp  nkeys.KeyPair
	xkey nkeys.KeyPair
}

func NewBasicEncryptedEnv(t *testing.T, dir *nst.TestDir) *BasicEncryptedEnv {
	akp, err := nkeys.CreateAccount()
	require.NoError(t, err)
	xkey, err := nkeys.CreateCurveKeys()
	require.NoError(t, err)
	return &BasicEncryptedEnv{
		t:    t,
		dir:  dir,
		akp:  akp,
		xkey: xkey,
	}
}

func (bc *BasicEncryptedEnv) GetServerConf() []byte {
	pk, err := bc.akp.PublicKey()
	require.NoError(bc.t, err)

	pck, err := bc.xkey.PublicKey()
	require.NoError(bc.t, err)

	conf := &nst.Conf{Accounts: map[string]nst.Account{}}
	conf.Authorization.Users.Add(nst.User{User: "auth", Password: "pwd"})
	conf.Authorization.AuthCallout = &nst.AuthCallout{}
	conf.Authorization.AuthCallout.Issuer = pk
	conf.Authorization.AuthCallout.XKey = pck
	conf.Authorization.AuthCallout.AuthUsers.Add("auth")
	return conf.Marshal(bc.t)
}

func (bc *BasicEncryptedEnv) EncodeUser(_ string, claim jwt.Claims) (string, error) {
	return claim.Encode(bc.akp)
}

func (bc *BasicEncryptedEnv) ServiceUserOpts() []nats.Option {
	return []nats.Option{nats.UserInfo("auth", "pwd")}
}

func (bc *BasicEncryptedEnv) UserOpts() []nats.Option {
	return []nats.Option{}
}

func (bc *BasicEncryptedEnv) EncryptionKey() nkeys.KeyPair {
	return bc.xkey
}

func (bc *BasicEncryptedEnv) Audience() string {
	return "$G"
}

func (bc *BasicEncryptedEnv) ServiceAudience() string {
	return "$G"
}

//func (bc *BasicEncryptedEnv) ServiceOpts() []Option {
//	return []Option{
//		ResponseSignerKey(bc.akp),
//		EncryptionKey(bc.xkey),
//	}
//}

func (bc *BasicEncryptedEnv) GetAccounts() map[string]nkeys.KeyPair {
	return map[string]nkeys.KeyPair{
		"A": bc.akp,
	}
}

func (bc *BasicEncryptedEnv) ServiceCreds() string {
	return ""
}

func (bc *BasicEncryptedEnv) SentinelCreds() string {
	return ""
}
