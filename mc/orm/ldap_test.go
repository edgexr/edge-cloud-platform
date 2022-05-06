// Copyright 2022 MobiledgeX, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package orm

import (
	"net/http"
	"sort"
	"testing"

	"github.com/edgexr/edge-cloud-infra/billing"
	"github.com/edgexr/edge-cloud-infra/mc/mcctl/mctestclient"
	"github.com/edgexr/edge-cloud-infra/mc/ormclient"
	"github.com/edgexr/edge-cloud/cli"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/vault"
	"github.com/stretchr/testify/require"
	"gopkg.in/ldap.v3"
)

func TestLDAPServer(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	addr := "127.0.0.1:9999"
	uri := "http://" + addr + "/api/v1"

	vaultServer, vaultConfig := vault.DummyServer()
	defer vaultServer.Close()

	defaultConfig.DisableRateLimit = true

	config := ServerConfig{
		ServAddr:                 addr,
		SqlAddr:                  "127.0.0.1:5445",
		RunLocal:                 true,
		InitLocal:                true,
		IgnoreEnv:                true,
		LDAPAddr:                 "127.0.0.1:9389",
		vaultConfig:              vaultConfig,
		LDAPUsername:             "gitlab",
		LDAPPassword:             "gitlab",
		UsageCheckpointInterval:  "MONTH",
		BillingPlatform:          billing.BillingTypeFake,
		DeploymentTag:            "local",
		PublicAddr:               "http://mc.mobiledgex.net",
		PasswordResetConsolePath: "#/passwordreset",
		VerifyEmailConsolePath:   "#/verify",
	}
	server, err := RunServer(&config)
	require.Nil(t, err, "run server")
	defer server.Stop()

	Jwks.Init(vaultConfig, "region", "mcorm")
	Jwks.Meta.CurrentVersion = 1
	Jwks.Keys[1] = &vault.JWK{
		Secret:  "12345",
		Refresh: "1s",
	}

	err = server.WaitUntilReady()
	require.Nil(t, err, "server online")

	mcClient := mctestclient.NewClient(&ormclient.Client{})

	// login as super user
	tokenAd, _, err := mcClient.DoLogin(uri, DefaultSuperuser, DefaultSuperpass, NoOTP, NoApiKeyId, NoApiKey)
	require.Nil(t, err, "login as superuser")

	// create new users & orgs
	_, token1, orgman1pw := testCreateUser(t, mcClient, uri, "orgman1")
	org1 := testCreateOrg(t, mcClient, uri, token1, "developer", "bigorg1")
	worker1, _, worker1pw := testCreateUser(t, mcClient, uri, "worker1")
	testAddUserRole(t, mcClient, uri, token1, org1.Name, "DeveloperContributor", worker1.Name, Success)

	_, token2, _ := testCreateUser(t, mcClient, uri, "orgman2")
	org2 := testCreateOrg(t, mcClient, uri, token2, "developer", "bigorg2")
	worker2, _, _ := testCreateUser(t, mcClient, uri, "worker2")
	testAddUserRole(t, mcClient, uri, token2, org2.Name, "DeveloperContributor", worker2.Name, Success)
	testAddUserRole(t, mcClient, uri, token1, org1.Name, "DeveloperContributor", worker2.Name, Success)

	l, err := ldap.Dial("tcp", config.LDAPAddr)
	require.Nil(t, err, "connected to ldap server")
	defer l.Close()

	var sr *ldap.SearchResult

	// Login fails for locked/email not verified users
	err = l.Bind("cn=worker1,ou=users", "worker1-password")
	require.NotNil(t, err, "login locked user")
	unlockUser(t, mcClient, uri, tokenAd, "orgman1")
	unlockUser(t, mcClient, uri, tokenAd, "orgman2")
	unlockUser(t, mcClient, uri, tokenAd, "worker1")
	unlockUser(t, mcClient, uri, tokenAd, "worker2")

	// Expect Count: 7 (1 admin entry + 4 users + 2 orgs)
	ldapSearchCheck(t, l, "cn=worker1,ou=users", worker1pw, "", "(objectClass=*)", 7)

	// Expect Count: 5 (1 admin entry + 4 users)
	ldapSearchCheck(t, l, "cn=worker1,ou=users", worker1pw, "ou=users", "(objectClass=*)", 5)

	// Expect Count: 1 (1 user)
	ldapSearchCheck(t, l, "cn=worker1,ou=users", worker1pw, "cn=orgman2,ou=users", "(objectClass=*)", 1)

	// Expect Count: 2 (2 orgs)
	ldapSearchCheck(t, l, "cn=orgman1,ou=users", orgman1pw, "ou=orgs", "(objectClass=*)", 2)

	// Expect Count: 1 (1 org)
	sr = ldapSearchCheck(t, l, "cn=orgman1,ou=users", orgman1pw, "cn=bigorg1,ou=orgs", "(objectClass=*)", 1)
	uniqueMemberEntries := sr.Entries[0].GetAttributeValues("uniqueMember")
	sort.Strings(uniqueMemberEntries)
	require.Equal(t, len(uniqueMemberEntries), 3, "num of uniqueMembers")
	require.Equal(t, uniqueMemberEntries[0], "cn=orgman1,ou=users", "uniqueMember orgman1")
	require.Equal(t, uniqueMemberEntries[1], "cn=worker1,ou=users", "uniqueMember worker1")
	require.Equal(t, uniqueMemberEntries[2], "cn=worker2,ou=users", "uniqueMember worker2")

	// Expect Count: 1 (1 user)
	sr = ldapSearchCheck(t, l, "cn=gitlab,ou=users", "gitlab", "", "(sAMAccountName=worker2)", 1)
	memberOfEntries := sr.Entries[0].GetAttributeValues("memberOf")
	sort.Strings(memberOfEntries)
	require.Equal(t, len(memberOfEntries), 2, "num of memberOf entries")
	require.Equal(t, memberOfEntries[0], "cn=bigorg1,ou=orgs", "memberOf bigorg1")
	require.Equal(t, memberOfEntries[1], "cn=bigorg2,ou=orgs", "memberOf bigorg2")

	// Expect Count: 1 (2 orgs)
	ldapSearchCheck(t, l, "cn=gitlab,ou=users", "gitlab", "", "(objectClass=groupOfUniqueNames)", 2)

	// Expect Count: 1 (1 user)
	ldapSearchCheck(t, l, "cn=gitlab,ou=users", "gitlab", "ou=users", "(email=orgman1@gmail.com)", 1)

	// Expect Count: 2 (2 orgs, as worker2 belongs to 2 orgs: bigorg1,bigorg2)
	ldapSearchCheck(t, l, "cn=orgman1,ou=users", orgman1pw, "ou=orgs", "(&(objectClass=groupOfUniqueNames)(|(uniqueMember=cn=worker2,ou=users)(uniqueMember=worker2)))", 2)

	// make sure anonymous search is disabled
	l2, err := ldap.Dial("tcp", config.LDAPAddr)
	require.Nil(t, err, "connected to ldap server")
	defer l2.Close()
	req := &ldap.SearchRequest{
		BaseDN: "",
		Filter: "(objectClass=*)",
	}
	sr, err = l2.Search(req)
	require.Nil(t, err, "anonymous ldap search")
	require.Equal(t, 0, len(sr.Entries))

	// same request should work after binding
	err = l2.Bind("cn=gitlab,ou=users", "gitlab")
	require.Nil(t, err, "ldap bind")
	sr, err = l2.Search(req)
	require.Nil(t, err, "ldap search")
	require.Equal(t, 7, len(sr.Entries))
}

func ldapSearchCheck(t *testing.T, l *ldap.Conn, bindDN, bindPassword, baseDN, filter string, numEntries int) *ldap.SearchResult {

	err := l.Bind(bindDN, bindPassword)
	require.Nil(t, err, "ldap bind")

	searchRequest := &ldap.SearchRequest{
		BaseDN: baseDN,
		Filter: filter,
	}
	sr, err := l.Search(searchRequest)
	require.Nil(t, err, "ldap search")
	require.Equal(t, len(sr.Entries), numEntries, "match num of entries from search result")

	return sr
}

func unlockUser(t *testing.T, mcClient *mctestclient.Client, uri, token, username string) {
	req := &cli.MapData{
		Namespace: cli.JsonNamespace,
		Data:      make(map[string]interface{}),
	}
	req.Data["name"] = username
	req.Data["locked"] = false
	req.Data["emailverified"] = true
	status, err := mcClient.RestrictedUpdateUser(uri, token, req)
	require.Nil(t, err)
	require.Equal(t, http.StatusOK, status)
}
