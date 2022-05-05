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
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud-infra/mc/ormutil"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/util"
	ber "github.com/nmcclain/asn1-ber"
	"github.com/nmcclain/ldap"
)

// LDAP interface to MC user database

const (
	OUusers = "users"
	OUorgs  = "orgs"
)

type ldapHandler struct {
}

func (s *ldapHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (ldap.LDAPResultCode, error) {
	span := log.StartSpan(log.DebugLevelApi, "ldap bind")
	span.SetTag("dn", bindDN)
	span.SetTag("remoteaddr", conn.RemoteAddr())
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	dn, err := parseDN(bindDN)
	if err != nil {
		return ldap.LDAPResultInvalidDNSyntax, nil
	}
	if dn.ou == OUusers && dn.cn == serverConfig.LDAPUsername && bindSimplePw == serverConfig.LDAPPassword {
		return ldap.LDAPResultSuccess, nil
	}
	if dn.ou == OUusers {
		lookup := ormapi.User{Name: dn.cn}
		user := ormapi.User{}
		log.SpanLog(ctx, log.DebugLevelApi, "lookup", "user", lookup)

		db := loggedDB(ctx)
		err := db.Where(&lookup).First(&user).Error
		if err != nil {
			time.Sleep(BadAuthDelay)
			return ldap.LDAPResultInvalidCredentials, err
		}
		// don't log "user", as it contains password hash
		log.SpanLog(ctx, log.DebugLevelApi, "pw check", "user", lookup)
		if !user.EmailVerified || user.Locked {
			time.Sleep(BadAuthDelay)
			return ldap.LDAPResultInvalidCredentials, nil
		}
		matches, err := ormutil.PasswordMatches(bindSimplePw, user.Passhash, user.Salt, user.Iter)
		if err != nil || !matches {
			time.Sleep(BadAuthDelay)
			return ldap.LDAPResultInvalidCredentials, err
		}
		log.SpanLog(ctx, log.DebugLevelApi, "success", "user", lookup)
		return ldap.LDAPResultSuccess, nil
	}
	return ldap.LDAPResultInvalidCredentials, nil
}

func (s *ldapHandler) Search(boundDN string, searchReq ldap.SearchRequest, conn net.Conn) (ldap.ServerSearchResult, error) {
	span := log.StartSpan(log.DebugLevelApi, "ldap search")
	span.SetTag("dn", boundDN)
	span.SetTag("remoteaddr", conn.RemoteAddr())
	span.SetTag("request", searchReq)
	defer span.Finish()
	ctx := log.ContextWithSpan(context.Background(), span)

	res := ldap.ServerSearchResult{}
	if boundDN == "" {
		// disable anonymous search
		res.ResultCode = ldap.LDAPResultInvalidCredentials
		return res, nil
	}
	filter, err := ldap.CompileFilter(searchReq.Filter)
	if err != nil {
		return res, err
	}

	dn, err := parseDN(searchReq.BaseDN)
	if err != nil {
		return res, fmt.Errorf("Invalid DN, %s", err.Error())
	}
	if dn.ou == "" {
		ldapLookupUsers(ctx, dn.cn, filter, &res)
		ldapLookupOrgs(ctx, dn.cn, filter, &res)
	} else if dn.ou == OUusers {
		ldapLookupUsers(ctx, dn.cn, filter, &res)
	} else if dn.ou == OUorgs {
		ldapLookupOrgs(ctx, dn.cn, filter, &res)
	} else {
		return res, fmt.Errorf("Invalid OU %s", dn.ou)
	}
	res.ResultCode = ldap.LDAPResultSuccess
	log.SpanLog(ctx, log.DebugLevelApi, "success", "result", res)
	return res, nil
}

func ldapLookupUsers(ctx context.Context, username string, filter *ber.Packet, result *ldap.ServerSearchResult) {
	users := []ormapi.User{}
	db := loggedDB(ctx)
	err := db.Find(&users).Error
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "db find users", "err", err)
		return
	}
	groupings, err := enforcer.GetGroupingPolicy()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "ldap get grouping policy failed", "err", err)
		return
	}
	for _, user := range users {
		if username != "" && username != user.Name {
			continue
		}
		dn := ldapdn{
			cn: user.Name,
			ou: OUusers,
		}
		entry := ldap.Entry{
			DN: dn.String(),
			Attributes: []*ldap.EntryAttribute{
				&ldap.EntryAttribute{
					Name:   "cn",
					Values: []string{user.Name},
				},
				&ldap.EntryAttribute{
					Name:   "sAMAccountName",
					Values: []string{user.Name},
				},
				&ldap.EntryAttribute{
					Name:   "email",
					Values: []string{user.Email},
				},
				&ldap.EntryAttribute{
					Name:   "mail",
					Values: []string{user.Email},
				},
				&ldap.EntryAttribute{
					Name:   "userPrincipalName",
					Values: []string{user.Name + "@" + OUusers},
				},
				&ldap.EntryAttribute{
					Name:   "objectClass",
					Values: []string{"posixAccount"},
				},
			},
		}
		roles := []*ormapi.Role{}
		for ii, _ := range groupings {
			role := parseRole(groupings[ii])
			if role == nil {
				continue
			}
			if role.Username != user.Name {
				continue
			}
			if role.Org == "" {
				continue
			}
			roles = append(roles, role)
		}
		if err == nil {
			orgs := []string{}
			for _, role := range roles {
				dn := ldapdn{
					cn: role.Org,
					ou: OUorgs,
				}
				orgs = append(orgs, dn.String())
			}
			if len(orgs) > 0 {
				attr := ldap.EntryAttribute{
					Name:   "memberOf",
					Values: orgs,
				}
				entry.Attributes = append(entry.Attributes, &attr)
			}
		}
		keep, _ := ldap.ServerApplyFilter(filter, &entry)
		if !keep {
			continue
		}

		result.Entries = append(result.Entries, &entry)
	}
}

func ldapLookupOrgs(ctx context.Context, orgname string, filter *ber.Packet, result *ldap.ServerSearchResult) {
	orgusers := make(map[string][]string)

	groupings, err := enforcer.GetGroupingPolicy()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "ldap get grouping policy failed", "err", err)
		return
	}
	for ii, _ := range groupings {
		role := parseRole(groupings[ii])
		if role == nil || role.Org == "" {
			continue
		}
		if orgname != "" && role.Org != orgname {
			continue
		}
		orgusers[role.Org] = append(orgusers[role.Org], role.Username)
	}

	for org, users := range orgusers {
		dn := ldapdn{
			cn: org,
			ou: OUorgs,
		}
		entry := ldap.Entry{
			DN: dn.String(),
			Attributes: []*ldap.EntryAttribute{
				&ldap.EntryAttribute{
					Name:   "ou",
					Values: []string{OUorgs},
				},
				&ldap.EntryAttribute{
					Name:   "cn",
					Values: []string{org},
				},
				&ldap.EntryAttribute{
					Name:   "objectClass",
					Values: []string{"groupOfUniqueNames"},
				},
			},
		}
		orgmems := []string{}
		for _, user := range users {
			udn := ldapdn{
				cn: user,
				ou: OUusers,
			}
			orgmems = append(orgmems, udn.String())
		}
		if len(orgmems) > 0 {
			attr := ldap.EntryAttribute{
				Name:   "uniqueMember",
				Values: orgmems,
			}
			entry.Attributes = append(entry.Attributes, &attr)
		}
		keep, _ := ldap.ServerApplyFilter(filter, &entry)
		if !keep {
			continue
		}

		result.Entries = append(result.Entries, &entry)
	}
}

// Note special char handling is accomplished by disallowing
// special chars for User or Organization names.
type ldapdn struct {
	cn string // common name (unique identifier)
	ou string // organization unit (users, orgs)
}

func parseDN(str string) (ldapdn, error) {
	dn := ldapdn{}

	if str == "" {
		return dn, nil
	}
	strs := strings.Split(str, ",")
	for _, subdn := range strs {
		subdn = util.UnescapeLDAPName(subdn)
		kv := strings.Split(subdn, "=")
		if len(kv) != 2 {
			return dn, fmt.Errorf("LDAP DN Key-value parse error for %s", str)
		}
		switch kv[0] {
		case "cn":
			dn.cn = kv[1]
		case "ou":
			dn.ou = kv[1]
		default:
			return dn, fmt.Errorf("LDAP DN invalid component %s", kv[0])
		}
	}
	return dn, nil
}

func (s *ldapdn) String() string {
	strs := []string{}
	if s.cn != "" {
		strs = append(strs, "cn="+util.EscapeLDAPName(s.cn))
	}
	if s.ou != "" {
		strs = append(strs, "ou="+util.EscapeLDAPName(s.ou))
	}
	if len(strs) == 0 {
		return ""
	}
	return strings.Join(strs, ",")
}
