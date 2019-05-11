package orm

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/util"
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
	log.DebugLog(log.DebugLevelApi, "LDAP bind",
		"bindDN", bindDN)
	dn, err := parseDN(bindDN)
	if err != nil {
		return ldap.LDAPResultInvalidDNSyntax, nil
	}
	if dn.ou == OUusers && dn.cn == "gitlab" && bindSimplePw == "gitlab" {
		return ldap.LDAPResultSuccess, nil
	}
	if dn.ou == OUusers {
		lookup := ormapi.User{Name: dn.cn}
		user := ormapi.User{}
		log.DebugLog(log.DebugLevelApi, "LDAP bind", "lookup", lookup)

		err := db.Where(&lookup).First(&user).Error
		if err != nil {
			time.Sleep(BadAuthDelay)
			return ldap.LDAPResultInvalidCredentials, err
		}
		log.DebugLog(log.DebugLevelApi, "LDAP bind pw check", "user", user)
		matches, err := PasswordMatches(bindSimplePw, user.Passhash, user.Salt, user.Iter)
		if err != nil || !matches {
			time.Sleep(BadAuthDelay)
			return ldap.LDAPResultInvalidCredentials, err
		}
		log.DebugLog(log.DebugLevelApi, "LDAP bind success", "user", user)
		return ldap.LDAPResultSuccess, nil
	}
	return ldap.LDAPResultInvalidCredentials, nil
}

func (s *ldapHandler) Search(boundDN string, searchReq ldap.SearchRequest, conn net.Conn) (ldap.ServerSearchResult, error) {
	log.DebugLog(log.DebugLevelApi, "LDAP search",
		"boundDN", boundDN,
		"req", searchReq)
	res := ldap.ServerSearchResult{}

	filter, err := ldap.CompileFilter(searchReq.Filter)
	if err != nil {
		return res, err
	}

	dn, err := parseDN(searchReq.BaseDN)
	if err != nil {
		return res, fmt.Errorf("Invalid DN, %s", err.Error())
	}
	if dn.ou == "" {
		ldapLookupUsers(dn.cn, filter, &res)
		ldapLookupOrgs(dn.cn, filter, &res)
	} else if dn.ou == OUusers {
		ldapLookupUsers(dn.cn, filter, &res)
	} else if dn.ou == OUorgs {
		ldapLookupOrgs(dn.cn, filter, &res)
	} else {
		return res, fmt.Errorf("Invalid OU %s", dn.ou)
	}
	res.ResultCode = ldap.LDAPResultSuccess
	log.DebugLog(log.DebugLevelApi, "LDAP search result", "res", res)
	return res, nil
}

func ldapLookupUsers(username string, filter *ber.Packet, result *ldap.ServerSearchResult) {
	users := []ormapi.User{}
	err := db.Find(&users).Error
	if err != nil {
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
		groupings := enforcer.GetGroupingPolicy()
		roles := []*ormapi.Role{}
		for ii, _ := range groupings {
			role := parseRole(groupings[ii])
			if role == nil {
				continue
			}
			roles = append(roles, role)
		}
		if err == nil {
			orgs := []string{}
			for _, role := range roles {
				// for now any role has full access
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

func ldapLookupOrgs(orgname string, filter *ber.Packet, result *ldap.ServerSearchResult) {
	orgusers := make(map[string][]string)

	groupings := enforcer.GetGroupingPolicy()
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
