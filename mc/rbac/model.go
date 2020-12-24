package rbac

// This is the Casbin model that our RBAC is based upon. While the string
// is not directly used anymore, it is left here as a reference for how
// the RBAC is modeled, and stored in postgres.

// RBAC model for Casbin (see https://vicarie.in/posts/generalized-authz.html
// and https://casbin.org/editor/).
// This extends the default RBAC model slightly by allowing Roles (sub)
// to be scoped by Organization (org) on a per-user basis, by prepending the
// Organization name to the user name when assigning a role to a user.
// Users without organizations prepended are super users and their role is
// not restricted to any organization - these users will be admins for
// the master controller.
var modelDef = `
[request_definition]
r = sub, org, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = (g(r.org + "::" + r.sub, p.sub) || g(r.sub, p.sub)) && r.obj == p.obj && r.act == p.act

[role_definition]
g = _, _
`

// A partial example matching config would be:
//
// p, DeveloperManager, Users, Manage
// p, DeveloperContributer, Apps, Manage
// p, DeveloperViewer, Apps, View
// p, AdminManager, Users, Manage
//
// g, superuser, AdminManager
// g, orgABC::adam, DeveloperManager
// g, orgABC::alice, DeveloperContributor
// g, orgXYZ::jon, DeveloperManager
// g, orgXYZ::bob, DeveloperContributor
//
// Example requests:
// (adam, orgABC, Users, Manage) -> OK
// (adam, orgXYZ, Users, Manage) -> Denied
// (superuser, <anything here>, Users, Manage) -> OK
//
// As part of our rbac query, we refer to above with table headers p_type, v0, v1, v2, ...
// So for example:
// p_type = p, v0 = DeveloperManager, v1 = Users, v2 = Manage
// p_type = g, v0 = orgABC::adam, v1 = DeveloperManager

func GetCasbinGroup(org, username string) string {
	if org == "" {
		return username
	}
	return org + "::" + username
}
