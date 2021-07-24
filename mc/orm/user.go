package orm

import (
	"bytes"
	"context"
	"fmt"
	"image/png"
	"io/ioutil"
	math "math"
	"net/http"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"github.com/labstack/echo"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud-infra/mc/rbac"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/util"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/trustelem/zxcvbn"
)

var BadAuthDelay = 3 * time.Second
var NoOTP = ""
var NoApiKeyId = ""
var NoApiKey = ""
var NoUserName = ""
var NoPassword = ""
var OTPLen otp.Digits = otp.DigitsSix
var OTPExpirationTime = uint(2 * 60)   // seconds
var OTPAuthenticatorExpTime = uint(30) // seconds
var OTPExpirationTimeStr = "2 minutes"

// Init admin creates the admin user and adds the admin role.
func InitAdmin(ctx context.Context, superuser, superpass string) error {
	log.SpanLog(ctx, log.DebugLevelApi, "init admin")

	// create superuser if it doesn't exist
	passhash, salt, iter := NewPasshash(superpass)
	super := ormapi.User{
		Name:          superuser,
		Email:         superuser + "@mobiledgex.net",
		EmailVerified: true,
		Passhash:      passhash,
		Salt:          salt,
		Iter:          iter,
		GivenName:     superuser,
		FamilyName:    superuser,
		Nickname:      superuser,
	}

	db := loggedDB(ctx)
	err := db.FirstOrCreate(&super, &ormapi.User{Name: superuser}).Error
	if err != nil {
		return err
	}

	// set role of superuser to admin manager
	err = enforcer.AddGroupingPolicy(ctx, super.Name, RoleAdminManager)
	if err != nil {
		return err
	}
	return nil
}

func GenerateWSAuthToken(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := GetContext(c)

	claims.StandardClaims.IssuedAt = time.Now().Unix()
	// Set short expiry as it is intended to be used immediately
	// by the client for connection to Websocket API endpoint
	claims.StandardClaims.ExpiresAt = time.Now().Add(JWTWSAuthDuration).Unix()
	cookie, err := Jwks.GenerateCookie(claims)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "failed to generate cookie", "err", err)
		return fmt.Errorf("Failed to generate cookie")
	}
	return c.JSON(http.StatusOK, M{"token": cookie})
}

func Login(c echo.Context) error {
	ctx := GetContext(c)
	login := ormapi.UserLogin{}
	if err := c.Bind(&login); err != nil {
		return bindErr(err)
	}
	db := loggedDB(ctx)
	user := ormapi.User{}
	if login.ApiKey != "" || login.ApiKeyId != "" {
		if login.ApiKeyId == "" {
			return fmt.Errorf("apikeyid not specified")
		}
		if login.ApiKey == "" {
			return fmt.Errorf("apikey not specified")
		}
		apiKeyObj := ormapi.UserApiKey{Id: login.ApiKeyId}
		err := db.Where(&apiKeyObj).First(&apiKeyObj).Error
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "ApiKey lookup failed", "apiKey", apiKeyObj, "err", err)
			time.Sleep(BadAuthDelay)
			return fmt.Errorf("Invalid ApiKey")
		}
		user.Name = apiKeyObj.Username
		err = db.Where(&user).First(&user).Error
		if err != nil {
			return dbErr(err)
		}
		span := log.SpanFromContext(ctx)
		span.SetTag("username", user.Name)
		span.SetTag("email", user.Email)

		matches, err := PasswordMatches(login.ApiKey, apiKeyObj.ApiKeyHash, apiKeyObj.Salt, apiKeyObj.Iter)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "apiKeyId matches err", "err", err)
		}
		if !matches || err != nil {
			time.Sleep(BadAuthDelay)
			return fmt.Errorf("Invalid ApiKey or ApiKeyId")
		}
	} else {
		if login.Username == "" {
			return fmt.Errorf("Username not specified")
		}

		if login.Password == "" {
			return fmt.Errorf("Please specify password")
		}
		lookup := ormapi.User{Name: login.Username}
		res := db.Where(&lookup).First(&user)
		if res.RecordNotFound() {
			// try look-up by email
			lookup.Name = ""
			lookup.Email = login.Username
			res = db.Where(&lookup).First(&user)
		}
		err := res.Error
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "user lookup failed", "lookup", lookup, "err", err)
			time.Sleep(BadAuthDelay)
			return fmt.Errorf("Invalid username or password")
		}
		span := log.SpanFromContext(ctx)
		span.SetTag("username", user.Name)
		span.SetTag("email", user.Email)

		matches, err := PasswordMatches(login.Password, user.Passhash, user.Salt, user.Iter)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "password matches err", "err", err)
		}
		if !matches || err != nil {
			time.Sleep(BadAuthDelay)
			return fmt.Errorf("Invalid username or password")
		}
	}

	if user.Locked {
		return fmt.Errorf("Account is locked, please contact MobiledgeX support")
	}
	if !getSkipVerifyEmail(ctx, nil) && !user.EmailVerified {
		return fmt.Errorf("Email not verified yet")
	}

	isAdmin, err := isUserAdmin(ctx, user.Name)
	if err != nil {
		return err
	}
	if login.Password != "" && user.PassCrackTimeSec == 0 {
		calcPasswordStrength(ctx, &user, login.Password)
		var err error
		err = checkPasswordStrength(ctx, &user, nil, isAdmin)
		if err != nil {
			if isAdmin {
				time.Sleep(BadAuthDelay)
				return fmt.Errorf("Existing password for Admin too weak, please update first")
			} else {
				// log warning for now
				log.SpanLog(ctx, log.DebugLevelApi, "user password strength check failure", "user", user.Name, "err", err)
			}
		}
		// save password strength
		err = db.Model(&user).Updates(&user).Error
		if err != nil {
			return dbErr(err)
		}
	}

	if login.Password != "" && user.TOTPSharedKey != "" {
		opts := totp.ValidateOpts{
			Period:    OTPExpirationTime,
			Skew:      1,
			Digits:    OTPLen,
			Algorithm: otp.AlgorithmSHA1,
		}
		if login.TOTP == "" {
			// Send OTP over email
			otp, err := totp.GenerateCodeCustom(user.TOTPSharedKey, time.Now().UTC(), opts)
			if err != nil {
				return err
			}
			err = sendOTPEmail(ctx, user.Name, user.Email, otp, OTPExpirationTimeStr)
			if err != nil {
				// log and ignore
				log.SpanLog(ctx, log.DebugLevelApi, "failed to send otp email", "err", err)
			}
			return newHTTPError(http.StatusNetworkAuthenticationRequired, "Missing OTP\nPlease use two factor authenticator app on "+
				"your phone to get OTP. We have also sent OTP to your registered email address")
		}
		// Default OTP expiration time for Authenticator client is set to 30secs
		// Hence first validate for 30secs, if that fails then validate for
		// 2mins (which is our default setting for email based OTP)
		opts.Period = OTPAuthenticatorExpTime
		valid, err := totp.ValidateCustom(login.TOTP, user.TOTPSharedKey, time.Now().UTC(), opts)
		if !valid {
			opts.Period = OTPExpirationTime
			valid, err = totp.ValidateCustom(login.TOTP, user.TOTPSharedKey, time.Now().UTC(), opts)
			if !valid {
				log.SpanLog(ctx, log.DebugLevelApi, "invalid or expired otp", "user", user.Name, "err", err)
				return fmt.Errorf("Invalid or expired OTP. Please login again to receive another OTP")
			}
		}
	}

	cookie, err := GenerateCookie(&user, login.ApiKeyId, serverConfig.DomainName)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "failed to generate cookie", "err", err)
		return fmt.Errorf("Failed to generate cookie")
	}
	ret := M{"token": cookie.Value}
	if isAdmin {
		ret["admin"] = true
	}
	c.SetCookie(cookie)
	return c.JSON(http.StatusOK, ret)
}

func RefreshAuthCookie(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := GetContext(c)
	if claims.FirstIssuedAt == 0 {
		log.SpanLog(ctx, log.DebugLevelApi, "failed to generate cookie as issued time is missing")
		return fmt.Errorf("Failed to refresh auth cookie")
	}
	// refresh auth cookie only if it was issued within 30 days
	if time.Unix(claims.FirstIssuedAt, 0).AddDate(0, 0, 30).Unix() < time.Now().Unix() {
		return newHTTPError(http.StatusUnauthorized, "expired jwt")
	}
	claims.StandardClaims.IssuedAt = time.Now().Unix()
	claims.StandardClaims.ExpiresAt = time.Now().AddDate(0, 0, 1).Unix()
	cookie, err := Jwks.GenerateCookie(claims)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "failed to generate cookie", "err", err)
		return fmt.Errorf("Failed to generate cookie")
	}
	httpCookie := NewHTTPAuthCookie(cookie, claims.ExpiresAt, serverConfig.DomainName)
	c.SetCookie(httpCookie)
	return c.JSON(http.StatusOK, M{"token": cookie})
}

func GenerateTOTPQR(accountName string) (string, []byte, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "MobiledgeX",
		AccountName: accountName,
		Period:      OTPExpirationTime,
		Digits:      OTPLen,
	})
	if err != nil {
		return "", nil, err
	}

	// Convert TOTP key into a QR code encoded as a PNG image.
	var buf bytes.Buffer
	img, err := key.Image(200, 200)
	if err != nil {
		return "", nil, err
	}
	err = png.Encode(&buf, img)
	if err != nil {
		return "", nil, err
	}

	return key.Secret(), buf.Bytes(), nil
}

func CreateUser(c echo.Context) error {
	ctx := GetContext(c)
	createuser := ormapi.CreateUser{}
	if err := c.Bind(&createuser); err != nil {
		return bindErr(err)
	}
	user := createuser.User
	if user.Name == "" {
		return fmt.Errorf("Name not specified")
	}
	err := ValidName(user.Name)
	if err != nil {
		return err
	}
	if !util.ValidEmail(user.Email) {
		return fmt.Errorf("Invalid email address")
	}
	if err := ValidPassword(user.Passhash); err != nil {
		return fmt.Errorf("Invalid password, %s", err)
	}
	orgT, err := GetAllOrgs(ctx)
	if err == nil {
		for orgName, _ := range orgT {
			if strings.ToLower(user.Name) == strings.ToLower(orgName) {
				return fmt.Errorf("user name cannot be same as org name")
			}
		}
	}

	config, err := getConfig(ctx)
	if err != nil {
		return err
	}
	calcPasswordStrength(ctx, &user, user.Passhash)
	// check password strength (new users are never admins)
	isAdmin := false
	err = checkPasswordStrength(ctx, &user, config, isAdmin)
	if err != nil {
		return err
	}

	if !getSkipVerifyEmail(ctx, config) {
		// real email will be filled in later
		createuser.Verify.Email = "dummy@dummy.com"
		err := ValidEmailRequest(c, &createuser.Verify)
		if err != nil {
			return err
		}
	}
	span := log.SpanFromContext(ctx)
	span.SetTag("username", user.Name)
	span.SetTag("email", user.Email)

	user.Locked = false
	if config.LockNewAccounts {
		user.Locked = true
	}
	user.EmailVerified = false

	userResponse := ormapi.UserResponse{}
	if user.EnableTOTP {
		totpKey, totpQR, err := GenerateTOTPQR(user.Email)
		if err != nil {
			return fmt.Errorf("Failed to setup 2FA: %v", err)
		}
		user.TOTPSharedKey = totpKey

		userResponse.TOTPSharedKey = totpKey
		userResponse.TOTPQRImage = totpQR
	}

	// password should be passed through in Passhash field.
	user.Passhash, user.Salt, user.Iter = NewPasshash(user.Passhash)
	db := loggedDB(ctx)
	if err := db.Create(&user).Error; err != nil {
		//check specifically for duplicate username and/or emails
		if err.Error() == "pq: duplicate key value violates unique constraint \"users_pkey\"" {
			return fmt.Errorf("Username with name %s (case-insensitive) already exists", user.Name)
		}
		if err.Error() == "pq: duplicate key value violates unique constraint \"users_email_key\"" {
			return fmt.Errorf("Email already in use")
		}

		return dbErr(err)
	}
	createuser.Verify.Email = user.Email
	err = sendVerifyEmail(ctx, user.Name, &createuser.Verify)
	if err != nil {
		db.Delete(&user)
		return err
	}

	gitlabCreateLDAPUser(ctx, &user)
	artifactoryCreateUser(ctx, &user)

	if user.Locked {
		msg := fmt.Sprintf("Locked account created for user %s, email %s", user.Name, user.Email)
		// just log in case of error
		senderr := sendNotify(ctx, config.NotifyEmailAddress,
			"Locked account created", msg)
		if senderr != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "failed to send notify of new locked account", "err", senderr)
		}
	}

	if user.TOTPSharedKey != "" {
		userResponse.Message = "User created with two factor authentication enabled. " +
			"Please use the following text code with the two factor authentication app on your " +
			"phone to set it up"
	} else {
		userResponse.Message = "user created"
	}
	return c.JSON(http.StatusOK, &userResponse)
}

func ResendVerify(c echo.Context) error {
	ctx := GetContext(c)

	req := ormapi.EmailRequest{}
	if err := c.Bind(&req); err != nil {
		return bindErr(err)
	}
	if err := ValidEmailRequest(c, &req); err != nil {
		return err
	}
	return sendVerifyEmail(ctx, "MobiledgeX user", &req)
}

func VerifyEmail(c echo.Context) error {
	ctx := GetContext(c)
	tok := ormapi.Token{}
	if err := c.Bind(&tok); err != nil {
		return bindErr(err)
	}
	claims := EmailClaims{}
	token, err := Jwks.VerifyCookie(tok.Token, &claims)
	if err != nil || !token.Valid {
		return &echo.HTTPError{
			Code:     http.StatusUnauthorized,
			Message:  "invalid or expired token",
			Internal: err,
		}
	}
	user := ormapi.User{Email: claims.Email}
	db := loggedDB(ctx)
	err = db.Where(&user).First(&user).Error
	if err != nil {
		// user got deleted in the meantime?
		return nil
	}
	span := log.SpanFromContext(ctx)
	span.SetTag("username", user.Name)

	user.EmailVerified = true
	if err := db.Model(&user).Updates(&user).Error; err != nil {
		return dbErr(err)
	}
	return c.JSON(http.StatusOK, Msg("email verified, thank you"))
}

func DeleteUser(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := GetContext(c)

	user := ormapi.User{}
	if err := c.Bind(&user); err != nil {
		return bindErr(err)
	}
	if user.Name == "" {
		return fmt.Errorf("User Name not specified")
	}
	// Only user themself or super-user can delete user.
	if user.Name != claims.Username {
		if err := authorized(ctx, claims.Username, "", ResourceUsers, ActionManage); err != nil {
			return err
		}
	}
	if user.Name == Superuser {
		return fmt.Errorf("Cannot delete superuser")
	}

	// delete role mappings
	groups, err := enforcer.GetGroupingPolicy()
	if err != nil {
		return dbErr(err)
	}
	// check role mappings first before deleting
	// need to make sure we are not deleting the last manager from an org or deleting the last AdminManager
	managerCounts := make(map[string]int)
	var userOrgs []string // orgs for which the user is a manager of
	for _, grp := range groups {
		if len(grp) < 2 {
			continue
		}
		strs := strings.Split(grp[0], "::")
		if grp[1] == RoleAdminManager || grp[1] == RoleDeveloperManager || grp[1] == RoleOperatorManager {
			org := ""
			username := grp[0]
			if len(strs) == 2 {
				org = strs[0]
				username = strs[1]
			}
			managerCounts[org] = managerCounts[org] + 1
			if username == user.Name {
				userOrgs = append(userOrgs, org)
			}
		}
	}
	for _, org := range userOrgs {
		if managerCounts[org] < 2 {
			if org == "" {
				err = fmt.Errorf("Error: Cannot delete the last remaining AdminManager")
			} else {
				err = fmt.Errorf("Error: Cannot delete the last remaining manager for the org %s", org)
			}
			return err
		}
	}
	for _, grp := range groups {
		if len(grp) < 2 {
			continue
		}
		strs := strings.Split(grp[0], "::")
		if grp[0] == user.Name || (len(strs) == 2 && strs[1] == user.Name) {
			err := enforcer.RemoveGroupingPolicy(ctx, grp[0], grp[1])
			if err != nil {
				return dbErr(err)
			}
		}
	}
	// delete user
	db := loggedDB(ctx)
	err = db.Delete(&user).Error
	if err != nil {
		return dbErr(err)
	}
	gitlabDeleteLDAPUser(ctx, user.Name)
	artifactoryDeleteUser(ctx, user.Name)

	return c.JSON(http.StatusOK, Msg("user deleted"))
}

// Show current user info
func CurrentUser(c echo.Context) error {
	ctx := GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	user := ormapi.User{Name: claims.Username}
	db := loggedDB(ctx)
	err = db.Where(&user).First(&user).Error
	if err != nil {
		return dbErr(err)
	}
	user.Passhash = ""
	user.Salt = ""
	user.Iter = 0
	user.TOTPSharedKey = ""
	return c.JSON(http.StatusOK, user)
}

// Fields to ignore for ShowUser filtering. Names are in database format.
var UserIgnoreFilterKeys = []string{
	"passhash",
	"salt",
	"iter",
	"pass_crack_time_sec",
	"totp_shared_key",
}

// Show users by Organization
func ShowUser(c echo.Context) error {
	ctx := GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	filter, err := bindDbFilter(c, &ormapi.ShowUser{})
	if err != nil {
		return err
	}
	// org and role are extra, when we query DB,
	// we'll query by the User object.
	filterOrg, _ := getFilterString(filter, "org")
	filterRole, _ := getFilterString(filter, "role")
	delete(filter, "org")
	delete(filter, "role")

	authOrgs, err := enforcer.GetAuthorizedOrgs(ctx, claims.Username, ResourceUsers, ActionView)
	if err != nil {
		return err
	}
	_, admin := authOrgs[""]
	_, orgFound := authOrgs[filterOrg]
	if filterOrg != "" && !admin && !orgFound {
		// no perms for specified org
		return echo.ErrForbidden
	}

	// prevent filtering user on sensitive data
	for _, name := range UserIgnoreFilterKeys {
		delete(filter, name)
	}

	// look for all users matching user filter
	db := loggedDB(ctx)
	users := []ormapi.User{}
	err = db.Where(filter).Find(&users).Error
	if err != nil {
		return dbErr(err)
	}

	if !admin || filterOrg != "" || filterRole != "" {
		// filter by specified org (or authorizedOrgs) or role
		groupings, err := enforcer.GetGroupingPolicy()
		if err != nil {
			return dbErr(err)
		}
		allowedUsers := make(map[string]struct{}) // key is username
		for _, grp := range groupings {
			role := parseRole(grp)
			if role == nil {
				continue
			}

			if filterOrg != "" && filterOrg != role.Org {
				continue
			}
			if filterOrg == "" && !admin {
				// filter by allowed orgs
				if _, found := authOrgs[role.Org]; !found {
					continue
				}
			}
			if filterRole != "" && filterRole != role.Role {
				continue
			}
			allowedUsers[role.Username] = struct{}{}
		}
		filteredUsers := []ormapi.User{}
		for _, user := range users {
			if _, found := allowedUsers[user.Name]; found {
				filteredUsers = append(filteredUsers, user)
			}
		}
		users = filteredUsers
	}
	for ii, _ := range users {
		// don't show auth info
		users[ii].Passhash = ""
		users[ii].TOTPSharedKey = ""
		users[ii].Salt = ""
		users[ii].Iter = 0
		if !admin && users[ii].Name != claims.Username {
			// don't expose private info to other users
			users[ii].Email = ""
			users[ii].EmailVerified = false
			users[ii].Locked = false
			users[ii].PassCrackTimeSec = 0
			users[ii].EnableTOTP = false
			users[ii].Metadata = ""
			users[ii].CreatedAt = time.Time{}
			users[ii].UpdatedAt = time.Time{}
		}
	}
	return c.JSON(http.StatusOK, users)
}

func NewPassword(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	in := ormapi.NewPassword{}
	if err := c.Bind(&in); err != nil {
		return bindErr(err)
	}
	return setPassword(c, claims.Username, in.Password)
}

func setPassword(c echo.Context, username, password string) error {
	ctx := GetContext(c)
	if err := ValidPassword(password); err != nil {
		return fmt.Errorf("Invalid password, %s", err)
	}
	user := ormapi.User{Name: username}
	db := loggedDB(ctx)
	err := db.Where(&user).First(&user).Error
	if err != nil {
		return dbErr(err)
	}

	calcPasswordStrength(ctx, &user, password)
	// check password strength
	isAdmin, err := isUserAdmin(ctx, user.Name)
	if err != nil {
		return err
	}
	err = checkPasswordStrength(ctx, &user, nil, isAdmin)
	if err != nil {
		return err
	}

	user.Passhash, user.Salt, user.Iter = NewPasshash(password)
	if err := db.Model(&user).Updates(&user).Error; err != nil {
		return dbErr(err)
	}
	return c.JSON(http.StatusOK, Msg("password updated"))
}

func calcPasswordStrength(ctx context.Context, user *ormapi.User, password string) {
	pwscore := zxcvbn.PasswordStrength(password, []string{})
	user.PassCrackTimeSec = pwscore.Guesses / float64(BruteForceGuessesPerSecond)
}

func checkPasswordStrength(ctx context.Context, user *ormapi.User, config *ormapi.Config, isAdmin bool) error {
	if config == nil {
		var err error
		config, err = getConfig(ctx)
		if err != nil {
			return err
		}
	}
	minCrackTime := config.PasswordMinCrackTimeSec
	if isAdmin {
		minCrackTime = config.AdminPasswordMinCrackTimeSec
	}
	if user.PassCrackTimeSec < minCrackTime {
		return fmt.Errorf("Password too weak, requires crack time %s but is %s. Please increase length or complexity", secDisplayTime(minCrackTime), secDisplayTime(user.PassCrackTimeSec))
	}
	return nil
}

func PasswordResetRequest(c echo.Context) error {
	ctx := GetContext(c)
	req := ormapi.EmailRequest{}
	if err := c.Bind(&req); err != nil {
		return bindErr(err)
	}
	if err := ValidEmailRequest(c, &req); err != nil {
		return err
	}
	noreply, err := getNoreply(ctx)
	if err != nil {
		return err
	}

	tmpl := passwordResetNoneTmpl
	arg := emailTmplArg{
		From:    noreply.Email,
		Email:   req.Email,
		OS:      req.OperatingSystem,
		Browser: req.Browser,
		IP:      req.ClientIP,
	}
	// To ensure we do not leak user accounts, we do not
	// return an error if the user is not found. Instead, we always
	// send an email to the account specified, but the contents
	// of the email are different if the user was not found.
	user := ormapi.User{Email: req.Email}
	db := loggedDB(ctx)
	res := db.Where(&user).First(&user)
	if !res.RecordNotFound() && res.Error == nil {
		info := EmailClaims{
			StandardClaims: jwt.StandardClaims{
				IssuedAt: time.Now().Unix(),
				// 1 hour
				ExpiresAt: time.Now().Add(time.Hour).Unix(),
			},
			Email:    req.Email,
			Username: user.Name,
		}
		cookie, err := Jwks.GenerateCookie(&info)
		if err != nil {
			return err
		}
		if req.CallbackURL != "" {
			arg.URL = req.CallbackURL + "?token=" + cookie
		}
		arg.Name = user.Name
		arg.Token = cookie
		tmpl = passwordResetTmpl
	}
	buf := bytes.Buffer{}
	if err := tmpl.Execute(&buf, &arg); err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelApi, "send password reset email",
		"from", noreply.Email, "to", req.Email)
	return sendEmail(noreply, req.Email, &buf)
}

func PasswordReset(c echo.Context) error {
	pw := ormapi.PasswordReset{}
	if err := c.Bind(&pw); err != nil {
		return bindErr(err)
	}
	claims := EmailClaims{}
	token, err := Jwks.VerifyCookie(pw.Token, &claims)
	if err != nil || !token.Valid {
		return &echo.HTTPError{
			Code:     http.StatusUnauthorized,
			Message:  "invalid or expired token",
			Internal: err,
		}
	}
	ctx := GetContext(c)
	span := log.SpanFromContext(ctx)
	span.SetTag("username", claims.Username)
	return setPassword(c, claims.Username, pw.Password)
}

func RestrictedUserUpdate(c echo.Context) error {
	ctx := GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	// Only admin user allowed to update user data.
	if err := authorized(ctx, claims.Username, "", ResourceUsers, ActionManage); err != nil {
		return err
	}
	// Pull json directly so we can unmarshal twice.
	// First time is to do lookup, second time is to apply
	// modified fields.
	body, err := ioutil.ReadAll(c.Request().Body)
	if err != nil {
		return bindErr(err)
	}
	in := ormapi.User{}
	err = BindJson(body, &in)
	if err != nil {
		return bindErr(err)
	}
	// in may contain other fields, but can only specify
	// name and email for where clause.
	lookup := ormapi.User{
		Name:  in.Name,
		Email: in.Email,
	}
	user := ormapi.User{}
	db := loggedDB(ctx)
	res := db.Where(&lookup).First(&user)
	if res.RecordNotFound() {
		return fmt.Errorf("user not found")
	}
	if res.Error != nil {
		return dbErr(res.Error)
	}
	saveuser := user
	// apply specified fields
	err = BindJson(body, &user)
	if err != nil {
		return bindErr(err)
	}
	// cannot update password or invariant fields
	user.Passhash = saveuser.Passhash
	user.Salt = saveuser.Salt
	user.Iter = saveuser.Iter
	user.CreatedAt = saveuser.CreatedAt
	user.Name = saveuser.Name
	user.Email = saveuser.Email

	err = db.Save(&user).Error
	if err != nil {
		return dbErr(err)
	}
	return nil
}

// modified version of go-zxcvbn scoring.displayTime that more closely
// matches the java script version of the lib.
func secDisplayTime(seconds float64) string {
	formater := "%.1f %s"
	minute := float64(60)
	hour := minute * float64(60)
	day := hour * float64(24)
	month := day * float64(31)
	year := month * float64(12)
	century := year * float64(100)

	if seconds < 1 {
		return "less than a second"
	} else if seconds < minute {
		return fmt.Sprintf(formater, (1 + math.Ceil(seconds)), "seconds")
	} else if seconds < hour {
		return fmt.Sprintf(formater, (1 + math.Ceil(seconds/minute)), "minutes")
	} else if seconds < day {
		return fmt.Sprintf(formater, (1 + math.Ceil(seconds/hour)), "hours")
	} else if seconds < month {
		return fmt.Sprintf(formater, (1 + math.Ceil(seconds/day)), "days")
	} else if seconds < year {
		return fmt.Sprintf(formater, (1 + math.Ceil(seconds/month)), "months")
	} else if seconds < century {
		return fmt.Sprintf(formater, (1 + math.Ceil(seconds/century)), "years")
	} else {
		return "centuries"
	}
}

func isUserAdmin(ctx context.Context, username string) (bool, error) {
	// it doesn't matter what the resource/action is here, as long
	// as it's part of one of the admin roles.
	authOrgs, err := enforcer.GetAuthorizedOrgs(ctx, username, ResourceConfig, ActionView)
	if err != nil {
		return false, dbErr(err)
	}
	if _, found := authOrgs[""]; found {
		return true, nil
	}
	return false, nil
}

func UpdateUser(c echo.Context) error {
	ctx := GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}

	cuser := ormapi.CreateUser{}
	cuser.User.Name = claims.Username
	user := &cuser.User
	db := loggedDB(ctx)
	res := db.Where(user).First(user)
	if res.RecordNotFound() {
		return fmt.Errorf("User not found")
	}
	old := *user

	// read args onto existing data, will overwrite only specified fields
	if err := c.Bind(&cuser); err != nil {
		return bindErr(err)
	}
	// check for fields that are not allowed to change
	if old.Name != user.Name {
		return fmt.Errorf("Cannot change username")
	}
	if old.EmailVerified != user.EmailVerified {
		return fmt.Errorf("Cannot change emailverified")
	}
	if old.Passhash != user.Passhash {
		return fmt.Errorf("Cannot change passhash")
	}
	if old.Salt != user.Salt {
		return fmt.Errorf("Cannot change salt")
	}
	if old.Iter != user.Iter {
		return fmt.Errorf("Cannot change iter")
	}
	if !old.CreatedAt.Equal(user.CreatedAt) {
		return fmt.Errorf("Cannot change createdat")
	}
	if !old.UpdatedAt.Equal(user.UpdatedAt) {
		return fmt.Errorf("Cannot change updatedat")
	}
	if old.Locked != user.Locked {
		return fmt.Errorf("Cannot change locked")
	}
	if old.PassCrackTimeSec != user.PassCrackTimeSec {
		return fmt.Errorf("Cannot change passcracktimesec")
	}

	// if email changed, need to verify
	sendVerify := false
	if old.Email != user.Email {
		config, err := getConfig(ctx)
		if err != nil {
			return err
		}
		if !getSkipVerifyEmail(ctx, config) {
			err := ValidEmailRequest(c, &cuser.Verify)
			if err != nil {
				return err
			}
			sendVerify = true
		}
		user.EmailVerified = false
	}

	userResponse := ormapi.UserResponse{}
	otpChanged := false
	if old.EnableTOTP != user.EnableTOTP {
		if user.EnableTOTP {
			totpKey, totpQR, err := GenerateTOTPQR(user.Email)
			if err != nil {
				return fmt.Errorf("Failed to setup 2FA: %v", err)
			}
			user.TOTPSharedKey = totpKey

			userResponse.TOTPSharedKey = totpKey
			userResponse.TOTPQRImage = totpQR
		} else {
			user.TOTPSharedKey = NoOTP
		}
		otpChanged = true
	}

	err = db.Save(user).Error
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key value violates unique constraint \"email_pkey") {
			return fmt.Errorf("Email %s already in use", user.Email)
		}
		return dbErr(err)
	}

	if sendVerify {
		err = sendVerifyEmail(ctx, user.Name, &cuser.Verify)
		if err != nil {
			undoErr := db.Save(&old).Error
			if undoErr != nil {
				log.SpanLog(ctx, log.DebugLevelApi, "undo update user failed", "user", claims.Username, "err", undoErr)
			}
			return fmt.Errorf("Failed to send verification email to %s, %v", user.Email, err)
		}
	}

	if otpChanged && user.TOTPSharedKey != "" {
		userResponse.Message = "User updated\nEnabled two factor authentication. " +
			"Please use the following text code with the two factor authentication app on your " +
			"phone to set it up"
	} else {
		userResponse.Message = "user updated"
	}
	return c.JSON(http.StatusOK, &userResponse)
}

func CreateUserApiKey(c echo.Context) error {
	ctx := GetContext(c)
	db := loggedDB(ctx)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	// Disallow apikey creation if auth type is ApiKey auth
	if claims.AuthType == ApiKeyAuth {
		return newHTTPError(http.StatusForbidden, "ApiKey auth not allowed to create API keys, please log in with user account")
	}
	apiKeyReq := ormapi.CreateUserApiKey{}
	if err := c.Bind(&apiKeyReq); err != nil {
		return bindErr(err)
	}
	config, err := getConfig(ctx)
	if err != nil {
		return err
	}
	// ensure that user has not reached the limit on the number of api keys it can create
	lookup := ormapi.UserApiKey{Username: claims.Username}
	curApiKeys := []ormapi.UserApiKey{}
	err = db.Where(&lookup).Find(&curApiKeys).Error
	if err != nil {
		return dbErr(err)
	}
	if len(curApiKeys) >= config.UserApiKeyCreateLimit {
		return fmt.Errorf("User cannot create more than %d API keys, please delete existing keys to create new one", config.UserApiKeyCreateLimit)
	}
	if len(apiKeyReq.Permissions) == 0 {
		return fmt.Errorf("No permissions for specified org")
	}

	apiKeyObj := ormapi.UserApiKey{}
	apiKeyObj.Username = claims.Username
	apiKeyObj.Org = apiKeyReq.Org
	apiKeyObj.Description = apiKeyReq.Description

	// verify that specified org exists
	org := ormapi.Organization{}
	org.Name = apiKeyObj.Org
	err = db.Where(&org).First(&org).Error
	if err != nil {
		return dbErr(err)
	}

	lookupOrg := apiKeyObj.Org
	if claims.Username == Superuser {
		lookupOrg = ""
	}
	// make sure caller has perms to access resource of target org
	validRolePerms, err := enforcer.GetPermissions(ctx, claims.Username, lookupOrg)
	if err != nil {
		return err
	}

	apiKeyId := uuid.New().String()
	apiKey := uuid.New().String()
	apiKeyRole := getApiKeyRoleName(apiKeyId)
	psub := rbac.GetCasbinGroup(apiKeyObj.Org, apiKeyId)
	cleanupPoliciesOnErr := func() {
		log.SpanLog(ctx, log.DebugLevelApi, "cleaning up all the policies", "user", claims.Username, "apiKeyId", apiKeyId)
		// remove policy if present, ignore err
		enforcer.RemovePolicy(ctx, apiKeyRole)
		enforcer.RemoveGroupingPolicy(ctx, psub, apiKeyRole)
	}

	// verify if user specified role/resource/action for the API key is valid
	var policyErr error
	for _, perm := range apiKeyReq.Permissions {
		if perm.Action != ActionView && perm.Action != ActionManage {
			cleanupPoliciesOnErr()
			return fmt.Errorf("Invalid action %s, valid actions are %s, %s", perm.Action, ActionView, ActionManage)
		}
		lookupRolePerm := ormapi.RolePerm{
			Resource: perm.Resource,
			Action:   perm.Action,
		}
		validPerms := []string{}
		for rPerm, _ := range validRolePerms {
			validPerms = append(validPerms, rPerm.Resource+":"+rPerm.Action)
		}
		if _, ok := validRolePerms[lookupRolePerm]; !ok {
			cleanupPoliciesOnErr()
			return fmt.Errorf("Invalid permission specified: [%s:%s], valid permissions (resource:action) are %v", perm.Resource, perm.Action, validPerms)
		}
		addPolicy(ctx, &policyErr, apiKeyRole, perm.Resource, perm.Action)
	}
	if policyErr != nil {
		cleanupPoliciesOnErr()
		return dbErr(policyErr)
	}

	err = enforcer.AddGroupingPolicy(ctx, psub, apiKeyRole)
	if err != nil {
		cleanupPoliciesOnErr()
		return dbErr(err)
	}

	apiKeyHash, apiKeySalt, apiKeyIter := NewPasshash(apiKey)
	apiKeyObj.ApiKeyHash = apiKeyHash
	apiKeyObj.Salt = apiKeySalt
	apiKeyObj.Iter = apiKeyIter
	apiKeyObj.Id = apiKeyId
	if err := db.Create(&apiKeyObj).Error; err != nil {
		cleanupPoliciesOnErr()
		return dbErr(err)
	}
	apiKeyOut := ormapi.CreateUserApiKey{}
	apiKeyOut.Id = apiKeyId
	apiKeyOut.ApiKey = apiKey
	return c.JSON(http.StatusOK, &apiKeyOut)
}

func DeleteUserApiKey(c echo.Context) error {
	ctx := GetContext(c)
	db := loggedDB(ctx)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	// Disallow apikey deletion if auth type is ApiKey auth
	if claims.AuthType == ApiKeyAuth {
		return newHTTPError(http.StatusForbidden, "ApiKey auth not allowed to delete API keys, please log in with user account")
	}
	lookup := ormapi.CreateUserApiKey{}
	if err := c.Bind(&lookup); err != nil {
		return bindErr(err)
	}
	apiKeyObj := ormapi.UserApiKey{Id: lookup.Id}
	err = db.Where(&apiKeyObj).First(&apiKeyObj).Error
	if err != nil {
		return dbErr(err)
	}
	apiKeyRole := getApiKeyRoleName(apiKeyObj.Id)
	err = enforcer.RemovePolicy(ctx, apiKeyRole)
	if err != nil {
		return dbErr(err)
	}
	psub := rbac.GetCasbinGroup(apiKeyObj.Org, apiKeyObj.Id)
	err = enforcer.RemoveGroupingPolicy(ctx, psub, apiKeyRole)
	if err != nil {
		return dbErr(err)
	}
	// delete user api key
	err = db.Delete(&apiKeyObj).Error
	if err != nil {
		return dbErr(err)
	}
	return c.JSON(http.StatusOK, Msg("deleted API Key successfully"))
}

func ShowUserApiKey(c echo.Context) error {
	ctx := GetContext(c)
	db := loggedDB(ctx)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	// Disallow apikey users to view api keys
	if claims.AuthType == ApiKeyAuth {
		return newHTTPError(http.StatusForbidden, "ApiKey auth not allowed to show API keys, please log in with user account")
	}
	filter := ormapi.CreateUserApiKey{}
	if c.Request().ContentLength > 0 {
		if err := c.Bind(&filter); err != nil {
			return bindErr(err)
		}
	}
	apiKeys := []ormapi.UserApiKey{}
	// if filter ID is 0, show all keys
	if filter.Id == "" {
		err := db.Find(&apiKeys).Error
		if err != nil {
			return dbErr(err)
		}
	} else {
		apiKeyObj := ormapi.UserApiKey{Id: filter.Id}
		err := db.Where(&apiKeyObj).First(&apiKeyObj).Error
		if err != nil {
			return dbErr(err)
		}
		apiKeys = append(apiKeys, apiKeyObj)
	}
	super := false
	if authorized(ctx, claims.Username, "", ResourceUsers, ActionView) == nil {
		// super user, show all apikeys
		super = true
	}
	outApiKeys := []ormapi.CreateUserApiKey{}
	for _, apiKeyObj := range apiKeys {
		if !super && apiKeyObj.Username != claims.Username {
			continue
		}
		out := ormapi.CreateUserApiKey{}
		out.Id = apiKeyObj.Id
		out.Description = apiKeyObj.Description
		out.Org = apiKeyObj.Org
		out.CreatedAt = apiKeyObj.CreatedAt
		if super {
			out.Username = apiKeyObj.Username
		}
		out.Permissions = []ormapi.RolePerm{}
		rolePerms, err := enforcer.GetPermissions(ctx, apiKeyObj.Id, apiKeyObj.Org)
		if err != nil {
			return err
		}
		for rolePerm, _ := range rolePerms {
			out.Permissions = append(out.Permissions, rolePerm)
		}
		outApiKeys = append(outApiKeys, out)
	}
	return c.JSON(http.StatusOK, &outApiKeys)
}
