package orm

import (
	"context"
	fmt "fmt"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ormutil"
	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/labstack/echo/v4"
)

// Oauth2. Currently only supports client credentials flow.
func InitOauth2() *server.Server {
	manager := manage.NewDefaultManager()
	// token memory store
	manager.MapTokenStorage(&TokenStore{})
	// ClientStore handles client lookup and authentication
	manager.MapClientStorage(&ClientStore{})
	// ClientCredential flow config
	manager.SetClientTokenCfg(&manage.Config{
		AccessTokenExp:    30 * time.Minute,
		RefreshTokenExp:   90 * time.Minute,
		IsGenerateRefresh: false,
	})
	// Token generator
	manager.MapAccessGenerate(&AccessGen{})

	// Server config
	cfg := &server.Config{
		TokenType: "Bearer",
		AllowedResponseTypes: []oauth2.ResponseType{
			oauth2.Code,
			oauth2.Token,
		},
		AllowedGrantTypes: []oauth2.GrantType{
			oauth2.ClientCredentials,
		},
	}
	return server.NewServer(cfg, manager)
}

// ClientStore handles client lookup
type ClientStore struct{}

// Get ApiKey by ID
func (s *ClientStore) GetByID(ctx context.Context, id string) (oauth2.ClientInfo, error) {
	db := loggedDB(ctx)
	apiKey := ormapi.UserApiKey{
		Id: id,
	}
	res := db.Where(apiKey).First(&apiKey)
	if res.RecordNotFound() {
		// returning an error from here causes the oauth2 server
		// to generate an internal server error. So instead,
		// return nil and allow the VerifyPassword call to fail.
		log.SpanLog(ctx, log.DebugLevelApi, "oauth2 client not found", "name", id)
		return &ClientInfo{
			NotFound: true,
		}, nil
	}
	err := res.Error
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "apikey lookup failed", "name", id, "err", err)
		time.Sleep(BadAuthDelay)
		return nil, fmt.Errorf("Internal server error")
	}
	info := ClientInfo{
		ID:       id,
		Username: apiKey.Username,
		KeyHash:  apiKey.ApiKeyHash,
		Salt:     apiKey.Salt,
		Iter:     apiKey.Iter,
	}
	return &info, nil
}

type ClientInfo struct {
	ID       string
	Username string
	KeyHash  string
	Salt     string
	Iter     int
	NotFound bool
}

func (s *ClientInfo) GetID() string     { return s.ID }
func (s *ClientInfo) GetSecret() string { return "" }
func (s *ClientInfo) GetDomain() string { return "" }
func (s *ClientInfo) GetUserID() string { return s.Username }
func (s *ClientInfo) VerifyPassword(pass string) bool {
	if s.NotFound {
		time.Sleep(BadAuthDelay)
		return false
	}
	matches, _ := ormutil.PasswordMatches(pass, s.KeyHash, s.Salt, s.Iter)
	if !matches {
		time.Sleep(BadAuthDelay)
	}
	return matches
}

// AccessGen generates the access JWT token
type AccessGen struct{}

func (s *AccessGen) Token(ctx context.Context, data *oauth2.GenerateBasic, isGenRefresh bool) (string, string, error) {
	config, err := getConfig(ctx)
	if err != nil {
		return "", "", err
	}
	user := ormapi.User{
		Name: data.Client.GetUserID(),
	}
	log.SpanLog(ctx, log.DebugLevelApi, "gen token", "id", data.Client.GetID(), "username", data.Client.GetUserID())
	// although this is an apikey, we need to treat it as a user
	// to be able to look up the associated federation provider/consumer
	// via the username.
	notApiKey := ""
	domain := serverConfig.HTTPCookieDomain
	cookie, err := GenerateCookie(&user, notApiKey, domain, config)
	if err != nil {
		return "", "", err
	}
	return cookie.Value, "", nil
}

// The way the oauth2 package is set up, valid tokens are stored in memory,
// and token validation is done by looking up the token.
// However, to avoid having to synchronize tokens across replicas, we
// do not store tokens in memory. Instead, we validate via the signing
// key pulled from Vault.
type TokenStore struct{}

func (s *TokenStore) Create(ctx context.Context, info oauth2.TokenInfo) error   { return nil }
func (s *TokenStore) RemoveByCode(ctx context.Context, code string) error       { return nil }
func (s *TokenStore) RemoveByAccess(ctx context.Context, access string) error   { return nil }
func (s *TokenStore) RemoveByRefresh(ctx context.Context, refresh string) error { return nil }
func (s *TokenStore) GetByCode(ctx context.Context, code string) (oauth2.TokenInfo, error) {
	return nil, fmt.Errorf("not supported")
}
func (s *TokenStore) GetByAccess(ctx context.Context, access string) (oauth2.TokenInfo, error) {
	return nil, fmt.Errorf("not supported")
}
func (s *TokenStore) GetByRefresh(ctx context.Context, code string) (oauth2.TokenInfo, error) {
	return nil, fmt.Errorf("not supported")
}

// Authenticate and issue a JWT token.
// Currently this is only for Federation.
func Oauth2Token(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	req := c.Request().WithContext(ctx)
	err := serverConfig.oauth2Server.HandleTokenRequest(c.Response(), req)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "oauth2token failed", "err", err)
		return err
	}
	return nil
}
