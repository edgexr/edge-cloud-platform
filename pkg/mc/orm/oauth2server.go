package orm

import (
	"context"
	fmt "fmt"
	"net/http"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/echoutil"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/passhash"
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
	srv := server.NewServer(cfg, manager)
	srv.ClientInfoHandler = clientCredsHandler
	return srv
}

// Custom client creds handler to allow for creds either in
// header or in body.
func clientCredsHandler(r *http.Request) (string, string, error) {
	clientID, clientSecret, err := server.ClientBasicHandler(r)
	if err == nil {
		return clientID, clientSecret, nil
	}
	return server.ClientFormHandler(r)
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
		ApiKeyId: apiKey.Id,
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
	ApiKeyId string
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
	matches, _ := passhash.PasswordMatches(pass, s.KeyHash, s.Salt, s.Iter)
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
	client, ok := data.Client.(*ClientInfo)
	if !ok {
		return "", "", fmt.Errorf("Invalid client info")
	}
	user := ormapi.User{
		Name: client.Username,
	}
	log.SpanLog(ctx, log.DebugLevelApi, "gen token", "id", data.Client.GetID(), "username", data.Client.GetUserID())

	domain := serverConfig.HTTPCookieDomain
	cookie, err := GenerateCookie(&user, client.ApiKeyId, domain, config)
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
// Currently this is only for Api Keys.
func Oauth2Token(c echo.Context) error {
	ctx := echoutil.GetContext(c)
	req := c.Request().WithContext(ctx)
	err := serverConfig.oauth2Server.HandleTokenRequest(c.Response(), req)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "oauth2token failed", "err", err)
		return err
	}
	return nil
}
