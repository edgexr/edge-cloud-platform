package vault

import (
	"errors"
	"fmt"
	"sync"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/mitchellh/mapstructure"
	"github.com/mobiledgex/edge-cloud/log"
)

// JWKS is a set of JWT keys to support rotating keys.
// Multiple keys are stored, indexed by Key ID.
// The Key ID is set on the JWT claims, so it can be looked up
// during verification.
// Rotation works by another process adding a new version of the
// secret to Vault. Vault maintains the older values of the secret,
// where we use the vault secret version as the key ID.
// If VerifyCookie encounters a Key ID greater than it's current
// one (implying another process had updated to a newer version),
// then it will attempt to update inline. Older key versions are
// handled by just looking up the older version. The refresh
// interval should be much smaller than the rotation interval
// to allow for all instances to update to the next rotation
// before the secret is rotated again.
// This implementation does not support the full JWKS spec feature
// set, for example being able to specify the signing algorithm, etc
// in the claims.

// JWKS stores the multiple versions of data retrieved from Vault,
// as well as the data needed to access Vault.
type JWKS struct {
	Keys              map[int]*JWK
	Meta              KVMetadata
	RefreshDelay      time.Duration
	Mux               sync.Mutex
	Path              string
	Metapath          string
	addr              string
	roleID            string
	secretID          string
	lastUpdateAttempt time.Time
}

// JWK is the data stored in Vault
type JWK struct {
	Secret  string
	Refresh string
}

var DefaultJwkRefreshDelay = 5 * time.Minute
var JwkUpdateDelay = 5 * time.Second

func (s *JWKS) Init(addr, name, roleID, secretID string) {
	s.Keys = make(map[int]*JWK)
	s.RefreshDelay = DefaultJwkRefreshDelay
	s.Path = "jwtkeys/data/" + name
	s.Metapath = "jwtkeys/metadata/" + name
	s.addr = addr
	s.roleID = roleID
	s.secretID = secretID
}

// GoUpdate starts a go thread to keep the JKWS up to date.
func (s *JWKS) GoUpdate() {
	go func() {
		first := true
		for {
			if !first {
				time.Sleep(s.RefreshDelay)
			} else {
				first = false
			}

			err := s.updateKeys()
			if err != nil {
				log.InfoLog("jwks update keys", "path", s.Path, "metapath", s.Metapath, "err", err)
				continue
			}
		}
	}()
}

func (s *JWKS) GetCurrentKey() (string, int, bool) {
	version := s.Meta.CurrentVersion
	str, ok := s.GetKey(version)
	return str, version, ok
}

func (s *JWKS) GetKey(version int) (string, bool) {
	if version > s.Meta.CurrentVersion {
		// New secret may have been pushed to Vault and used
		// by another instance. See if we can grab it as well.
		err := s.updateKeys()
		if err != nil {
			return "", false
		}
	}
	s.Mux.Lock()
	defer s.Mux.Unlock()
	jwk, ok := s.Keys[version]
	if !ok {
		return "", false
	}
	return jwk.Secret, true
}

// KVJWK represents the kv data in vault returned by a specific version request
type KVJWK struct {
	Meta KVMeta `mapstructure:"metadata"`
	Data JWK    `mapstructure:"data"`
}

func (s *JWKS) updateKeys() error {
	s.Mux.Lock()
	if time.Since(s.lastUpdateAttempt) < JwkUpdateDelay {
		// avoid constant attempts
		s.Mux.Unlock()
		return fmt.Errorf("too many update attempts")
	}
	s.lastUpdateAttempt = time.Now()
	s.Mux.Unlock()

	client, err := NewClient(s.addr)
	if err != nil {
		return fmt.Errorf("new client failed for %s", s.addr)
	}
	err = AppRoleLogin(client, s.roleID, s.secretID)
	if err != nil {
		return fmt.Errorf("approle login failed for %s, %s", s.addr, err.Error())
	}

	// Get the metadata to find out how many and what versions there are
	kvdata, err := GetKV(client, s.Metapath, -1)
	if err != nil {
		return err
	}
	metadata, err := ParseMetadata(kvdata)
	if err != nil {
		return err
	}

	// Key ID is set to the key version in Vault. This version is
	// automatically incremented whenever the key is updated, so it
	// is a natural JWT key ID.
	keys := make(map[int]*JWK)
	for ii := metadata.CurrentVersion; ii >= metadata.OldestVersion; ii-- {
		kvdata, err := GetKV(client, s.Path, ii)
		if err != nil {
			return err
		}
		kvjwk := &KVJWK{}
		err = mapstructure.WeakDecode(kvdata, kvjwk)
		if err != nil {
			return err
		}
		if kvjwk.Meta.Version != ii {
			return fmt.Errorf("requested %s version %d but got version %d", s.Path, ii, kvjwk.Meta.Version)
		}
		keys[kvjwk.Meta.Version] = &kvjwk.Data

		if ii == metadata.CurrentVersion && kvjwk.Data.Refresh != "" {
			dur, err := time.ParseDuration(kvjwk.Data.Refresh)
			if err != nil {
				log.InfoLog("parse refresh failed", "refresh",
					kvjwk.Data.Refresh, "err", err)
			} else {
				s.RefreshDelay = dur
			}
		}
	}

	// swap in new keys
	s.Mux.Lock()
	s.Meta = *metadata
	s.Keys = keys
	s.Mux.Unlock()
	return nil
}

func PutSecret(addr, roleID, secretID, name, secret, refresh string) error {
	client, err := NewClient(addr)
	if err != nil {
		return err
	}
	err = AppRoleLogin(client, roleID, secretID)
	if err != nil {
		return err
	}
	path := "jwtkeys/data/" + name
	data := map[string]interface{}{
		"secret":  secret,
		"refresh": refresh,
	}
	out := map[string]interface{}{
		"data": data,
	}
	return PutKV(client, path, out)
}

type Claims interface {
	jwt.Claims
	// Get the Key ID with the claims (for VerifyCookie)
	GetKid() int
	// Set the Key ID with the claims (for GenerateCookie)
	SetKid(int)
}

func (s *JWKS) GenerateCookie(claims Claims) (string, error) {
	skey, kid, ok := s.GetCurrentKey()
	if !ok {
		return "", errors.New("no signing key")
	}
	claims.SetKid(kid)
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	cookie, err := token.SignedString([]byte(skey))
	return cookie, err
}

func (s *JWKS) VerifyCookie(cookie string, claims Claims) (*jwt.Token, error) {
	if cookie == "" {
		return nil, errors.New("missing cookie")
	}
	return jwt.ParseWithClaims(cookie, claims, func(token *jwt.Token) (verifykey interface{}, err error) {
		secret, ok := s.GetKey(claims.GetKid())
		if !ok {
			return nil, fmt.Errorf("no secret for kid %d in cookie %s", claims.GetKid(), cookie)
		}
		return []byte(secret), nil
	})
}