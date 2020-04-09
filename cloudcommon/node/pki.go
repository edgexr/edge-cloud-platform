package node

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/vault"
)

var refreshCertInterval = 48 * time.Hour

type internalPki struct {
	// Internal PKI supports either cert files supplied on the
	// command line or retrieved from Vault.
	// Command line certs are supported if specified.
	// Vault certs are supported if the VaultAddr is specified.
	// The UseVaultCerts arg determines which sets of certs to use
	// if available.
	UseVaultCerts bool

	// These are the certs loaded from disk specified on the command line.
	fileCert *tls.Certificate
	fileCAs  []*x509.Certificate

	// Certs map contains certs that identify this node, issued by Vault.
	// These certs are retrieved dynamically by the tls config because
	// they may be refreshed periodically, so cannot be copied into
	// the tls config.
	// CA certs do not change frequently, and the tls config doesn't
	// provide any way to retrieve them dynamically anyway. They are
	// still cached to avoid talking to Vault for every new connection.
	certs map[certId]*tls.Certificate
	cas   map[string][]*x509.Certificate

	enabled        bool
	vaultConfig    *vault.Config
	localRegion    string
	refreshTrigger chan bool

	mux sync.Mutex
}

type certId struct {
	CommonName string
	Issuer     string
}

func (s *NodeMgr) initInternalPki(ctx context.Context) error {
	pkiDesc := []string{}

	if s.TlsCertFile != "" {
		// load certs from command line
		err := s.InternalPki.loadCerts(s.TlsCertFile)
		if err != nil {
			return err
		}
		s.InternalPki.enabled = true
		pkiDesc = append(pkiDesc, "from-file")
	}
	s.InternalPki.vaultConfig = s.VaultConfig
	if s.InternalPki.vaultConfig.Addr != "" {
		if s.TlsCertFile == "" {
			// no files specified, so use Vault certs
			s.InternalPki.UseVaultCerts = true
		}
		// enable Vault certs
		log.SpanLog(ctx, log.DebugLevelInfo, "enable internal Vault PKI")

		s.InternalPki.certs = make(map[certId]*tls.Certificate)
		s.InternalPki.cas = make(map[string][]*x509.Certificate)
		s.InternalPki.localRegion = s.Region
		s.InternalPki.enabled = true
		s.InternalPki.refreshTrigger = make(chan bool, 1)

		go s.InternalPki.refreshCerts()

		pkiDesc = append(pkiDesc, "from-Vault")
		if s.InternalPki.UseVaultCerts {
			pkiDesc = append(pkiDesc, "useVaultCerts")
		}
	}
	if len(pkiDesc) == 0 {
		s.MyNode.InternalPki = "none"
	} else {
		s.MyNode.InternalPki = strings.Join(pkiDesc, ",")
	}
	return nil
}

// Load certs specified on command line.
func (s *internalPki) loadCerts(tlsCertFile string) error {
	dir := path.Dir(tlsCertFile)
	// load CA file
	caFile := dir + "/" + "mex-ca.crt"
	cabs, err := ioutil.ReadFile(caFile)
	if err != nil {
		return fmt.Errorf("failed to read %s: %v", caFile, err)
	}
	caCerts, err := certsFromPem(cabs)
	if err != nil {
		return fmt.Errorf("failed to parse CA cert %s: %v", caFile, err)
	}

	// load public and private key
	keyFile := strings.Replace(tlsCertFile, "crt", "key", 1)
	cert, err := tls.LoadX509KeyPair(tlsCertFile, keyFile)
	if err != nil {
		return fmt.Errorf("failed to load key pair %s: %v", tlsCertFile, err)
	}

	s.mux.Lock()
	s.fileCAs = caCerts
	s.fileCert = &cert
	s.mux.Unlock()
	return nil
}

func (s *internalPki) refreshCerts() {
	interval := refreshCertInterval
	for {
		select {
		case <-time.After(interval):
		case <-s.refreshTrigger:
			span := log.StartSpan(log.DebugLevelInfo, "refresh internal PKI certs")
			ctx := log.ContextWithSpan(context.Background(), span)
			err := s.RefreshNow(ctx)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfo, "refresh pki certs failures", "err", err)
				// retry again soon
				interval = time.Hour
			} else {
				interval = refreshCertInterval
			}
			span.Finish()
		}
	}
}

func (s *internalPki) RefreshNow(ctx context.Context) error {
	if s.vaultConfig.Addr == "" {
		return nil
	}
	log.SpanLog(ctx, log.DebugLevelInfo, "refreshing certs")
	ids := make([]certId, 0)
	s.mux.Lock()
	for id, _ := range s.certs {
		ids = append(ids, id)
	}
	s.mux.Unlock()

	failures := make([]string, 0)
	for _, id := range ids {
		cert, err := s.issueCert(ctx, id)
		if err != nil {
			str := fmt.Sprintf("cert %v: %v", id, err)
			failures = append(failures, str)
		}
		s.mux.Lock()
		s.certs[id] = cert
		s.mux.Unlock()
	}
	if len(failures) == 0 {
		return nil
	}
	return fmt.Errorf("failed to issue certs: %s", strings.Join(failures, ","))
}

func (s *internalPki) triggerRefresh() {
	select {
	case s.refreshTrigger <- true:
	default:
	}
}

// Adapated from x509.CertPool:AppendCertsFromPem()
func certsFromPem(pemCerts []byte) ([]*x509.Certificate, error) {
	certs := []*x509.Certificate{}
	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return certs, err
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// GetClientTlsConfig gets the TLS Config for the Client.
// The client issuer specifies where the client issues its cert from.
// The server issuers specify which CAs are trusted when verifying the
// remote server's certificate.
func (s *internalPki) GetClientTlsConfig(ctx context.Context, commonName, clientIssuer string, serverIssuers []MatchCA, ops ...TlsOp) (*tls.Config, error) {
	if !s.enabled {
		return nil, nil
	}
	opts := &TlsOptions{}
	for _, op := range ops {
		op(opts)
	}

	id := certId{
		CommonName: commonName,
		Issuer:     clientIssuer,
	}
	err := s.ensureCertInCache(ctx, id)
	if s.filterVaultPkiErr(ctx, err) != nil {
		return nil, err
	}

	caPool, err := s.getCAs(ctx, serverIssuers)
	if s.filterVaultPkiErr(ctx, err) != nil {
		return nil, err
	}

	// Use the GetClientCertificate func to be able to refresh certs
	config := &tls.Config{
		MinVersion:            tls.VersionTLS12,
		ServerName:            opts.serverName,
		InsecureSkipVerify:    opts.skipVerify,
		RootCAs:               caPool,
		GetClientCertificate:  s.getClientCertificateFunc(id),
		VerifyPeerCertificate: s.getVerifyFunc(serverIssuers),
	}
	return config, nil
}

// GetServerTlsConfig gets the TLS Config for the Server.
// The server issuer specifies where the server issues its cert from.
// The client issuers specify which CAs are trusted when verifying the
// remote client's certificate.
func (s *internalPki) GetServerTlsConfig(ctx context.Context, commonName, serverIssuer string, clientIssuers []MatchCA, ops ...TlsOp) (*tls.Config, error) {
	if !s.enabled {
		return nil, nil
	}
	opts := &TlsOptions{}
	for _, op := range ops {
		op(opts)
	}

	id := certId{
		CommonName: commonName,
		Issuer:     serverIssuer,
	}
	err := s.ensureCertInCache(ctx, id)
	if s.filterVaultPkiErr(ctx, err) != nil {
		return nil, err
	}

	caPool, err := s.getCAs(ctx, clientIssuers)
	if s.filterVaultPkiErr(ctx, err) != nil {
		return nil, err
	}

	// Use the GetCertificate func to be able to refresh certs
	config := &tls.Config{
		MinVersion:            tls.VersionTLS12,
		ClientAuth:            tls.RequireAndVerifyClientCert,
		ClientCAs:             caPool,
		GetCertificate:        s.getCertificateFunc(id),
		VerifyPeerCertificate: s.getVerifyFunc(clientIssuers),
	}
	if opts.noMutualAuth {
		config.ClientAuth = tls.NoClientCert
	}
	return config, nil
}

func (s *internalPki) filterVaultPkiErr(ctx context.Context, err error) error {
	// If file certs are specified and UseVaultCerts is false,
	// log VaultPki lookup failures instead of returning an error.
	// This allows us to rollout the Vault Pki code even if
	// Vault hasn't been configured for it yet.
	if err != nil && s.fileCert != nil && !s.UseVaultCerts {
		log.SpanLog(ctx, log.DebugLevelInfo, "Suppress Vault PKI error", "err", err)
		return nil
	}
	return err
}

func (s *internalPki) getVerifyFunc(issuers []MatchCA) func([][]byte, [][]*x509.Certificate) error {
	matchRegion := make(map[string]struct{})
	for _, issuer := range issuers {
		if issuer.RequireRegionMatch {
			matchRegion[issuer.Issuer] = struct{}{}
		}
	}
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if verifiedChains == nil {
			// tls not configured for connection
			return nil
		}
		if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 {
			fmt.Printf("no cert in verifiedChains?\n")
			return nil
		}
		for _, chain := range verifiedChains {
			regionalCAName := ""
			for _, cert := range chain {
				if !cert.IsCA || len(cert.DNSNames) == 0 {
					continue
				}
				commonName := cert.DNSNames[0]
				// Check if cert is issued by Vault regional CA
				if commonName == CertIssuerRegional || commonName == CertIssuerRegionalCloudlet {
					regionalCAName = commonName
					break
				}
			}
			if regionalCAName == "" {
				continue
			}
			// Cert issued by Vault regional CA must have
			// region tag to be valid.
			cert := chain[0]
			region := ""
			for _, uri := range cert.URIs {
				strs := strings.Split(uri.String(), "://")
				if len(strs) == 2 && strs[0] == "region" {
					region = strs[1]
				}
			}
			if region == "" {
				return fmt.Errorf("Vault CA issued by %s to %v without region URI_SANS tag (tags are %v)", regionalCAName, cert.DNSNames, cert.URIs)
			}
			// Tls config may require region match
			_, found := matchRegion[regionalCAName]
			if found && region != s.localRegion {
				return fmt.Errorf("region mismatch, expected local uri sans for %s but remote cert for %v has URI SANS %v", s.localRegion, cert.DNSNames, cert.URIs)
			}
		}
		return nil
	}
}

func (s *internalPki) getClientCertificateFunc(id certId) func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return s.lookupCertForHandshake(id)
	}
}

func (s *internalPki) getCertificateFunc(id certId) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return s.lookupCertForHandshake(id)
	}
}

func (s *internalPki) lookupCertForHandshake(id certId) (*tls.Certificate, error) {
	if s.vaultConfig.Addr != "" && s.UseVaultCerts {
		s.mux.Lock()
		cert, found := s.certs[id]
		s.mux.Unlock()
		if !found {
			return nil, fmt.Errorf("cert for %v not found in internal vault pki cache", id)
		}
		return cert, nil
	}
	if s.fileCert != nil {
		return s.fileCert, nil
	}
	return nil, fmt.Errorf("internal PKI disabled and no supplied certs for %v", id)
}

func (s *internalPki) ensureCertInCache(ctx context.Context, id certId) error {
	if s.vaultConfig.Addr == "" {
		return nil
	}
	s.mux.Lock()
	_, found := s.certs[id]
	s.mux.Unlock()
	if !found {
		cert, err := s.issueCert(ctx, id)
		if err != nil {
			return err
		}
		s.mux.Lock()
		s.certs[id] = cert
		s.mux.Unlock()
	}
	return nil
}

func (s *internalPki) issueCert(ctx context.Context, id certId) (*tls.Certificate, error) {
	rolename := s.localRegion
	uriSans := "region://" + s.localRegion
	if rolename == "" {
		rolename = "default"
		uriSans = "region://none"
	}
	path := id.Issuer + "/issue/" + rolename

	data := make(map[string]interface{})
	data["common_name"] = id.CommonName
	data["ttl"] = "72h"
	data["alt_names"] = "*." + id.CommonName + ",localhost"
	data["ip_sans"] = "127.0.0.1,0.0.0.0"
	data["uri_sans"] = uriSans

	log.SpanLog(ctx, log.DebugLevelInfo, "issue internal cert", "path", path, "id", id, "request", data)

	client, err := s.vaultConfig.Login()
	if err != nil {
		return nil, fmt.Errorf("issueCert login failure %v", err)
	}

	secret, err := client.Logical().Write(path, data)
	if err != nil {
		return nil, fmt.Errorf("issueCert write failure %s %v", path, err)
	}

	pub, err := getVaultCertData(secret.Data, "certificate")
	if err != nil {
		return nil, fmt.Errorf("issueCert certificate data failure %v", err)
	}
	key, err := getVaultCertData(secret.Data, "private_key")
	if err != nil {
		return nil, fmt.Errorf("issueCert private_key data failure %v", err)
	}

	cert, err := tls.X509KeyPair(pub, key)
	if err != nil {
		return nil, fmt.Errorf("failed to load x509 key pair, %v", err)
	}
	return &cert, nil
}

func getVaultCertData(data map[string]interface{}, key string) ([]byte, error) {
	dat, ok := data[key]
	if !ok {
		return nil, fmt.Errorf("key %s not found in Vault data", key)
	}
	listStr := "list "
	// may be list of certs
	list, ok := dat.([]interface{})
	if !ok {
		list = []interface{}{dat}
		listStr = ""
	}
	pemData := []byte{}
	for _, obj := range list {
		switch v := obj.(type) {
		case []byte:
			pemData = append(pemData, v...)
		case string:
			pemData = append(pemData, []byte(v)...)
		default:
			return nil, fmt.Errorf("%skey %s unexpected data format %T", listStr, key, obj)
		}
	}
	return pemData, nil
}

func (s *internalPki) getCAs(ctx context.Context, issuers []MatchCA) (*x509.CertPool, error) {
	pool := x509.NewCertPool()

	if s.fileCAs != nil {
		for _, ca := range s.fileCAs {
			pool.AddCert(ca)
		}
	}

	if s.vaultConfig.Addr == "" {
		return pool, nil
	}
	var client *api.Client
	var err error
	for _, caissuer := range issuers {
		s.mux.Lock()
		cas, found := s.cas[caissuer.Issuer]
		s.mux.Unlock()
		if !found {
			path := caissuer.Issuer + "/cert/ca"
			log.SpanLog(ctx, log.DebugLevelInfo, "pki getCAs", "path", path)
			if client == nil {
				client, err = s.vaultConfig.Login()
				if err != nil {
					return nil, err
				}
			}
			secret, err := client.Logical().Read(path)
			if err != nil {
				return nil, err
			}
			cab, err := getVaultCertData(secret.Data, "certificate")
			if err != nil {
				return nil, err
			}
			cas, err = certsFromPem(cab)
			if err != nil {
				return nil, err
			}
			s.mux.Lock()
			s.cas[caissuer.Issuer] = cas
			s.mux.Unlock()
		}
		for _, ca := range cas {
			pool.AddCert(ca)
		}
	}
	return pool, nil
}

func (s *NodeMgr) CommonName() string {
	cn := s.MyNode.Key.Type
	if cn == NodeTypeController {
		cn = "ctrl"
	}
	return cn + "." + cloudcommon.CertDNSRoot
}

type TlsOptions struct {
	serverName   string
	skipVerify   bool
	noMutualAuth bool
}

type TlsOp func(s *TlsOptions)

func WithTlsServerName(name string) TlsOp {
	name = strings.Split(name, ":")[0]
	return func(opts *TlsOptions) { opts.serverName = name }
}

func WithTlsSkipVerify(skipVerify bool) TlsOp {
	return func(opts *TlsOptions) { opts.skipVerify = skipVerify }
}

func WithNoMutualAuth(noMutualAuth bool) TlsOp {
	return func(opts *TlsOptions) { opts.noMutualAuth = noMutualAuth }
}