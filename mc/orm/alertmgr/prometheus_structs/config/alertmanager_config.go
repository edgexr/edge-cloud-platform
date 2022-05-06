// Copyright 2015 Prometheus Team
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

package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	commoncfg "github.com/edgexr/edge-cloud-infra/mc/orm/alertmgr/prometheus_structs/commoncfg"
	model "github.com/edgexr/edge-cloud-infra/mc/orm/alertmgr/prometheus_structs/model"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

/*
* This is local modification to allow marshaling and unmarshaling secrets
const secretToken = "<secret>"

var secretTokenJSON string

func init() {
	b, err := json.Marshal(secretToken)
	if err != nil {
		panic(err)
	}
	secretTokenJSON = string(b)
}
*/
// Secret is a string that must not be revealed on marshaling.
type Secret string

// MarshalYAML implements the yaml.Marshaler interface for Secret.
func (s Secret) MarshalYAML() (interface{}, error) {
	return s, nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface for Secret.
func (s *Secret) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain Secret
	return unmarshal((*plain)(s))
}

// MarshalJSON implements the json.Marshaler interface for Secret.
func (s Secret) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(s))
}

// URL is a custom type that represents an HTTP or HTTPS URL and allows validation at configuration load time.
type URL struct {
	*url.URL
}

// Copy makes a deep-copy of the struct.
func (u *URL) Copy() *URL {
	v := *u.URL
	return &URL{&v}
}

// MarshalYAML implements the yaml.Marshaler interface for URL.
func (u URL) MarshalYAML() (interface{}, error) {
	if u.URL != nil {
		return u.URL.String(), nil
	}
	return nil, nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface for URL.
func (u *URL) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	urlp, err := parseURL(s)
	if err != nil {
		return err
	}
	u.URL = urlp.URL
	return nil
}

// MarshalJSON implements the json.Marshaler interface for URL.
func (u URL) MarshalJSON() ([]byte, error) {
	if u.URL != nil {
		return json.Marshal(u.URL.String())
	}
	return nil, nil
}

// UnmarshalJSON implements the json.Marshaler interface for URL.
func (u *URL) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	urlp, err := parseURL(s)
	if err != nil {
		return err
	}
	u.URL = urlp.URL
	return nil
}

/* Note - local change. We don't need secret URLs.
*
// SecretURL is a URL that must not be revealed on marshaling.
type SecretURL URL

// MarshalYAML implements the yaml.Marshaler interface for SecretURL.
func (s SecretURL) MarshalYAML() (interface{}, error) {
	if s.URL != nil {
		return secretToken, nil
	}
	return nil, nil
}

// UnmarshalYAML implements the yaml.Unmarshaler interface for SecretURL.
func (s *SecretURL) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var str string
	if err := unmarshal(&str); err != nil {
		return err
	}
	// In order to deserialize a previously serialized configuration (eg from
	// the Alertmanager API with amtool), `<secret>` needs to be treated
	// specially, as it isn't a valid URL.
	if str == secretToken {
		s.URL = &url.URL{}
		return nil
	}
	return unmarshal((*URL)(s))
}

// MarshalJSON implements the json.Marshaler interface for SecretURL.
func (s SecretURL) MarshalJSON() ([]byte, error) {
	return json.Marshal(secretToken)
}

// UnmarshalJSON implements the json.Marshaler interface for SecretURL.
func (s *SecretURL) UnmarshalJSON(data []byte) error {
	// In order to deserialize a previously serialized configuration (eg from
	// the Alertmanager API with amtool), `<secret>` needs to be treated
	// specially, as it isn't a valid URL.
	if string(data) == secretToken || string(data) == secretTokenJSON {
		s.URL = &url.URL{}
		return nil
	}
	return json.Unmarshal(data, (*URL)(s))
}
*/
// Load parses the YAML input s into a Config.
func Load(s string) (*Config, error) {
	cfg := &Config{}
	err := yaml.UnmarshalStrict([]byte(s), cfg)
	if err != nil {
		return nil, err
	}
	// Check if we have a root route. We cannot check for it in the
	// UnmarshalYAML method because it won't be called if the input is empty
	// (e.g. the config file is empty or only contains whitespace).
	if cfg.Route == nil {
		return nil, errors.New("no route provided in config")
	}

	// Check if continue in root route.
	if cfg.Route.Continue {
		return nil, errors.New("cannot have continue in root route")
	}

	cfg.original = s
	return cfg, nil
}

// LoadFile parses the given YAML file into a Config.
func LoadFile(filename string) (*Config, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	cfg, err := Load(string(content))
	if err != nil {
		return nil, err
	}

	resolveFilepaths(filepath.Dir(filename), cfg)
	return cfg, nil
}

// resolveFilepaths joins all relative paths in a configuration
// with a given base directory.
func resolveFilepaths(baseDir string, cfg *Config) {
	join := func(fp string) string {
		if len(fp) > 0 && !filepath.IsAbs(fp) {
			fp = filepath.Join(baseDir, fp)
		}
		return fp
	}

	for i, tf := range cfg.Templates {
		cfg.Templates[i] = join(tf)
	}
}

// Config is the top-level configuration for Alertmanager's config files.
type Config struct {
	Global       *GlobalConfig  `yaml:"global,omitempty" json:"global,omitempty"`
	Route        *Route         `yaml:"route,omitempty" json:"route,omitempty"`
	InhibitRules []*InhibitRule `yaml:"inhibit_rules,omitempty" json:"inhibit_rules,omitempty"`
	Receivers    []*Receiver    `yaml:"receivers,omitempty" json:"receivers,omitempty"`
	Templates    []string       `yaml:"templates" json:"templates"`

	// original is the input from which the config was parsed.
	original string
}

func (c Config) String() string {
	b, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Sprintf("<error creating config string: %s>", err)
	}
	return string(b)
}

// UnmarshalYAML implements the yaml.Unmarshaler interface for Config.
func (c *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// We want to set c to the defaults and then overwrite it with the input.
	// To make unmarshal fill the plain data struct rather than calling UnmarshalYAML
	// again, we have to hide it using a type indirection.
	type plain Config
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}

	// If a global block was open but empty the default global config is overwritten.
	// We have to restore it here.
	if c.Global == nil {
		c.Global = &GlobalConfig{}
		*c.Global = DefaultGlobalConfig()
	}

	names := map[string]struct{}{}

	for _, rcv := range c.Receivers {
		if _, ok := names[rcv.Name]; ok {
			return fmt.Errorf("notification config name %q is not unique", rcv.Name)
		}
		for _, wh := range rcv.WebhookConfigs {
			if wh.HTTPConfig == nil {
				wh.HTTPConfig = c.Global.HTTPConfig
			}
		}
		for _, ec := range rcv.EmailConfigs {
			if ec.Smarthost.String() == "" {
				if c.Global.SMTPSmarthost.String() == "" {
					return fmt.Errorf("no global SMTP smarthost set")
				}
				ec.Smarthost = c.Global.SMTPSmarthost
			}
			if ec.From == "" {
				if c.Global.SMTPFrom == "" {
					return fmt.Errorf("no global SMTP from set")
				}
				ec.From = c.Global.SMTPFrom
			}
			if ec.Hello == "" {
				ec.Hello = c.Global.SMTPHello
			}
			if ec.AuthUsername == "" {
				ec.AuthUsername = c.Global.SMTPAuthUsername
			}
			if ec.AuthPassword == "" {
				ec.AuthPassword = c.Global.SMTPAuthPassword
			}
			if ec.AuthSecret == "" {
				ec.AuthSecret = c.Global.SMTPAuthSecret
			}
			if ec.AuthIdentity == "" {
				ec.AuthIdentity = c.Global.SMTPAuthIdentity
			}
			if ec.RequireTLS == nil {
				ec.RequireTLS = new(bool)
				*ec.RequireTLS = c.Global.SMTPRequireTLS
			}
		}
		for _, sc := range rcv.SlackConfigs {
			if sc.HTTPConfig == nil {
				sc.HTTPConfig = c.Global.HTTPConfig
			}
			if sc.APIURL == nil {
				if c.Global.SlackAPIURL == nil {
					return fmt.Errorf("no global Slack API URL set")
				}
				sc.APIURL = c.Global.SlackAPIURL
			}
		}
		for _, poc := range rcv.PushoverConfigs {
			if poc.HTTPConfig == nil {
				poc.HTTPConfig = c.Global.HTTPConfig
			}
		}
		for _, pdc := range rcv.PagerdutyConfigs {
			if pdc.HTTPConfig == nil {
				pdc.HTTPConfig = c.Global.HTTPConfig
			}
			if pdc.URL == nil {
				if c.Global.PagerdutyURL == nil {
					return fmt.Errorf("no global PagerDuty URL set")
				}
				pdc.URL = c.Global.PagerdutyURL
			}
		}
		for _, ogc := range rcv.OpsGenieConfigs {
			if ogc.HTTPConfig == nil {
				ogc.HTTPConfig = c.Global.HTTPConfig
			}
			if ogc.APIURL == nil {
				if c.Global.OpsGenieAPIURL == nil {
					return fmt.Errorf("no global OpsGenie URL set")
				}
				ogc.APIURL = c.Global.OpsGenieAPIURL
			}
			if !strings.HasSuffix(ogc.APIURL.Path, "/") {
				ogc.APIURL.Path += "/"
			}
			if ogc.APIKey == "" {
				if c.Global.OpsGenieAPIKey == "" {
					return fmt.Errorf("no global OpsGenie API Key set")
				}
				ogc.APIKey = c.Global.OpsGenieAPIKey
			}
		}
		for _, wcc := range rcv.WechatConfigs {
			if wcc.HTTPConfig == nil {
				wcc.HTTPConfig = c.Global.HTTPConfig
			}

			if wcc.APIURL == nil {
				if c.Global.WeChatAPIURL == nil {
					return fmt.Errorf("no global Wechat URL set")
				}
				wcc.APIURL = c.Global.WeChatAPIURL
			}

			if wcc.APISecret == "" {
				if c.Global.WeChatAPISecret == "" {
					return fmt.Errorf("no global Wechat ApiSecret set")
				}
				wcc.APISecret = c.Global.WeChatAPISecret
			}

			if wcc.CorpID == "" {
				if c.Global.WeChatAPICorpID == "" {
					return fmt.Errorf("no global Wechat CorpID set")
				}
				wcc.CorpID = c.Global.WeChatAPICorpID
			}

			if !strings.HasSuffix(wcc.APIURL.Path, "/") {
				wcc.APIURL.Path += "/"
			}
		}
		for _, voc := range rcv.VictorOpsConfigs {
			if voc.HTTPConfig == nil {
				voc.HTTPConfig = c.Global.HTTPConfig
			}
			if voc.APIURL == nil {
				if c.Global.VictorOpsAPIURL == nil {
					return fmt.Errorf("no global VictorOps URL set")
				}
				voc.APIURL = c.Global.VictorOpsAPIURL
			}
			if !strings.HasSuffix(voc.APIURL.Path, "/") {
				voc.APIURL.Path += "/"
			}
			if voc.APIKey == "" {
				if c.Global.VictorOpsAPIKey == "" {
					return fmt.Errorf("no global VictorOps API Key set")
				}
				voc.APIKey = c.Global.VictorOpsAPIKey
			}
		}
		names[rcv.Name] = struct{}{}
	}

	// The root route must not have any matchers as it is the fallback node
	// for all alerts.
	if c.Route == nil {
		return fmt.Errorf("no routes provided")
	}
	if len(c.Route.Receiver) == 0 {
		return fmt.Errorf("root route must specify a default receiver")
	}
	if len(c.Route.Match) > 0 || len(c.Route.MatchRE) > 0 {
		return fmt.Errorf("root route must not have any matchers")
	}

	// Validate that all receivers used in the routing tree are defined.
	return checkReceiver(c.Route, names)
}

// checkReceiver returns an error if a node in the routing tree
// references a receiver not in the given map.
func checkReceiver(r *Route, receivers map[string]struct{}) error {
	for _, sr := range r.Routes {
		if err := checkReceiver(sr, receivers); err != nil {
			return err
		}
	}
	if r.Receiver == "" {
		return nil
	}
	if _, ok := receivers[r.Receiver]; !ok {
		return fmt.Errorf("undefined receiver %q used in route", r.Receiver)
	}
	return nil
}

// DefaultGlobalConfig returns GlobalConfig with default values.
func DefaultGlobalConfig() GlobalConfig {
	return GlobalConfig{
		ResolveTimeout: model.Duration(5 * time.Minute),
		HTTPConfig:     &commoncfg.HTTPClientConfig{},

		SMTPHello:       "localhost",
		SMTPRequireTLS:  true,
		PagerdutyURL:    mustParseURL("https://events.pagerduty.com/v2/enqueue"),
		OpsGenieAPIURL:  mustParseURL("https://api.opsgenie.com/"),
		WeChatAPIURL:    mustParseURL("https://qyapi.weixin.qq.com/cgi-bin/"),
		VictorOpsAPIURL: mustParseURL("https://alert.victorops.com/integrations/generic/20131114/alert/"),
	}
}

func mustParseURL(s string) *URL {
	u, err := parseURL(s)
	if err != nil {
		panic(err)
	}
	return u
}

func parseURL(s string) (*URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme %q for URL", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("missing host for URL")
	}
	return &URL{u}, nil
}

// HostPort represents a "host:port" network address.
type HostPort struct {
	Host string
	Port string
}

// UnmarshalYAML implements the yaml.Unmarshaler interface for HostPort.
func (hp *HostPort) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var (
		s   string
		err error
	)
	if err = unmarshal(&s); err != nil {
		return err
	}
	if s == "" {
		return nil
	}
	hp.Host, hp.Port, err = net.SplitHostPort(s)
	if err != nil {
		return err
	}
	if hp.Port == "" {
		return errors.Errorf("address %q: port cannot be empty", s)
	}
	return nil
}

// UnmarshalJSON implements the json.Unmarshaler interface for HostPort.
func (hp *HostPort) UnmarshalJSON(data []byte) error {
	var (
		s   string
		err error
	)
	if err = json.Unmarshal(data, &s); err != nil {
		return err
	}
	if s == "" {
		return nil
	}
	hp.Host, hp.Port, err = net.SplitHostPort(s)
	if err != nil {
		return err
	}
	if hp.Port == "" {
		return errors.Errorf("address %q: port cannot be empty", s)
	}
	return nil
}

// MarshalYAML implements the yaml.Marshaler interface for HostPort.
func (hp HostPort) MarshalYAML() (interface{}, error) {
	return hp.String(), nil
}

// MarshalJSON implements the json.Marshaler interface for HostPort.
func (hp HostPort) MarshalJSON() ([]byte, error) {
	return json.Marshal(hp.String())
}

func (hp HostPort) String() string {
	if hp.Host == "" && hp.Port == "" {
		return ""
	}
	return fmt.Sprintf("%s:%s", hp.Host, hp.Port)
}

// GlobalConfig defines configuration parameters that are valid globally
// unless overwritten.
type GlobalConfig struct {
	// ResolveTimeout is the time after which an alert is declared resolved
	// if it has not been updated.
	ResolveTimeout model.Duration `yaml:"resolve_timeout" json:"resolve_timeout"`

	HTTPConfig *commoncfg.HTTPClientConfig `yaml:"http_config,omitempty" json:"http_config,omitempty"`

	SMTPFrom         string   `yaml:"smtp_from,omitempty" json:"smtp_from,omitempty"`
	SMTPHello        string   `yaml:"smtp_hello,omitempty" json:"smtp_hello,omitempty"`
	SMTPSmarthost    HostPort `yaml:"smtp_smarthost,omitempty" json:"smtp_smarthost,omitempty"`
	SMTPAuthUsername string   `yaml:"smtp_auth_username,omitempty" json:"smtp_auth_username,omitempty"`
	SMTPAuthPassword Secret   `yaml:"smtp_auth_password,omitempty" json:"smtp_auth_password,omitempty"`
	SMTPAuthSecret   Secret   `yaml:"smtp_auth_secret,omitempty" json:"smtp_auth_secret,omitempty"`
	SMTPAuthIdentity string   `yaml:"smtp_auth_identity,omitempty" json:"smtp_auth_identity,omitempty"`
	SMTPRequireTLS   bool     `yaml:"smtp_require_tls" json:"smtp_require_tls"`
	SlackAPIURL      *URL     `yaml:"slack_api_url,omitempty" json:"slack_api_url,omitempty"`
	PagerdutyURL     *URL     `yaml:"pagerduty_url,omitempty" json:"pagerduty_url,omitempty"`
	OpsGenieAPIURL   *URL     `yaml:"opsgenie_api_url,omitempty" json:"opsgenie_api_url,omitempty"`
	OpsGenieAPIKey   Secret   `yaml:"opsgenie_api_key,omitempty" json:"opsgenie_api_key,omitempty"`
	WeChatAPIURL     *URL     `yaml:"wechat_api_url,omitempty" json:"wechat_api_url,omitempty"`
	WeChatAPISecret  Secret   `yaml:"wechat_api_secret,omitempty" json:"wechat_api_secret,omitempty"`
	WeChatAPICorpID  string   `yaml:"wechat_api_corp_id,omitempty" json:"wechat_api_corp_id,omitempty"`
	VictorOpsAPIURL  *URL     `yaml:"victorops_api_url,omitempty" json:"victorops_api_url,omitempty"`
	VictorOpsAPIKey  Secret   `yaml:"victorops_api_key,omitempty" json:"victorops_api_key,omitempty"`
}

// UnmarshalYAML implements the yaml.Unmarshaler interface for GlobalConfig.
func (c *GlobalConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*c = DefaultGlobalConfig()
	type plain GlobalConfig
	return unmarshal((*plain)(c))
}

// A Route is a node that contains definitions of how to handle alerts.
type Route struct {
	Receiver string `yaml:"receiver,omitempty" json:"receiver,omitempty"`

	GroupByStr []string          `yaml:"group_by,omitempty" json:"group_by,omitempty"`
	GroupBy    []model.LabelName `yaml:"-" json:"-"`
	GroupByAll bool              `yaml:"-" json:"-"`

	Match    map[string]string `yaml:"match,omitempty" json:"match,omitempty"`
	MatchRE  MatchRegexps      `yaml:"match_re,omitempty" json:"match_re,omitempty"`
	Continue bool              `yaml:"continue,omitempty" json:"continue,omitempty"`
	Routes   []*Route          `yaml:"routes,omitempty" json:"routes,omitempty"`

	GroupWait      *model.Duration `yaml:"group_wait,omitempty" json:"group_wait,omitempty"`
	GroupInterval  *model.Duration `yaml:"group_interval,omitempty" json:"group_interval,omitempty"`
	RepeatInterval *model.Duration `yaml:"repeat_interval,omitempty" json:"repeat_interval,omitempty"`
}

// UnmarshalYAML implements the yaml.Unmarshaler interface for Route.
func (r *Route) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain Route
	if err := unmarshal((*plain)(r)); err != nil {
		return err
	}

	for k := range r.Match {
		if !model.LabelNameRE.MatchString(k) {
			return fmt.Errorf("invalid label name %q", k)
		}
	}

	for _, l := range r.GroupByStr {
		if l == "..." {
			r.GroupByAll = true
		} else {
			labelName := model.LabelName(l)
			if !labelName.IsValid() {
				return fmt.Errorf("invalid label name %q in group_by list", l)
			}
			r.GroupBy = append(r.GroupBy, labelName)
		}
	}

	if len(r.GroupBy) > 0 && r.GroupByAll {
		return fmt.Errorf("cannot have wildcard group_by (`...`) and other other labels at the same time")
	}

	groupBy := map[model.LabelName]struct{}{}

	for _, ln := range r.GroupBy {
		if _, ok := groupBy[ln]; ok {
			return fmt.Errorf("duplicated label %q in group_by", ln)
		}
		groupBy[ln] = struct{}{}
	}

	if r.GroupInterval != nil && time.Duration(*r.GroupInterval) == time.Duration(0) {
		return fmt.Errorf("group_interval cannot be zero")
	}
	if r.RepeatInterval != nil && time.Duration(*r.RepeatInterval) == time.Duration(0) {
		return fmt.Errorf("repeat_interval cannot be zero")
	}

	return nil
}

// InhibitRule defines an inhibition rule that mutes alerts that match the
// target labels if an alert matching the source labels exists.
// Both alerts have to have a set of labels being equal.
type InhibitRule struct {
	// SourceMatch defines a set of labels that have to equal the given
	// value for source alerts.
	SourceMatch map[string]string `yaml:"source_match,omitempty" json:"source_match,omitempty"`
	// SourceMatchRE defines pairs like SourceMatch but does regular expression
	// matching.
	SourceMatchRE MatchRegexps `yaml:"source_match_re,omitempty" json:"source_match_re,omitempty"`
	// TargetMatch defines a set of labels that have to equal the given
	// value for target alerts.
	TargetMatch map[string]string `yaml:"target_match,omitempty" json:"target_match,omitempty"`
	// TargetMatchRE defines pairs like TargetMatch but does regular expression
	// matching.
	TargetMatchRE MatchRegexps `yaml:"target_match_re,omitempty" json:"target_match_re,omitempty"`
	// A set of labels that must be equal between the source and target alert
	// for them to be a match.
	Equal model.LabelNames `yaml:"equal,omitempty" json:"equal,omitempty"`
}

// UnmarshalYAML implements the yaml.Unmarshaler interface for InhibitRule.
func (r *InhibitRule) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain InhibitRule
	if err := unmarshal((*plain)(r)); err != nil {
		return err
	}

	for k := range r.SourceMatch {
		if !model.LabelNameRE.MatchString(k) {
			return fmt.Errorf("invalid label name %q", k)
		}
	}

	for k := range r.TargetMatch {
		if !model.LabelNameRE.MatchString(k) {
			return fmt.Errorf("invalid label name %q", k)
		}
	}

	return nil
}

// Receiver configuration provides configuration on how to contact a receiver.
type Receiver struct {
	// A unique identifier for this receiver.
	Name string `yaml:"name" json:"name"`

	EmailConfigs     []*EmailConfig     `yaml:"email_configs,omitempty" json:"email_configs,omitempty"`
	PagerdutyConfigs []*PagerdutyConfig `yaml:"pagerduty_configs,omitempty" json:"pagerduty_configs,omitempty"`
	SlackConfigs     []*SlackConfig     `yaml:"slack_configs,omitempty" json:"slack_configs,omitempty"`
	WebhookConfigs   []*WebhookConfig   `yaml:"webhook_configs,omitempty" json:"webhook_configs,omitempty"`
	OpsGenieConfigs  []*OpsGenieConfig  `yaml:"opsgenie_configs,omitempty" json:"opsgenie_configs,omitempty"`
	WechatConfigs    []*WechatConfig    `yaml:"wechat_configs,omitempty" json:"wechat_configs,omitempty"`
	PushoverConfigs  []*PushoverConfig  `yaml:"pushover_configs,omitempty" json:"pushover_configs,omitempty"`
	VictorOpsConfigs []*VictorOpsConfig `yaml:"victorops_configs,omitempty" json:"victorops_configs,omitempty"`
}

// UnmarshalYAML implements the yaml.Unmarshaler interface for Receiver.
func (c *Receiver) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain Receiver
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}
	if c.Name == "" {
		return fmt.Errorf("missing name in receiver")
	}
	return nil
}

// MatchRegexps represents a map of Regexp.
type MatchRegexps map[string]Regexp

// UnmarshalYAML implements the yaml.Unmarshaler interface for MatchRegexps.
func (m *MatchRegexps) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain MatchRegexps
	if err := unmarshal((*plain)(m)); err != nil {
		return err
	}
	for k, v := range *m {
		if !model.LabelNameRE.MatchString(k) {
			return fmt.Errorf("invalid label name %q", k)
		}
		if v.Regexp == nil {
			return fmt.Errorf("invalid regexp value for %q", k)
		}
	}
	return nil
}

// Regexp encapsulates a regexp.Regexp and makes it YAML marshalable.
type Regexp struct {
	*regexp.Regexp
	original string
}

// UnmarshalYAML implements the yaml.Unmarshaler interface for Regexp.
func (re *Regexp) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	regex, err := regexp.Compile("^(?:" + s + ")$")
	if err != nil {
		return err
	}
	re.Regexp = regex
	re.original = s
	return nil
}

// MarshalYAML implements the yaml.Marshaler interface for Regexp.
func (re Regexp) MarshalYAML() (interface{}, error) {
	if re.original != "" {
		return re.original, nil
	}
	return nil, nil
}

// UnmarshalJSON implements the json.Marshaler interface for Regexp
func (re *Regexp) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	regex, err := regexp.Compile("^(?:" + s + ")$")
	if err != nil {
		return err
	}
	re.Regexp = regex
	re.original = s
	return nil
}

// MarshalJSON implements the json.Marshaler interface for Regexp.
func (re Regexp) MarshalJSON() ([]byte, error) {
	if re.original != "" {
		return json.Marshal(re.original)
	}
	return nil, nil
}

//// notifiers.go
var (
	// DefaultWebhookConfig defines default values for Webhook configurations.
	DefaultWebhookConfig = WebhookConfig{
		NotifierConfig: NotifierConfig{
			VSendResolved: true,
		},
	}

	// DefaultEmailConfig defines default values for Email configurations.
	DefaultEmailConfig = EmailConfig{
		NotifierConfig: NotifierConfig{
			VSendResolved: false,
		},
		HTML: `{{ template "email.default.html" . }}`,
		Text: ``,
	}

	// DefaultEmailSubject defines the default Subject header of an Email.
	DefaultEmailSubject = `{{ template "email.default.subject" . }}`

	// DefaultPagerdutyDetails defines the default values for PagerDuty details.
	DefaultPagerdutyDetails = map[string]string{
		"firing":       `{{ template "pagerduty.default.instances" .Alerts.Firing }}`,
		"resolved":     `{{ template "pagerduty.default.instances" .Alerts.Resolved }}`,
		"num_firing":   `{{ .Alerts.Firing | len }}`,
		"num_resolved": `{{ .Alerts.Resolved | len }}`,
	}

	// DefaultPagerdutyConfig defines default values for PagerDuty configurations.
	DefaultPagerdutyConfig = PagerdutyConfig{
		NotifierConfig: NotifierConfig{
			VSendResolved: true,
		},
		Description: `{{ template "pagerduty.default.description" .}}`,
		Client:      `{{ template "pagerduty.default.client" . }}`,
		ClientURL:   `{{ template "pagerduty.default.clientURL" . }}`,
	}

	// DefaultSlackConfig defines default values for Slack configurations.
	DefaultSlackConfig = SlackConfig{
		NotifierConfig: NotifierConfig{
			VSendResolved: false,
		},
		Color:      `{{ if eq .Status "firing" }}danger{{ else }}good{{ end }}`,
		Username:   `{{ template "slack.default.username" . }}`,
		Title:      `{{ template "slack.default.title" . }}`,
		TitleLink:  `{{ template "slack.default.titlelink" . }}`,
		IconEmoji:  `{{ template "slack.default.iconemoji" . }}`,
		IconURL:    `{{ template "slack.default.iconurl" . }}`,
		Pretext:    `{{ template "slack.default.pretext" . }}`,
		Text:       `{{ template "slack.default.text" . }}`,
		Fallback:   `{{ template "slack.default.fallback" . }}`,
		CallbackID: `{{ template "slack.default.callbackid" . }}`,
		Footer:     `{{ template "slack.default.footer" . }}`,
	}

	// DefaultOpsGenieConfig defines default values for OpsGenie configurations.
	DefaultOpsGenieConfig = OpsGenieConfig{
		NotifierConfig: NotifierConfig{
			VSendResolved: true,
		},
		Message:     `{{ template "opsgenie.default.message" . }}`,
		Description: `{{ template "opsgenie.default.description" . }}`,
		Source:      `{{ template "opsgenie.default.source" . }}`,
		// TODO: Add a details field with all the alerts.
	}

	// DefaultWechatConfig defines default values for wechat configurations.
	DefaultWechatConfig = WechatConfig{
		NotifierConfig: NotifierConfig{
			VSendResolved: false,
		},
		Message: `{{ template "wechat.default.message" . }}`,
		ToUser:  `{{ template "wechat.default.to_user" . }}`,
		ToParty: `{{ template "wechat.default.to_party" . }}`,
		ToTag:   `{{ template "wechat.default.to_tag" . }}`,
		AgentID: `{{ template "wechat.default.agent_id" . }}`,
	}

	// DefaultVictorOpsConfig defines default values for VictorOps configurations.
	DefaultVictorOpsConfig = VictorOpsConfig{
		NotifierConfig: NotifierConfig{
			VSendResolved: true,
		},
		MessageType:       `CRITICAL`,
		StateMessage:      `{{ template "victorops.default.state_message" . }}`,
		EntityDisplayName: `{{ template "victorops.default.entity_display_name" . }}`,
		MonitoringTool:    `{{ template "victorops.default.monitoring_tool" . }}`,
	}

	// DefaultPushoverConfig defines default values for Pushover configurations.
	DefaultPushoverConfig = PushoverConfig{
		NotifierConfig: NotifierConfig{
			VSendResolved: true,
		},
		Title:    `{{ template "pushover.default.title" . }}`,
		Message:  `{{ template "pushover.default.message" . }}`,
		URL:      `{{ template "pushover.default.url" . }}`,
		Priority: `{{ if eq .Status "firing" }}2{{ else }}0{{ end }}`, // emergency (firing) or normal
		Retry:    duration(1 * time.Minute),
		Expire:   duration(1 * time.Hour),
		HTML:     false,
	}
)

// NotifierConfig contains base options common across all notifier configurations.
type NotifierConfig struct {
	VSendResolved bool `yaml:"send_resolved" json:"send_resolved"`
}

func (nc *NotifierConfig) SendResolved() bool {
	return nc.VSendResolved
}

// EmailConfig configures notifications via mail.
type EmailConfig struct {
	NotifierConfig `yaml:",inline" json:",inline"`

	// Email address to notify.
	To           string              `yaml:"to,omitempty" json:"to,omitempty"`
	From         string              `yaml:"from,omitempty" json:"from,omitempty"`
	Hello        string              `yaml:"hello,omitempty" json:"hello,omitempty"`
	Smarthost    HostPort            `yaml:"smarthost,omitempty" json:"smarthost,omitempty"`
	AuthUsername string              `yaml:"auth_username,omitempty" json:"auth_username,omitempty"`
	AuthPassword Secret              `yaml:"auth_password,omitempty" json:"auth_password,omitempty"`
	AuthSecret   Secret              `yaml:"auth_secret,omitempty" json:"auth_secret,omitempty"`
	AuthIdentity string              `yaml:"auth_identity,omitempty" json:"auth_identity,omitempty"`
	Headers      map[string]string   `yaml:"headers,omitempty" json:"headers,omitempty"`
	HTML         string              `yaml:"html,omitempty" json:"html,omitempty"`
	Text         string              `yaml:"text,omitempty" json:"text,omitempty"`
	RequireTLS   *bool               `yaml:"require_tls,omitempty" json:"require_tls,omitempty"`
	TLSConfig    commoncfg.TLSConfig `yaml:"tls_config,omitempty" json:"tls_config,omitempty"`
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (c *EmailConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*c = DefaultEmailConfig
	type plain EmailConfig
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}
	if c.To == "" {
		return fmt.Errorf("missing to address in email config")
	}
	// Header names are case-insensitive, check for collisions.
	normalizedHeaders := map[string]string{}
	for h, v := range c.Headers {
		normalized := strings.Title(h)
		if _, ok := normalizedHeaders[normalized]; ok {
			return fmt.Errorf("duplicate header %q in email config", normalized)
		}
		normalizedHeaders[normalized] = v
	}
	c.Headers = normalizedHeaders

	return nil
}

// PagerdutyConfig configures notifications via PagerDuty.
type PagerdutyConfig struct {
	NotifierConfig `yaml:",inline" json:",inline"`

	HTTPConfig *commoncfg.HTTPClientConfig `yaml:"http_config,omitempty" json:"http_config,omitempty"`

	ServiceKey  Secret            `yaml:"service_key,omitempty" json:"service_key,omitempty"`
	RoutingKey  Secret            `yaml:"routing_key,omitempty" json:"routing_key,omitempty"`
	URL         *URL              `yaml:"url,omitempty" json:"url,omitempty"`
	Client      string            `yaml:"client,omitempty" json:"client,omitempty"`
	ClientURL   string            `yaml:"client_url,omitempty" json:"client_url,omitempty"`
	Description string            `yaml:"description,omitempty" json:"description,omitempty"`
	Details     map[string]string `yaml:"details,omitempty" json:"details,omitempty"`
	Images      []PagerdutyImage  `yaml:"images,omitempty" json:"images,omitempty"`
	Links       []PagerdutyLink   `yaml:"links,omitempty" json:"links,omitempty"`
	Severity    string            `yaml:"severity,omitempty" json:"severity,omitempty"`
	Class       string            `yaml:"class,omitempty" json:"class,omitempty"`
	Component   string            `yaml:"component,omitempty" json:"component,omitempty"`
	Group       string            `yaml:"group,omitempty" json:"group,omitempty"`
}

// PagerdutyLink is a link
type PagerdutyLink struct {
	Href string `yaml:"href,omitempty" json:"href,omitempty"`
	Text string `yaml:"text,omitempty" json:"text,omitempty"`
}

// PagerdutyImage is an image
type PagerdutyImage struct {
	Src  string `yaml:"src,omitempty" json:"src,omitempty"`
	Alt  string `yaml:"alt,omitempty" json:"alt,omitempty"`
	Href string `yaml:"href,omitempty" json:"href,omitempty"`
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (c *PagerdutyConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*c = DefaultPagerdutyConfig
	type plain PagerdutyConfig
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}
	if c.RoutingKey == "" && c.ServiceKey == "" {
		return fmt.Errorf("missing service or routing key in PagerDuty config")
	}
	if c.Details == nil {
		c.Details = make(map[string]string)
	}
	for k, v := range DefaultPagerdutyDetails {
		if _, ok := c.Details[k]; !ok {
			c.Details[k] = v
		}
	}
	return nil
}

// SlackAction configures a single Slack action that is sent with each notification.
// See https://api.slack.com/docs/message-attachments#action_fields and https://api.slack.com/docs/message-buttons
// for more information.
type SlackAction struct {
	Type         string                  `yaml:"type,omitempty"  json:"type,omitempty"`
	Text         string                  `yaml:"text,omitempty"  json:"text,omitempty"`
	URL          string                  `yaml:"url,omitempty"   json:"url,omitempty"`
	Style        string                  `yaml:"style,omitempty" json:"style,omitempty"`
	Name         string                  `yaml:"name,omitempty"  json:"name,omitempty"`
	Value        string                  `yaml:"value,omitempty"  json:"value,omitempty"`
	ConfirmField *SlackConfirmationField `yaml:"confirm,omitempty"  json:"confirm,omitempty"`
}

// UnmarshalYAML implements the yaml.Unmarshaler interface for SlackAction.
func (c *SlackAction) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain SlackAction
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}
	if c.Type == "" {
		return fmt.Errorf("missing type in Slack action configuration")
	}
	if c.Text == "" {
		return fmt.Errorf("missing text in Slack action configuration")
	}
	if c.URL != "" {
		// Clear all message action fields.
		c.Name = ""
		c.Value = ""
		c.ConfirmField = nil
	} else if c.Name != "" {
		c.URL = ""
	} else {
		return fmt.Errorf("missing name or url in Slack action configuration")
	}
	return nil
}

// SlackConfirmationField protect users from destructive actions or particularly distinguished decisions
// by asking them to confirm their button click one more time.
// See https://api.slack.com/docs/interactive-message-field-guide#confirmation_fields for more information.
type SlackConfirmationField struct {
	Text        string `yaml:"text,omitempty"  json:"text,omitempty"`
	Title       string `yaml:"title,omitempty"  json:"title,omitempty"`
	OkText      string `yaml:"ok_text,omitempty"  json:"ok_text,omitempty"`
	DismissText string `yaml:"dismiss_text,omitempty"  json:"dismiss_text,omitempty"`
}

// UnmarshalYAML implements the yaml.Unmarshaler interface for SlackConfirmationField.
func (c *SlackConfirmationField) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain SlackConfirmationField
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}
	if c.Text == "" {
		return fmt.Errorf("missing text in Slack confirmation configuration")
	}
	return nil
}

// SlackField configures a single Slack field that is sent with each notification.
// Each field must contain a title, value, and optionally, a boolean value to indicate if the field
// is short enough to be displayed next to other fields designated as short.
// See https://api.slack.com/docs/message-attachments#fields for more information.
type SlackField struct {
	Title string `yaml:"title,omitempty" json:"title,omitempty"`
	Value string `yaml:"value,omitempty" json:"value,omitempty"`
	Short *bool  `yaml:"short,omitempty" json:"short,omitempty"`
}

// UnmarshalYAML implements the yaml.Unmarshaler interface for SlackField.
func (c *SlackField) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type plain SlackField
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}
	if c.Title == "" {
		return fmt.Errorf("missing title in Slack field configuration")
	}
	if c.Value == "" {
		return fmt.Errorf("missing value in Slack field configuration")
	}
	return nil
}

// SlackConfig configures notifications via Slack.
type SlackConfig struct {
	NotifierConfig `yaml:",inline" json:",inline"`

	HTTPConfig *commoncfg.HTTPClientConfig `yaml:"http_config,omitempty" json:"http_config,omitempty"`

	APIURL *URL `yaml:"api_url,omitempty" json:"api_url,omitempty"`

	// Slack channel override, (like #other-channel or @username).
	Channel  string `yaml:"channel,omitempty" json:"channel,omitempty"`
	Username string `yaml:"username,omitempty" json:"username,omitempty"`
	Color    string `yaml:"color,omitempty" json:"color,omitempty"`

	Title       string         `yaml:"title,omitempty" json:"title,omitempty"`
	TitleLink   string         `yaml:"title_link,omitempty" json:"title_link,omitempty"`
	Pretext     string         `yaml:"pretext,omitempty" json:"pretext,omitempty"`
	Text        string         `yaml:"text,omitempty" json:"text,omitempty"`
	Fields      []*SlackField  `yaml:"fields,omitempty" json:"fields,omitempty"`
	ShortFields bool           `yaml:"short_fields,omitempty" json:"short_fields,omitempty"`
	Footer      string         `yaml:"footer,omitempty" json:"footer,omitempty"`
	Fallback    string         `yaml:"fallback,omitempty" json:"fallback,omitempty"`
	CallbackID  string         `yaml:"callback_id,omitempty" json:"callback_id,omitempty"`
	IconEmoji   string         `yaml:"icon_emoji,omitempty" json:"icon_emoji,omitempty"`
	IconURL     string         `yaml:"icon_url,omitempty" json:"icon_url,omitempty"`
	ImageURL    string         `yaml:"image_url,omitempty" json:"image_url,omitempty"`
	ThumbURL    string         `yaml:"thumb_url,omitempty" json:"thumb_url,omitempty"`
	LinkNames   bool           `yaml:"link_names,omitempty" json:"link_names,omitempty"`
	MrkdwnIn    []string       `yaml:"mrkdwn_in,omitempty" json:"mrkdwn_in,omitempty"`
	Actions     []*SlackAction `yaml:"actions,omitempty" json:"actions,omitempty"`
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (c *SlackConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*c = DefaultSlackConfig
	type plain SlackConfig
	return unmarshal((*plain)(c))
}

// WebhookConfig configures notifications via a generic webhook.
type WebhookConfig struct {
	NotifierConfig `yaml:",inline" json:",inline"`

	HTTPConfig *commoncfg.HTTPClientConfig `yaml:"http_config,omitempty" json:"http_config,omitempty"`

	// URL to send POST request to.
	URL *URL `yaml:"url" json:"url"`
	// MaxAlerts is the maximum number of alerts to be sent per webhook message.
	// Alerts exceeding this threshold will be truncated. Setting this to 0
	// allows an unlimited number of alerts.
	MaxAlerts uint64 `yaml:"max_alerts" json:"max_alerts"`
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (c *WebhookConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*c = DefaultWebhookConfig
	type plain WebhookConfig
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}
	if c.URL == nil {
		return fmt.Errorf("missing URL in webhook config")
	}
	if c.URL.Scheme != "https" && c.URL.Scheme != "http" {
		return fmt.Errorf("scheme required for webhook url")
	}
	return nil
}

// WechatConfig configures notifications via Wechat.
type WechatConfig struct {
	NotifierConfig `yaml:",inline" json:",inline"`

	HTTPConfig *commoncfg.HTTPClientConfig `yaml:"http_config,omitempty" json:"http_config,omitempty"`

	APISecret Secret `yaml:"api_secret,omitempty" json:"api_secret,omitempty"`
	CorpID    string `yaml:"corp_id,omitempty" json:"corp_id,omitempty"`
	Message   string `yaml:"message,omitempty" json:"message,omitempty"`
	APIURL    *URL   `yaml:"api_url,omitempty" json:"api_url,omitempty"`
	ToUser    string `yaml:"to_user,omitempty" json:"to_user,omitempty"`
	ToParty   string `yaml:"to_party,omitempty" json:"to_party,omitempty"`
	ToTag     string `yaml:"to_tag,omitempty" json:"to_tag,omitempty"`
	AgentID   string `yaml:"agent_id,omitempty" json:"agent_id,omitempty"`
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (c *WechatConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*c = DefaultWechatConfig
	type plain WechatConfig
	return unmarshal((*plain)(c))
}

// OpsGenieConfig configures notifications via OpsGenie.
type OpsGenieConfig struct {
	NotifierConfig `yaml:",inline" json:",inline"`

	HTTPConfig *commoncfg.HTTPClientConfig `yaml:"http_config,omitempty" json:"http_config,omitempty"`

	APIKey      Secret                    `yaml:"api_key,omitempty" json:"api_key,omitempty"`
	APIURL      *URL                      `yaml:"api_url,omitempty" json:"api_url,omitempty"`
	Message     string                    `yaml:"message,omitempty" json:"message,omitempty"`
	Description string                    `yaml:"description,omitempty" json:"description,omitempty"`
	Source      string                    `yaml:"source,omitempty" json:"source,omitempty"`
	Details     map[string]string         `yaml:"details,omitempty" json:"details,omitempty"`
	Responders  []OpsGenieConfigResponder `yaml:"responders,omitempty" json:"responders,omitempty"`
	Tags        string                    `yaml:"tags,omitempty" json:"tags,omitempty"`
	Note        string                    `yaml:"note,omitempty" json:"note,omitempty"`
	Priority    string                    `yaml:"priority,omitempty" json:"priority,omitempty"`
}

const opsgenieValidTypesRe = `^(team|user|escalation|schedule)$`

var opsgenieTypeMatcher = regexp.MustCompile(opsgenieValidTypesRe)

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (c *OpsGenieConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*c = DefaultOpsGenieConfig
	type plain OpsGenieConfig
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}

	for _, r := range c.Responders {
		if r.ID == "" && r.Username == "" && r.Name == "" {
			return errors.Errorf("OpsGenieConfig responder %v has to have at least one of id, username or name specified", r)
		}

		r.Type = strings.ToLower(r.Type)
		if !opsgenieTypeMatcher.MatchString(r.Type) {
			return errors.Errorf("OpsGenieConfig responder %v type does not match valid options %s", r, opsgenieValidTypesRe)
		}
	}

	return nil
}

type OpsGenieConfigResponder struct {
	// One of those 3 should be filled.
	ID       string `yaml:"id,omitempty" json:"id,omitempty"`
	Name     string `yaml:"name,omitempty" json:"name,omitempty"`
	Username string `yaml:"username,omitempty" json:"username,omitempty"`

	// team, user, escalation, schedule etc.
	Type string `yaml:"type,omitempty" json:"type,omitempty"`
}

// VictorOpsConfig configures notifications via VictorOps.
type VictorOpsConfig struct {
	NotifierConfig `yaml:",inline" json:",inline"`

	HTTPConfig *commoncfg.HTTPClientConfig `yaml:"http_config,omitempty" json:"http_config,omitempty"`

	APIKey            Secret            `yaml:"api_key" json:"api_key"`
	APIURL            *URL              `yaml:"api_url" json:"api_url"`
	RoutingKey        string            `yaml:"routing_key" json:"routing_key"`
	MessageType       string            `yaml:"message_type" json:"message_type"`
	StateMessage      string            `yaml:"state_message" json:"state_message"`
	EntityDisplayName string            `yaml:"entity_display_name" json:"entity_display_name"`
	MonitoringTool    string            `yaml:"monitoring_tool" json:"monitoring_tool"`
	CustomFields      map[string]string `yaml:"custom_fields,omitempty" json:"custom_fields,omitempty"`
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (c *VictorOpsConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*c = DefaultVictorOpsConfig
	type plain VictorOpsConfig
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}
	if c.RoutingKey == "" {
		return fmt.Errorf("missing Routing key in VictorOps config")
	}

	reservedFields := []string{"routing_key", "message_type", "state_message", "entity_display_name", "monitoring_tool", "entity_id", "entity_state"}

	for _, v := range reservedFields {
		if _, ok := c.CustomFields[v]; ok {
			return fmt.Errorf("VictorOps config contains custom field %s which cannot be used as it conflicts with the fixed/static fields", v)
		}
	}

	return nil
}

type duration time.Duration

func (d *duration) UnmarshalText(text []byte) error {
	parsed, err := time.ParseDuration(string(text))
	if err == nil {
		*d = duration(parsed)
	}
	return err
}

func (d duration) MarshalText() ([]byte, error) {
	return []byte(time.Duration(d).String()), nil
}

type PushoverConfig struct {
	NotifierConfig `yaml:",inline" json:",inline"`

	HTTPConfig *commoncfg.HTTPClientConfig `yaml:"http_config,omitempty" json:"http_config,omitempty"`

	UserKey  Secret   `yaml:"user_key,omitempty" json:"user_key,omitempty"`
	Token    Secret   `yaml:"token,omitempty" json:"token,omitempty"`
	Title    string   `yaml:"title,omitempty" json:"title,omitempty"`
	Message  string   `yaml:"message,omitempty" json:"message,omitempty"`
	URL      string   `yaml:"url,omitempty" json:"url,omitempty"`
	URLTitle string   `yaml:"url_title,omitempty" json:"url_title,omitempty"`
	Sound    string   `yaml:"sound,omitempty" json:"sound,omitempty"`
	Priority string   `yaml:"priority,omitempty" json:"priority,omitempty"`
	Retry    duration `yaml:"retry,omitempty" json:"retry,omitempty"`
	Expire   duration `yaml:"expire,omitempty" json:"expire,omitempty"`
	HTML     bool     `yaml:"html,omitempty" json:"html,omitempty"`
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (c *PushoverConfig) UnmarshalYAML(unmarshal func(interface{}) error) error {
	*c = DefaultPushoverConfig
	type plain PushoverConfig
	if err := unmarshal((*plain)(c)); err != nil {
		return err
	}
	if c.UserKey == "" {
		return fmt.Errorf("missing user key in Pushover config")
	}
	if c.Token == "" {
		return fmt.Errorf("missing token in Pushover config")
	}
	return nil
}
