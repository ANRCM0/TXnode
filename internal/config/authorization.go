package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// AuthorizationConfig enables finite, signed native Node authorization. It is
// deliberately opt-in so existing bearer-only and Xboard installations retain
// their current behavior and do not accidentally claim an offline guarantee.
type AuthorizationConfig struct {
	Enabled         bool                        `yaml:"enabled"`
	StateDir        string                      `yaml:"state_dir,omitempty"`
	PublicKey       string                      `yaml:"public_key,omitempty"`
	KeyID           string                      `yaml:"key_id,omitempty"`
	KeyEpoch        string                      `yaml:"key_epoch,omitempty"`
	CoreInstanceID  string                      `yaml:"core_instance_id,omitempty"`
	PolicyVersion   string                      `yaml:"policy_version,omitempty"`
	RefreshInterval int                         `yaml:"refresh_interval,omitempty"`
	MaxClockSkew    int                         `yaml:"max_clock_skew,omitempty"`
	Provider        AuthorizationProviderConfig `yaml:"provider,omitempty"`
}

type AuthorizationProviderConfig struct {
	Endpoint              string `yaml:"endpoint,omitempty"`
	ProviderID            string `yaml:"provider_id,omitempty"`
	ProviderInstanceEpoch string `yaml:"provider_instance_epoch,omitempty"`
	CAFile                string `yaml:"ca_file,omitempty"`
	ClientCert            string `yaml:"client_cert,omitempty"`
	ClientKey             string `yaml:"client_key,omitempty"`
}

const (
	DefaultAuthorizationRefreshSeconds       = 30
	DefaultAuthorizationMaxOfflineSeconds    = 120
	DefaultAuthorizationClockSkewSeconds     = 5
	NativeAuthorizationPolicyVersion         = "native-node-authorization/v1"
	NativeProviderAuthorizationPolicyVersion = "native-provider-authorization/v1"
	NativeProviderUsagePolicyVersion         = "native-provider-authorization/v2"
)

func ProviderAuthorizationPolicy(policy string) bool {
	return policy == NativeProviderAuthorizationPolicyVersion || policy == NativeProviderUsagePolicyVersion
}

// ValidateProvider keeps material delivery opt-in and binds its address and
// TLS identity to local operator configuration, never a Core response.
func (c AuthorizationConfig) ValidateProvider() error {
	hasProvider := c.Provider != (AuthorizationProviderConfig{})
	if !ProviderAuthorizationPolicy(c.PolicyVersion) {
		if hasProvider {
			return errors.New("NODE_AUTHORIZATION_PROVIDER_POLICY_REQUIRED")
		}
		return nil
	}
	p := c.Provider
	u, err := url.Parse(p.Endpoint)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" || u.Opaque != "" {
		return errors.New("NODE_AUTHORIZATION_PROVIDER_ENDPOINT_INVALID")
	}
	_, epochErr := strconv.ParseInt(p.ProviderInstanceEpoch, 10, 64)
	if !regexp.MustCompile(`\A[a-z][a-z0-9_-]{0,63}\z`).MatchString(p.ProviderID) || !regexp.MustCompile(`\A[1-9][0-9]{0,18}\z`).MatchString(p.ProviderInstanceEpoch) || epochErr != nil {
		return errors.New("NODE_AUTHORIZATION_PROVIDER_IDENTITY_INVALID")
	}
	for _, path := range []string{p.CAFile, p.ClientCert, p.ClientKey} {
		if path == "" || !filepath.IsAbs(path) {
			return errors.New("NODE_AUTHORIZATION_PROVIDER_TLS_REQUIRED")
		}
	}
	return nil
}

func (c *AuthorizationConfig) applyDefaults(configDir string) {
	if c.RefreshInterval == 0 {
		c.RefreshInterval = DefaultAuthorizationRefreshSeconds
	}
	if c.MaxClockSkew == 0 {
		c.MaxClockSkew = DefaultAuthorizationClockSkewSeconds
	}
	if c.PolicyVersion == "" {
		c.PolicyVersion = NativeAuthorizationPolicyVersion
	}
	if c.StateDir == "" && configDir != "" {
		c.StateDir = filepath.Join(configDir, "authorization")
	}
}

func (c *Config) ValidateAuthorization() error {
	if c == nil {
		return nil
	}
	if !c.Authorization.Enabled {
		if c.Authorization.Provider != (AuthorizationProviderConfig{}) {
			return errors.New("NODE_AUTHORIZATION_PROVIDER_POLICY_REQUIRED")
		}
		return nil
	}
	a := &c.Authorization
	a.applyDefaults(c.Kernel.ConfigDir)
	if c.Panel.Provider != "txboard" || c.IsStandalone() {
		return errors.New("NODE_AUTHORIZATION_REQUIRES_TXBOARD_NONSTANDALONE")
	}
	if c.UsageV2.Enabled && a.PolicyVersion != NativeProviderUsagePolicyVersion {
		return errors.New("NODE_AUTHORIZATION_USAGE_V2_INCOMPATIBLE")
	}
	if a.PolicyVersion == NativeProviderUsagePolicyVersion && (!c.UsageV2.Enabled || c.UsageV2.IsolatedCopy) {
		return errors.New("NODE_AUTHORIZATION_NATIVE_USAGE_REQUIRED")
	}
	if strings.TrimSpace(c.Kernel.ConfigDir) == "" || !filepath.IsAbs(c.Kernel.ConfigDir) || strings.TrimSpace(a.StateDir) == "" || !filepath.IsAbs(a.StateDir) {
		return errors.New("NODE_AUTHORIZATION_STATE_DIR_REQUIRED")
	}
	if c.Panel.URL == "" {
		return errors.New("NODE_AUTHORIZATION_PANEL_REQUIRED")
	}
	if u, err := url.Parse(c.Panel.URL); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
		return errors.New("NODE_AUTHORIZATION_REQUIRES_HTTPS")
	}
	if !regexp.MustCompile(`\A[A-Za-z0-9:_-]{8,80}\z`).MatchString(a.CoreInstanceID) {
		return errors.New("NODE_AUTHORIZATION_CORE_INSTANCE_INVALID")
	}
	if !regexp.MustCompile(`\A[A-Za-z0-9_-]{1,64}\z`).MatchString(a.KeyID) || !regexp.MustCompile(`\A[1-9][0-9]{0,18}\z`).MatchString(a.KeyEpoch) {
		return errors.New("NODE_AUTHORIZATION_TRUST_INVALID")
	}
	key, err := base64.RawURLEncoding.DecodeString(a.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(key) != a.PublicKey {
		return errors.New("NODE_AUTHORIZATION_PUBLIC_KEY_INVALID")
	}
	if a.PolicyVersion != NativeAuthorizationPolicyVersion && !ProviderAuthorizationPolicy(a.PolicyVersion) || a.RefreshInterval < 1 || a.RefreshInterval > 30 || a.MaxClockSkew < 0 || a.MaxClockSkew > 30 {
		return errors.New("NODE_AUTHORIZATION_POLICY_INVALID")
	}
	if err := a.ValidateProvider(); err != nil {
		return err
	}
	if info, err := os.Stat(a.StateDir); err == nil && !info.IsDir() {
		return fmt.Errorf("NODE_AUTHORIZATION_STATE_DIR_NOT_DIRECTORY")
	}
	return nil
}
