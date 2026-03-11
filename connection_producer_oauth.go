// Copyright 2026 Snowflake Inc.
// SPDX-License-Identifier: MPL-2.0

package snowflake

import (
	"database/sql"
	"fmt"
	"net/url"

	"github.com/snowflakedb/gosnowflake"
)

// validateOAuthConfig checks that OAuth client credentials configuration is
// valid and mutually exclusive with other authentication methods.
func (c *snowflakeConnectionProducer) validateOAuthConfig() error {
	if len(c.Password) > 0 || len(c.PrivateKey) > 0 || len(c.WorkloadIdentityProvider) > 0 {
		return ErrOAuthMutuallyExclusive
	}

	if c.Username == "" {
		return ErrOAuthUsernameRequired
	}

	if c.OAuthClientID == "" || c.OAuthClientSecret == "" || c.OAuthTokenEndpoint == "" {
		return ErrOAuthMissingFields
	}

	return nil
}

// openSnowflakeOAuth opens a Snowflake connection using OAuth 2.0 client
// credentials flow. gosnowflake handles the token exchange internally.
func openSnowflakeOAuth(connectionURL, username, clientID, clientSecret, tokenEndpoint, scope string) (*sql.DB, error) {
	cfg, err := getSnowflakeOAuthConfig(connectionURL, username, clientID, clientSecret, tokenEndpoint, scope)
	if err != nil {
		return nil, fmt.Errorf("error constructing Snowflake OAuth config: %w", err)
	}
	connector := gosnowflake.NewConnector(gosnowflake.SnowflakeDriver{}, *cfg)
	return sql.OpenDB(connector), nil
}

// getSnowflakeOAuthConfig builds a gosnowflake.Config for OAuth 2.0 client
// credentials authentication. gosnowflake uses OauthClientID, OauthClientSecret,
// and OauthTokenRequestURL to exchange credentials for a bearer token.
func getSnowflakeOAuthConfig(connectionURL, username, clientID, clientSecret, tokenEndpoint, scope string) (*gosnowflake.Config, error) {
	u, err := url.Parse(connectionURL)
	if err != nil {
		return nil, fmt.Errorf("error parsing Snowflake connection URL %q: %w", connectionURL, err)
	}

	q := u.Query()
	q.Set("authenticator", gosnowflake.AuthTypeOAuthClientCredentials.String())
	u.RawQuery = q.Encode()

	// construct dsn: "user:@<account>.snowflakecomputing.com/<db>?..."
	dsn := fmt.Sprintf("%s:%s@%s", username, "", u.String())
	cfg, err := gosnowflake.ParseDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("error parsing Snowflake DSN: %w", err)
	}

	cfg.OauthClientID = clientID
	cfg.OauthClientSecret = clientSecret
	cfg.OauthTokenRequestURL = tokenEndpoint

	if scope != "" {
		cfg.OauthScope = scope
	}

	return cfg, nil
}
