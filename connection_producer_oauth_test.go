// Copyright 2026 Snowflake Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


package snowflake

import (
	"context"
	"strings"
	"testing"

	"github.com/snowflakedb/gosnowflake"
	"github.com/stretchr/testify/require"
)

func TestGetSnowflakeOAuthConfig(t *testing.T) {
	tt := map[string]struct {
		connectionURL  string
		username       string
		clientID       string
		clientSecret   string
		tokenEndpoint  string
		scope          string
		expectedConfig *gosnowflake.Config
		expectedError  string
	}{
		"basic client credentials": {
			connectionURL: "testaccount.snowflakecomputing.com/testdb",
			username:      "testvaultuser",
			clientID:      "my-client-id",
			clientSecret:  "my-client-secret",
			tokenEndpoint: "https://myidp.example.com/oauth/token",
			expectedConfig: &gosnowflake.Config{
				Account:              "testaccount",
				User:                 "testvaultuser",
				Database:             "testdb",
				Authenticator:        gosnowflake.AuthTypeOAuthClientCredentials,
				OauthClientID:        "my-client-id",
				OauthClientSecret:    "my-client-secret",
				OauthTokenRequestURL: "https://myidp.example.com/oauth/token",
			},
		},
		"with scope": {
			connectionURL: "testaccount.snowflakecomputing.com/testdb",
			username:      "testvaultuser",
			clientID:      "my-client-id",
			clientSecret:  "my-client-secret",
			tokenEndpoint: "https://myidp.example.com/oauth/token",
			scope:         "session:role:SYSADMIN",
			expectedConfig: &gosnowflake.Config{
				Account:              "testaccount",
				User:                 "testvaultuser",
				Database:             "testdb",
				Authenticator:        gosnowflake.AuthTypeOAuthClientCredentials,
				OauthClientID:        "my-client-id",
				OauthClientSecret:    "my-client-secret",
				OauthTokenRequestURL: "https://myidp.example.com/oauth/token",
				OauthScope:           "session:role:SYSADMIN",
			},
		},
		"with query params in connection URL": {
			connectionURL: "testaccount.snowflakecomputing.com/testdb?disableOCSPChecks=true",
			username:      "testvaultuser",
			clientID:      "my-client-id",
			clientSecret:  "my-client-secret",
			tokenEndpoint: "https://myidp.example.com/oauth/token",
			expectedConfig: &gosnowflake.Config{
				Account:              "testaccount",
				User:                 "testvaultuser",
				Database:             "testdb",
				Authenticator:        gosnowflake.AuthTypeOAuthClientCredentials,
				OauthClientID:        "my-client-id",
				OauthClientSecret:    "my-client-secret",
				OauthTokenRequestURL: "https://myidp.example.com/oauth/token",
				DisableOCSPChecks:    true,
			},
		},
		"without database in connection URL": {
			connectionURL: "testaccount.snowflakecomputing.com",
			username:      "testvaultuser",
			clientID:      "my-client-id",
			clientSecret:  "my-client-secret",
			tokenEndpoint: "https://myidp.example.com/oauth/token",
			expectedConfig: &gosnowflake.Config{
				Account:              "testaccount",
				User:                 "testvaultuser",
				Authenticator:        gosnowflake.AuthTypeOAuthClientCredentials,
				OauthClientID:        "my-client-id",
				OauthClientSecret:    "my-client-secret",
				OauthTokenRequestURL: "https://myidp.example.com/oauth/token",
			},
		},
		"invalid connection URL": {
			connectionURL: "://bad-url",
			username:      "testvaultuser",
			clientID:      "my-client-id",
			clientSecret:  "my-client-secret",
			tokenEndpoint: "https://myidp.example.com/oauth/token",
			expectedError: "error parsing Snowflake connection URL",
		},
	}

	for name, tc := range tt {
		t.Run(name, func(t *testing.T) {
			cfg, err := getSnowflakeOAuthConfig(tc.connectionURL, tc.username, tc.clientID, tc.clientSecret, tc.tokenEndpoint, tc.scope)
			if tc.expectedError != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.expectedError)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, cfg)
			require.Equal(t, tc.expectedConfig.Account, cfg.Account)
			require.Equal(t, tc.expectedConfig.User, cfg.User)
			require.Equal(t, tc.expectedConfig.Database, cfg.Database)
			require.Equal(t, tc.expectedConfig.Authenticator, cfg.Authenticator)
			require.Equal(t, tc.expectedConfig.OauthClientID, cfg.OauthClientID)
			require.Equal(t, tc.expectedConfig.OauthClientSecret, cfg.OauthClientSecret)
			require.Equal(t, tc.expectedConfig.OauthTokenRequestURL, cfg.OauthTokenRequestURL)
			require.Equal(t, tc.expectedConfig.OauthScope, cfg.OauthScope)
			require.Equal(t, tc.expectedConfig.DisableOCSPChecks, cfg.DisableOCSPChecks)
		})
	}
}

func TestOpenSnowflakeOAuth(t *testing.T) {
	// openSnowflakeOAuth builds the connector but does not dial — no live Snowflake needed.
	db, err := openSnowflakeOAuth(
		"testaccount.snowflakecomputing.com/testdb",
		"testvaultuser",
		"my-client-id",
		"my-client-secret",
		"https://myidp.example.com/oauth/token",
		"",
	)
	require.NoError(t, err)
	require.NotNil(t, db)
	require.NotNil(t, db.Stats())
}

func TestValidateOAuthConfig(t *testing.T) {
	tt := map[string]struct {
		config        map[string]interface{}
		expectedError string
	}{
		"valid config": {
			config: map[string]interface{}{
				"connection_url":      "testaccount.snowflakecomputing.com/testdb",
				"username":            "vaultuser",
				"oauth_client_id":     "my-client-id",
				"oauth_client_secret": "my-client-secret",
				"oauth_token_endpoint": "https://myidp.example.com/oauth/token",
			},
		},
		"valid config with scope": {
			config: map[string]interface{}{
				"connection_url":       "testaccount.snowflakecomputing.com/testdb",
				"username":             "vaultuser",
				"oauth_client_id":      "my-client-id",
				"oauth_client_secret":  "my-client-secret",
				"oauth_token_endpoint": "https://myidp.example.com/oauth/token",
				"oauth_scope":          "session:role:SYSADMIN",
			},
		},
		"oauth and password are mutually exclusive": {
			config: map[string]interface{}{
				"connection_url":       "testaccount.snowflakecomputing.com/testdb",
				"username":             "vaultuser",
				"password":             "secret",
				"oauth_client_id":      "my-client-id",
				"oauth_client_secret":  "my-client-secret",
				"oauth_token_endpoint": "https://myidp.example.com/oauth/token",
			},
			expectedError: ErrOAuthMutuallyExclusive.Error(),
		},
		"oauth and private_key are mutually exclusive": {
			config: map[string]interface{}{
				"connection_url":       "testaccount.snowflakecomputing.com/testdb",
				"username":             "vaultuser",
				"private_key":          []byte(testPrivateKey),
				"oauth_client_id":      "my-client-id",
				"oauth_client_secret":  "my-client-secret",
				"oauth_token_endpoint": "https://myidp.example.com/oauth/token",
			},
			expectedError: ErrOAuthMutuallyExclusive.Error(),
		},
		"oauth and WIF are mutually exclusive": {
			config: map[string]interface{}{
				"connection_url":             "testaccount.snowflakecomputing.com/testdb",
				"username":                   "vaultuser",
				"workload_identity_provider": "AWS",
				"oauth_client_id":            "my-client-id",
				"oauth_client_secret":        "my-client-secret",
				"oauth_token_endpoint":       "https://myidp.example.com/oauth/token",
			},
			// WIF validation runs first and rejects oauth_client_id being set alongside it
			expectedError: ErrWIFMutuallyExclusive.Error(),
		},
		"oauth requires username": {
			config: map[string]interface{}{
				"connection_url":       "testaccount.snowflakecomputing.com/testdb",
				"oauth_client_id":      "my-client-id",
				"oauth_client_secret":  "my-client-secret",
				"oauth_token_endpoint": "https://myidp.example.com/oauth/token",
			},
			expectedError: ErrOAuthUsernameRequired.Error(),
		},
		"missing client_secret": {
			config: map[string]interface{}{
				"connection_url":       "testaccount.snowflakecomputing.com/testdb",
				"username":             "vaultuser",
				"oauth_client_id":      "my-client-id",
				"oauth_token_endpoint": "https://myidp.example.com/oauth/token",
			},
			expectedError: ErrOAuthMissingFields.Error(),
		},
		"missing token_endpoint": {
			config: map[string]interface{}{
				"connection_url":      "testaccount.snowflakecomputing.com/testdb",
				"username":            "vaultuser",
				"oauth_client_id":     "my-client-id",
				"oauth_client_secret": "my-client-secret",
			},
			expectedError: ErrOAuthMissingFields.Error(),
		},
		"missing client_id": {
			config: map[string]interface{}{
				"connection_url":       "testaccount.snowflakecomputing.com/testdb",
				"username":             "vaultuser",
				"oauth_client_secret":  "my-client-secret",
				"oauth_token_endpoint": "https://myidp.example.com/oauth/token",
			},
		},
	}

	for name, tc := range tt {
		t.Run(name, func(t *testing.T) {
			producer := &snowflakeConnectionProducer{}
			err := producer.Initialize(context.Background(), tc.config, false)
			if tc.expectedError != "" {
				require.Error(t, err)
				require.True(t, strings.Contains(err.Error(), tc.expectedError),
					"expected error %q, got %q", tc.expectedError, err.Error())
				return
			}
			require.NoError(t, err)
		})
	}
}