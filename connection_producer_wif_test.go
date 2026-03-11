// Copyright 2026 Snowflake Inc.
// SPDX-License-Identifier: MPL-2.0

package snowflake

import (
	"context"
	"strings"
	"testing"

	"github.com/snowflakedb/gosnowflake"
	"github.com/stretchr/testify/require"
)

func TestGetSnowflakeWIFConfig(t *testing.T) {
	tt := map[string]struct {
		connectionURL  string
		username       string
		provider       string
		token          string
		entraResource  string
		expectedConfig *gosnowflake.Config
		expectedError  string
	}{
		"AWS provider": {
			connectionURL: "testaccount.snowflakecomputing.com/testdb",
			username:      "testvaultuser",
			provider:      "AWS",
			expectedConfig: &gosnowflake.Config{
				Account:                  "testaccount",
				User:                     "testvaultuser",
				Database:                 "testdb",
				Authenticator:            gosnowflake.AuthTypeWorkloadIdentityFederation,
				WorkloadIdentityProvider: "AWS",
			},
		},
		"GCP provider": {
			connectionURL: "testaccount.snowflakecomputing.com/testdb",
			username:      "testvaultuser",
			provider:      "GCP",
			expectedConfig: &gosnowflake.Config{
				Account:                  "testaccount",
				User:                     "testvaultuser",
				Database:                 "testdb",
				Authenticator:            gosnowflake.AuthTypeWorkloadIdentityFederation,
				WorkloadIdentityProvider: "GCP",
			},
		},
		"AZURE provider": {
			connectionURL: "testaccount.snowflakecomputing.com/testdb",
			username:      "testvaultuser",
			provider:      "AZURE",
			expectedConfig: &gosnowflake.Config{
				Account:                  "testaccount",
				User:                     "testvaultuser",
				Database:                 "testdb",
				Authenticator:            gosnowflake.AuthTypeWorkloadIdentityFederation,
				WorkloadIdentityProvider: "AZURE",
			},
		},
		"AZURE provider with entra resource": {
			connectionURL: "testaccount.snowflakecomputing.com/testdb",
			username:      "testvaultuser",
			provider:      "AZURE",
			entraResource: "api://my-custom-resource",
			expectedConfig: &gosnowflake.Config{
				Account:                       "testaccount",
				User:                          "testvaultuser",
				Database:                      "testdb",
				Authenticator:                 gosnowflake.AuthTypeWorkloadIdentityFederation,
				WorkloadIdentityProvider:      "AZURE",
				WorkloadIdentityEntraResource: "api://my-custom-resource",
			},
		},
		"OIDC provider with token": {
			connectionURL: "testaccount.snowflakecomputing.com/testdb",
			username:      "testvaultuser",
			provider:      "OIDC",
			token:         "eyJhbGciOiJSUzI1NiJ9.test.token",
			expectedConfig: &gosnowflake.Config{
				Account:                  "testaccount",
				User:                     "testvaultuser",
				Database:                 "testdb",
				Authenticator:            gosnowflake.AuthTypeWorkloadIdentityFederation,
				WorkloadIdentityProvider: "OIDC",
				Token:                    "eyJhbGciOiJSUzI1NiJ9.test.token",
			},
		},
		"lowercase provider is normalized to uppercase": {
			connectionURL: "testaccount.snowflakecomputing.com/testdb",
			username:      "testvaultuser",
			provider:      "aws",
			expectedConfig: &gosnowflake.Config{
				Account:                  "testaccount",
				User:                     "testvaultuser",
				Database:                 "testdb",
				Authenticator:            gosnowflake.AuthTypeWorkloadIdentityFederation,
				WorkloadIdentityProvider: "AWS",
			},
		},
		"connection URL with query params": {
			connectionURL: "testaccount.snowflakecomputing.com/testdb?disableOCSPChecks=true",
			username:      "testvaultuser",
			provider:      "GCP",
			expectedConfig: &gosnowflake.Config{
				Account:                  "testaccount",
				User:                     "testvaultuser",
				Database:                 "testdb",
				Authenticator:            gosnowflake.AuthTypeWorkloadIdentityFederation,
				WorkloadIdentityProvider: "GCP",
				DisableOCSPChecks:        true,
			},
		},
		"connection URL without database": {
			connectionURL: "testaccount.snowflakecomputing.com",
			username:      "testvaultuser",
			provider:      "AWS",
			expectedConfig: &gosnowflake.Config{
				Account:                  "testaccount",
				User:                     "testvaultuser",
				Authenticator:            gosnowflake.AuthTypeWorkloadIdentityFederation,
				WorkloadIdentityProvider: "AWS",
			},
		},
		"invalid connection URL": {
			connectionURL: "://bad-url",
			username:      "testvaultuser",
			provider:      "AWS",
			expectedError: "error parsing Snowflake connection URL",
		},
	}

	for name, tc := range tt {
		t.Run(name, func(t *testing.T) {
			cfg, err := getSnowflakeWIFConfig(tc.connectionURL, tc.username, tc.provider, tc.token, tc.entraResource)
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
			require.Equal(t, tc.expectedConfig.WorkloadIdentityProvider, cfg.WorkloadIdentityProvider)
			require.Equal(t, tc.expectedConfig.Token, cfg.Token)
			require.Equal(t, tc.expectedConfig.WorkloadIdentityEntraResource, cfg.WorkloadIdentityEntraResource)
			require.Equal(t, tc.expectedConfig.DisableOCSPChecks, cfg.DisableOCSPChecks)
		})
	}
}

func TestOpenSnowflakeWIF(t *testing.T) {
	// openSnowflakeWIF builds the connector but does not dial — no live Snowflake needed.
	db, err := openSnowflakeWIF(
		"testaccount.snowflakecomputing.com/testdb",
		"testvaultuser",
		"AWS",
		"",
		"",
	)
	require.NoError(t, err)
	require.NotNil(t, db)
	require.NotNil(t, db.Stats())
}

func TestValidateWIFConfig(t *testing.T) {
	tt := map[string]struct {
		config        map[string]interface{}
		expectedError string
	}{
		"valid AWS provider": {
			config: map[string]interface{}{
				"connection_url":             "testaccount.snowflakecomputing.com/testdb",
				"username":                   "vaultuser",
				"workload_identity_provider": "AWS",
			},
		},
		"valid GCP provider": {
			config: map[string]interface{}{
				"connection_url":             "testaccount.snowflakecomputing.com/testdb",
				"username":                   "vaultuser",
				"workload_identity_provider": "GCP",
			},
		},
		"valid AZURE provider": {
			config: map[string]interface{}{
				"connection_url":             "testaccount.snowflakecomputing.com/testdb",
				"username":                   "vaultuser",
				"workload_identity_provider": "AZURE",
			},
		},
		"valid AZURE provider with entra resource": {
			config: map[string]interface{}{
				"connection_url":                   "testaccount.snowflakecomputing.com/testdb",
				"username":                         "vaultuser",
				"workload_identity_provider":       "AZURE",
				"workload_identity_entra_resource": "api://my-resource",
			},
		},
		"valid OIDC provider with token": {
			config: map[string]interface{}{
				"connection_url":             "testaccount.snowflakecomputing.com/testdb",
				"username":                   "vaultuser",
				"workload_identity_provider": "OIDC",
				"workload_identity_token":    "eyJhbGciOiJSUzI1NiJ9.test.token",
			},
		},
		"lowercase provider is accepted": {
			config: map[string]interface{}{
				"connection_url":             "testaccount.snowflakecomputing.com/testdb",
				"username":                   "vaultuser",
				"workload_identity_provider": "aws",
			},
		},
		"WIF and password are mutually exclusive": {
			config: map[string]interface{}{
				"connection_url":             "testaccount.snowflakecomputing.com/testdb",
				"username":                   "vaultuser",
				"password":                   "secret",
				"workload_identity_provider": "AWS",
			},
			expectedError: ErrWIFMutuallyExclusive.Error(),
		},
		"WIF and private_key are mutually exclusive": {
			config: map[string]interface{}{
				"connection_url":             "testaccount.snowflakecomputing.com/testdb",
				"username":                   "vaultuser",
				"private_key":                []byte(testPrivateKey),
				"workload_identity_provider": "AWS",
			},
			expectedError: ErrWIFMutuallyExclusive.Error(),
		},
		"WIF requires username": {
			config: map[string]interface{}{
				"connection_url":             "testaccount.snowflakecomputing.com/testdb",
				"workload_identity_provider": "AWS",
			},
			expectedError: ErrWIFUsernameRequired.Error(),
		},
		"OIDC provider requires token": {
			config: map[string]interface{}{
				"connection_url":             "testaccount.snowflakecomputing.com/testdb",
				"username":                   "vaultuser",
				"workload_identity_provider": "OIDC",
			},
			expectedError: ErrWIFTokenRequired.Error(),
		},
		"invalid provider is rejected": {
			config: map[string]interface{}{
				"connection_url":             "testaccount.snowflakecomputing.com/testdb",
				"username":                   "vaultuser",
				"workload_identity_provider": "GITHUB",
			},
			expectedError: ErrWIFInvalidProvider.Error(),
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
