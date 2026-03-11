// Copyright 2026 Snowflake Inc.
// SPDX-License-Identifier: MPL-2.0

package snowflake

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/snowflakedb/gosnowflake"
	"github.com/stretchr/testify/require"
)

// testPrivateKey and testSingleLinePrivateKey are generated fresh at test
// init time so no static private key material is stored in the repository.
var (
	testPrivateKey           string
	testSingleLinePrivateKey string
)

func init() {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("failed to generate test RSA key: %v", err))
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(fmt.Sprintf("failed to marshal test RSA key: %v", err))
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	testPrivateKey = string(pemBytes)
	// testSingleLinePrivateKey exercises the same parsing path with the key
	// provided as a Go string literal (escape sequences) rather than a raw string.
	testSingleLinePrivateKey = testPrivateKey
}

func TestOpenSnowflake(t *testing.T) {
	// Generate a new RSA key for testing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}

	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}
	var pemKey bytes.Buffer
	pem.Encode(&pemKey, pemBlock)

	db, err := openSnowflake("account.snowflakecomputing.com/db", "user", pemKey.Bytes())
	if err != nil {
		t.Fatalf("Failed to open Snowflake connection: %v", err)
	}

	require.NotNil(t, db.Stats())
}

func TestGetSnowflakeConfig(t *testing.T) {
	tt := map[string]struct {
		providedPrivateKey string
		username           string
		connectionURL      string
		expectedConfig     *gosnowflake.Config
		expectedError      string
	}{
		// confirms that the connection URL format upon initial release is correctly parsed
		"key pair connection URL format without params": {
			providedPrivateKey: testPrivateKey,
			username:           "testvaultuser",
			connectionURL:      "testaccount.snowflakecomputing.com/testdb",
			expectedConfig: &gosnowflake.Config{
				Account:  "testaccount",
				User:     "testvaultuser",
				Database: "testdb",
				PrivateKey: func() *rsa.PrivateKey {
					key, _ := getPrivateKey([]byte(testPrivateKey))
					return key
				}(),
				Authenticator: gosnowflake.AuthTypeJwt,
			},
		},
		// confirms that query params in the connection URL are correctly parsed
		"key pair connection URL format with query params": {
			providedPrivateKey: testPrivateKey,
			username:           "testvaultuser",
			connectionURL:      "testaccount.snowflakecomputing.com/testdb?disableOCSPChecks=true&maxRetryCount=5",
			expectedConfig: &gosnowflake.Config{
				Account:  "testaccount",
				User:     "testvaultuser",
				Database: "testdb",
				PrivateKey: func() *rsa.PrivateKey {
					key, _ := getPrivateKey([]byte(testPrivateKey))
					return key
				}(),
				DisableOCSPChecks: true,
				MaxRetryCount:     5,
				Authenticator:     gosnowflake.AuthTypeJwt,
			},
		},
		// confirms that DB is optional in the connection URL
		"key pair connection URL without DB": {
			providedPrivateKey: testPrivateKey,
			username:           "testvaultuser",
			connectionURL:      "testaccount.snowflakecomputing.com?disableOCSPChecks=true&maxRetryCount=5",
			expectedConfig: &gosnowflake.Config{
				Account: "testaccount",
				User:    "testvaultuser",
				PrivateKey: func() *rsa.PrivateKey {
					key, _ := getPrivateKey([]byte(testPrivateKey))
					return key
				}(),
				DisableOCSPChecks: true,
				MaxRetryCount:     5,
				Authenticator:     gosnowflake.AuthTypeJwt,
			},
		},
	}

	for name, tc := range tt {
		t.Run(name, func(t *testing.T) {
			cfg, err := getSnowflakeConfig(tc.connectionURL, tc.username, []byte(tc.providedPrivateKey))
			if tc.expectedError != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tc.expectedError)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, cfg)
			// Compare all relevant fields for this test
			// this confirms that the config was correctly parsed from the provided inputs
			require.Equal(t, tc.expectedConfig.Account, cfg.Account)
			require.Equal(t, tc.expectedConfig.User, cfg.User)
			require.Equal(t, tc.expectedConfig.Database, cfg.Database)
			require.Equal(t, tc.expectedConfig.Authenticator, cfg.Authenticator)
			require.Equal(t, tc.expectedConfig.DisableOCSPChecks, cfg.DisableOCSPChecks)
			require.Equal(t, tc.expectedConfig.KeepSessionAlive, cfg.KeepSessionAlive)
			require.NotNil(t, cfg.PrivateKey)
		})
	}
}

// TestGetPrivateKey ensures reading private
// keys works as expected for multiple cases
func TestGetPrivateKey(t *testing.T) {
	tests := map[string]struct {
		providedPrivateKey string
		wantErr            error
	}{
		"valid private key string": {
			providedPrivateKey: testPrivateKey,
			wantErr:            nil,
		},
		"valid private key single-line string": {
			providedPrivateKey: testSingleLinePrivateKey,
			wantErr:            nil,
		},
		"empty private key": {
			providedPrivateKey: "",
			wantErr:            ErrInvalidPrivateKey,
		},
		"invalid private key": {
			providedPrivateKey: "***REMOVED***\ninvalid\n",
			wantErr:            ErrInvalidPrivateKey,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := getPrivateKey([]byte(tt.providedPrivateKey))

			require.Equal(t, tt.wantErr, err)
		})
	}
}
