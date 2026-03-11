// Copyright 2026 Snowflake Inc.
// SPDX-License-Identifier: MPL-2.0

package snowflake

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/sdk/database/dbplugin/v5"
	dbtesting "github.com/hashicorp/vault/sdk/database/dbplugin/v5/testing"
	"github.com/snowflakedb/gosnowflake"
	"github.com/stretchr/testify/require"
)

const (
	envVarSnowflakeAccount    = "SNOWFLAKE_ACCOUNT"
	envVarSnowflakeUser       = "SNOWFLAKE_USER"
	envVarSnowflakePassword   = "SNOWFLAKE_PASSWORD"
	envVarSnowflakeDatabase   = "SNOWFLAKE_DATABASE"
	envVarSnowflakeSchema     = "SNOWFLAKE_SCHEMA"
	envVarSnowflakePrivateKey = "SNOWFLAKE_PRIVATE_KEY"

	envVarRunAccTests = "VAULT_ACC"
)

var runAcceptanceTests = os.Getenv(envVarRunAccTests) != ""

func connUrl(t *testing.T) string {
	connURL, err := dsnString()
	if err != nil {
		t.Fatalf("failed to retrieve connection DSN: %s", err)
	}

	return connURL
}

func skipIfNoPassword(t *testing.T) {
	t.Helper()
	if os.Getenv(envVarSnowflakePassword) == "" {
		t.Skip("skipping because SNOWFLAKE_PASSWORD is not set")
	}
}

func skipIfNoKeyPair(t *testing.T) {
	t.Helper()
	if os.Getenv(envVarSnowflakePrivateKey) == "" {
		t.Skip("skipping because SNOWFLAKE_PRIVATE_KEY is not set")
	}
}

// connUrlKeyPair returns the connection URL, admin username, and decoded private key bytes
// for key-pair authenticated admin operations. It skips the test if required env vars are missing.
func connUrlKeyPair(t *testing.T) (connURL, username string, privateKeyBytes []byte) {
	t.Helper()
	connURL, rawBase64PrivateKey, username, err := getKeyPairAuthParameters("")
	if err != nil {
		t.Skipf("skipping key-pair test: %s", err)
	}

	privateKeyBytes, err = base64.StdEncoding.DecodeString(rawBase64PrivateKey)
	if err != nil {
		t.Fatalf("failed to decode base64 private key: %s", err)
	}

	return connURL, username, privateKeyBytes
}

// attemptDropUserKeyPair drops a user using key-pair authentication for the admin connection.
func attemptDropUserKeyPair(connURL, adminUser string, adminPrivateKey []byte, username string) {
	db, err := openSnowflake(connURL, adminUser, adminPrivateKey)
	if err != nil {
		log.Printf("key-pair connection issue: %s", err)
		return
	}
	defer db.Close()

	_, err = db.Exec(fmt.Sprintf("DROP USER %s", username))
	if err != nil {
		log.Printf("query issue: %s", err)
	}
}

// TestSnowflakeSQL_Initialize ensures initializing the Snowflake
// DB works as expected for both user-pass and keypair authentication
// scenarios
func TestSnowflakeSQL_Initialize(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	t.Run("userpass auth", func(t *testing.T) {
		skipIfNoPassword(t)

		db := new()
		defer dbtesting.AssertClose(t, db)

		connURL, err := dsnString()
		if err != nil {
			t.Fatalf("failed to retrieve connection DSN: %s", err)
		}

		expectedConfig := map[string]interface{}{
			"connection_url": connURL,
			dbplugin.SupportedCredentialTypesKey: []interface{}{
				dbplugin.CredentialTypePassword.String(),
				dbplugin.CredentialTypeRSAPrivateKey.String(),
			},
		}
		req := dbplugin.InitializeRequest{
			Config: map[string]interface{}{
				"connection_url": connURL,
			},
			VerifyConnection: true,
		}
		resp := dbtesting.AssertInitialize(t, db, req)
		if !reflect.DeepEqual(resp.Config, expectedConfig) {
			t.Fatalf("Actual: %#v\nExpected: %#v", resp.Config, expectedConfig)
		}

		connProducer := db.snowflakeConnectionProducer
		if !connProducer.Initialized {
			t.Fatal("Database should be initialized")
		}
	})

	// the environment variable SNOWFLAKE_PRIVATE_KEY in CI
	// is a base64 encoded string. As such, this test expects the
	// input for the variable to be base64 encoded
	t.Run("keypair auth with raw private key", func(t *testing.T) {
		db := new()
		defer dbtesting.AssertClose(t, db)

		connURL, rawBase64PrivateKey, user, err := getKeyPairAuthParameters("")
		if err != nil {
			t.Fatalf("failed to retrieve connection URL: %s", err)
		}

		// decode base64 encoded private key from environment
		privateKey, err := base64.StdEncoding.DecodeString(rawBase64PrivateKey)
		if err != nil {
			t.Fatalf("failed to decode private key: %s", err)
		}

		expectedConfig := map[string]interface{}{
			"connection_url": connURL,
			"username":       user,
			"private_key":    privateKey,
			dbplugin.SupportedCredentialTypesKey: []interface{}{
				dbplugin.CredentialTypePassword.String(),
				dbplugin.CredentialTypeRSAPrivateKey.String(),
			},
		}
		req := dbplugin.InitializeRequest{
			Config: map[string]interface{}{
				"connection_url": connURL,
				"username":       user,
				"private_key":    privateKey,
			},
			VerifyConnection: true,
		}
		resp := dbtesting.AssertInitialize(t, db, req)
		if !reflect.DeepEqual(resp.Config, expectedConfig) {
			t.Fatalf("Actual: %#v\nExpected: %#v", resp.Config, expectedConfig)
		}

		connProducer := db.snowflakeConnectionProducer
		if !connProducer.Initialized {
			t.Fatal("Database should be initialized")
		}
	})

	// the environment variable SNOWFLAKE_PRIVATE_KEY in CI
	// is a base64 encoded string. As such, this test expects the
	// input for the variable to be base64 encoded
	t.Run("keypair auth with query params", func(t *testing.T) {
		db := new()
		defer dbtesting.AssertClose(t, db)

		connURL, rawBase64PrivateKey, user, err := getKeyPairAuthParameters("disableOCSPChecks=true&maxRetryCount=5")
		if err != nil {
			t.Fatalf("failed to retrieve connection URL: %s", err)
		}

		// decode base64 encoded private key from environment
		privateKey, err := base64.StdEncoding.DecodeString(rawBase64PrivateKey)
		if err != nil {
			t.Fatalf("failed to decode private key: %s", err)
		}

		expectedConfig := map[string]interface{}{
			"connection_url": connURL,
			"username":       user,
			"private_key":    privateKey,
			dbplugin.SupportedCredentialTypesKey: []interface{}{
				dbplugin.CredentialTypePassword.String(),
				dbplugin.CredentialTypeRSAPrivateKey.String(),
			},
		}
		req := dbplugin.InitializeRequest{
			Config: map[string]interface{}{
				"connection_url": connURL,
				"username":       user,
				"private_key":    privateKey,
			},
			VerifyConnection: true,
		}
		resp := dbtesting.AssertInitialize(t, db, req)
		if !reflect.DeepEqual(resp.Config, expectedConfig) {
			t.Fatalf("Actual: %#v\nExpected: %#v", resp.Config, expectedConfig)
		}

		connProducer := db.snowflakeConnectionProducer
		if !connProducer.Initialized {
			t.Fatal("Database should be initialized")
		}
	})

}

func TestSnowflake_NewUser(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	type testCase struct {
		creationStmts  []string
		credentialType dbplugin.CredentialType
		keyBits        int
		password       string
		expectErr      bool
	}

	passwordTests := map[string]testCase{
		"new user with empty creation statements": {
			credentialType: dbplugin.CredentialTypePassword,
			creationStmts:  []string{},
			expectErr:      true,
		},
		"new user with password credential using name": {
			credentialType: dbplugin.CredentialTypePassword,
			creationStmts: []string{
				`
				CREATE USER {{name}} PASSWORD = '{{password}}' DEFAULT_ROLE = public;
				GRANT ROLE public TO USER {{name}};`,
			},
			password: "y8fva_sdVA3rasf",
		},
		"new user with password credential using username and split statements": {
			credentialType: dbplugin.CredentialTypePassword,
			creationStmts: []string{
				"CREATE USER {{username}} PASSWORD = '{{password}}';",
				"GRANT ROLE public TO USER {{username}};",
			},
			password: "secure_password",
		},
	}

	keyPairTests := map[string]testCase{
		"new user with 2048 bit rsa_private_key credential": {
			credentialType: dbplugin.CredentialTypeRSAPrivateKey,
			creationStmts: []string{
				`
				CREATE USER {{username}} RSA_PUBLIC_KEY='{{public_key}}';
				GRANT ROLE public TO USER {{username}};`,
			},
			keyBits: 2048,
		},
		"new user with 3072 bit rsa_private_key credential": {
			credentialType: dbplugin.CredentialTypeRSAPrivateKey,
			creationStmts: []string{
				"CREATE USER {{username}} RSA_PUBLIC_KEY='{{public_key}}';",
			},
			keyBits: 3072,
		},
		"new user with 4096 bit rsa_private_key credential and split statements": {
			credentialType: dbplugin.CredentialTypeRSAPrivateKey,
			creationStmts: []string{
				"CREATE USER {{username}} RSA_PUBLIC_KEY='{{public_key}}';",
				"GRANT ROLE public TO USER {{username}};",
			},
			keyBits: 4096,
		},
	}

	for name, test := range passwordTests {
		t.Run(name, func(t *testing.T) {
			skipIfNoPassword(t)
			connURL := connUrl(t)

			db := new()
			defer dbtesting.AssertClose(t, db)

			initReq := dbplugin.InitializeRequest{
				Config: map[string]interface{}{
					"connection_url": connURL,
				},
				VerifyConnection: true,
			}
			dbtesting.AssertInitialize(t, db, initReq)

			createReq := dbplugin.NewUserRequest{
				UsernameConfig: dbplugin.UsernameMetadata{
					DisplayName: "test",
					RoleName:    "test",
				},
				Statements: dbplugin.Statements{
					Commands: test.creationStmts,
				},
				CredentialType: test.credentialType,
				Password:       test.password,
				Expiration:     time.Now().Add(time.Hour),
			}

			ctx, cancel := context.WithTimeout(context.Background(), getRequestTimeout(t))
			defer cancel()

			createResp, err := db.NewUser(ctx, createReq)
			if test.expectErr {
				require.Error(t, err)
				return
			} else if err != nil {
				t.Fatalf("failed to create user %s", err)
			}
			defer attemptDropUser(connURL, createResp.Username)
			assertPasswordCredentialsExist(t, connURL, createResp.Username, test.password)
		})
	}

	for name, test := range keyPairTests {
		t.Run(name, func(t *testing.T) {
			skipIfNoKeyPair(t)
			connURL, adminUser, adminPrivateKey := connUrlKeyPair(t)

			db := new()
			defer dbtesting.AssertClose(t, db)

			initReq := dbplugin.InitializeRequest{
				Config: map[string]interface{}{
					"connection_url": connURL,
					"username":       adminUser,
					"private_key":    adminPrivateKey,
				},
				VerifyConnection: true,
			}
			dbtesting.AssertInitialize(t, db, initReq)

			pub, priv := testGenerateRSAKeyPair(t, test.keyBits)
			createReq := dbplugin.NewUserRequest{
				UsernameConfig: dbplugin.UsernameMetadata{
					DisplayName: "test",
					RoleName:    "test",
				},
				Statements: dbplugin.Statements{
					Commands: test.creationStmts,
				},
				CredentialType: test.credentialType,
				PublicKey:      pub,
				Expiration:     time.Now().Add(time.Hour),
			}

			ctx, cancel := context.WithTimeout(context.Background(), getRequestTimeout(t))
			defer cancel()

			createResp, err := db.NewUser(ctx, createReq)
			if test.expectErr {
				require.Error(t, err)
				return
			} else if err != nil {
				t.Fatalf("failed to create user %s", err)
			}
			defer attemptDropUserKeyPair(connURL, adminUser, adminPrivateKey, createResp.Username)
			assertRSAKeyPairCredentialsExist(t, connURL, createResp.Username, priv)
		})
	}
}

func TestSnowflake_RenewUser(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}
	skipIfNoPassword(t)

	connURL := connUrl(t)

	db := new()
	defer dbtesting.AssertClose(t, db)

	initReq := dbplugin.InitializeRequest{
		Config: map[string]interface{}{
			"connection_url": connURL,
		},
		VerifyConnection: true,
	}
	dbtesting.AssertInitialize(t, db, initReq)

	password := "y8fva_sdVA3rasf"

	createReq := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: "test",
			RoleName:    "test",
		},
		Statements: dbplugin.Statements{
			Commands: []string{
				`
				CREATE USER {{name}} PASSWORD = '{{password}}';
				GRANT ROLE public TO USER {{name}};`,
			},
		},
		Password:   password,
		Expiration: time.Now().Add(time.Hour),
	}

	createResp := dbtesting.AssertNewUser(t, db, createReq)
	defer attemptDropUser(connURL, createResp.Username)

	assertPasswordCredentialsExist(t, connURL, createResp.Username, password)

	renewReq := dbplugin.UpdateUserRequest{
		Username: createResp.Username,
		Expiration: &dbplugin.ChangeExpiration{
			NewExpiration: time.Now().Add(time.Minute),
		},
	}

	dbtesting.AssertUpdateUser(t, db, renewReq)

	// Sleep longer than the initial expiration time
	time.Sleep(2 * time.Second)

	assertPasswordCredentialsExist(t, connURL, createResp.Username, password)
}

func TestSnowflake_RevokeUser(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}
	skipIfNoPassword(t)

	connURL := connUrl(t)

	type testCase struct {
		deleteStatements []string
	}

	tests := map[string]testCase{
		"name revoke": {
			deleteStatements: []string{
				`
				DROP USER {{name}};`,
			},
		},
		"username revoke": {
			deleteStatements: []string{
				`
				DROP USER {{username}};`,
			},
		},
		"default revoke": {},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			db := new()
			defer dbtesting.AssertClose(t, db)

			initReq := dbplugin.InitializeRequest{
				Config: map[string]interface{}{
					"connection_url": connURL,
				},
				VerifyConnection: true,
			}
			dbtesting.AssertInitialize(t, db, initReq)

			password := "y8fva_sdVA3rasf"

			createReq := dbplugin.NewUserRequest{
				UsernameConfig: dbplugin.UsernameMetadata{
					DisplayName: "test",
					RoleName:    "test",
				},
				Statements: dbplugin.Statements{
					Commands: []string{
						`
						CREATE USER {{name}} PASSWORD = '{{password}}';
						GRANT ROLE public TO USER {{name}};`,
					},
				},
				Password:   password,
				Expiration: time.Now().Add(time.Hour),
			}

			createResp := dbtesting.AssertNewUser(t, db, createReq)

			assertPasswordCredentialsExist(t, connURL, createResp.Username, password)

			deleteReq := dbplugin.DeleteUserRequest{
				Username: createResp.Username,
				Statements: dbplugin.Statements{
					Commands: test.deleteStatements,
				},
			}
			dbtesting.AssertDeleteUser(t, db, deleteReq)
			assertPasswordCredentialsDoNotExist(t, connURL, createResp.Username, password)
		})
	}
}

func TestSnowflake_RenewUser_KeyPair(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}
	skipIfNoKeyPair(t)

	connURL, adminUser, adminPrivateKey := connUrlKeyPair(t)

	db := new()
	defer dbtesting.AssertClose(t, db)

	initReq := dbplugin.InitializeRequest{
		Config: map[string]interface{}{
			"connection_url": connURL,
			"username":       adminUser,
			"private_key":    adminPrivateKey,
		},
		VerifyConnection: true,
	}
	dbtesting.AssertInitialize(t, db, initReq)

	pub, priv := testGenerateRSAKeyPair(t, 2048)

	createReq := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: "test",
			RoleName:    "test",
		},
		Statements: dbplugin.Statements{
			Commands: []string{
				`
				CREATE USER {{username}} RSA_PUBLIC_KEY='{{public_key}}';
				GRANT ROLE public TO USER {{username}};`,
			},
		},
		CredentialType: dbplugin.CredentialTypeRSAPrivateKey,
		PublicKey:      pub,
		Expiration:     time.Now().Add(time.Hour),
	}

	createResp := dbtesting.AssertNewUser(t, db, createReq)
	defer attemptDropUserKeyPair(connURL, adminUser, adminPrivateKey, createResp.Username)

	assertRSAKeyPairCredentialsExist(t, connURL, createResp.Username, priv)

	renewReq := dbplugin.UpdateUserRequest{
		Username: createResp.Username,
		Expiration: &dbplugin.ChangeExpiration{
			NewExpiration: time.Now().Add(time.Minute),
		},
	}

	dbtesting.AssertUpdateUser(t, db, renewReq)

	// Sleep longer than the initial expiration time
	time.Sleep(2 * time.Second)

	assertRSAKeyPairCredentialsExist(t, connURL, createResp.Username, priv)
}

func TestSnowflake_RevokeUser_KeyPair(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}
	skipIfNoKeyPair(t)

	connURL, adminUser, adminPrivateKey := connUrlKeyPair(t)

	db := new()
	defer dbtesting.AssertClose(t, db)

	initReq := dbplugin.InitializeRequest{
		Config: map[string]interface{}{
			"connection_url": connURL,
			"username":       adminUser,
			"private_key":    adminPrivateKey,
		},
		VerifyConnection: true,
	}
	dbtesting.AssertInitialize(t, db, initReq)

	pub, priv := testGenerateRSAKeyPair(t, 2048)

	createReq := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: "test",
			RoleName:    "test",
		},
		Statements: dbplugin.Statements{
			Commands: []string{
				`
				CREATE USER {{username}} RSA_PUBLIC_KEY='{{public_key}}';
				GRANT ROLE public TO USER {{username}};`,
			},
		},
		CredentialType: dbplugin.CredentialTypeRSAPrivateKey,
		PublicKey:      pub,
		Expiration:     time.Now().Add(time.Hour),
	}

	createResp := dbtesting.AssertNewUser(t, db, createReq)

	assertRSAKeyPairCredentialsExist(t, connURL, createResp.Username, priv)

	deleteReq := dbplugin.DeleteUserRequest{
		Username: createResp.Username,
		Statements: dbplugin.Statements{
			Commands: []string{
				"DROP USER {{username}};",
			},
		},
	}
	dbtesting.AssertDeleteUser(t, db, deleteReq)
	assertRSAKeyPairCredentialsDoNotExist(t, connURL, createResp.Username, priv)
}

func TestSnowflake_DefaultUsernameTemplate(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}
	skipIfNoPassword(t)

	connURL := connUrl(t)

	db := new()
	defer dbtesting.AssertClose(t, db)

	initReq := dbplugin.InitializeRequest{
		Config: map[string]interface{}{
			"connection_url": connURL,
		},
		VerifyConnection: true,
	}
	dbtesting.AssertInitialize(t, db, initReq)

	password := "y8fva_sdVA3rasf"
	createReq := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: "test",
			RoleName:    "test",
		},
		Statements: dbplugin.Statements{
			Commands: []string{
				`
				CREATE USER {{name}} PASSWORD = '{{password}}';
				GRANT ROLE public TO USER {{name}};`,
			},
		},
		Password:   password,
		Expiration: time.Now().Add(time.Hour),
	}
	createResp := dbtesting.AssertNewUser(t, db, createReq)
	defer attemptDropUser(connURL, createResp.Username)

	if createResp.Username == "" {
		t.Fatalf("Missing username")
	}

	assertPasswordCredentialsExist(t, connURL, createResp.Username, password)

	require.Regexp(t, `^v_test_test_[a-zA-Z0-9]{20}_[0-9]{10}$`, createResp.Username)
}

func TestSnowflake_CustomUsernameTemplate(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}
	skipIfNoPassword(t)

	connURL := connUrl(t)

	db := new()
	defer dbtesting.AssertClose(t, db)

	initReq := dbplugin.InitializeRequest{
		Config: map[string]interface{}{
			"connection_url":    connURL,
			"username_template": "{{.DisplayName}}_{{random 10}}",
		},
		VerifyConnection: true,
	}
	dbtesting.AssertInitialize(t, db, initReq)

	password := "y8fva_sdVA3rasf"
	createReq := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: "test",
			RoleName:    "test",
		},
		Statements: dbplugin.Statements{
			Commands: []string{
				`
				CREATE USER {{name}} PASSWORD = '{{password}}';
				GRANT ROLE public TO USER {{name}};`,
			},
		},
		Password:   password,
		Expiration: time.Now().Add(time.Hour),
	}
	createResp := dbtesting.AssertNewUser(t, db, createReq)
	defer attemptDropUser(connURL, createResp.Username)

	if createResp.Username == "" {
		t.Fatalf("Missing username")
	}

	assertPasswordCredentialsExist(t, connURL, createResp.Username, password)

	require.Regexp(t, `^test_[a-zA-Z0-9]{10}$`, createResp.Username)
}

func dsnString() (string, error) {
	user := os.Getenv(envVarSnowflakeUser)
	password := os.Getenv(envVarSnowflakePassword)
	account := os.Getenv(envVarSnowflakeAccount)

	var err error
	if user == "" {
		err = multierror.Append(err, fmt.Errorf("SNOWFLAKE_USER not set"))
	}
	if password == "" {
		err = multierror.Append(err, fmt.Errorf("SNOWFLAKE_PASSWORD not set"))
	}
	if account == "" {
		err = multierror.Append(err, fmt.Errorf("SNOWFLAKE_ACCOUNT not set"))
	}

	if err != nil {
		return "", err
	}

	dsnString := fmt.Sprintf("%s:%s@%s", user, password, account)

	return dsnString, nil
}

func getKeyPairAuthParameters(optionalQueryParams string) (connURL string, pKey string, user string, err error) {
	user = os.Getenv(envVarSnowflakeUser)
	pKey = os.Getenv(envVarSnowflakePrivateKey)
	account := os.Getenv(envVarSnowflakeAccount)
	database := os.Getenv(envVarSnowflakeDatabase)

	if user == "" {
		err = multierror.Append(err, fmt.Errorf("SNOWFLAKE_USER not set"))
	}
	if pKey == "" {
		err = multierror.Append(err, fmt.Errorf("SNOWFLAKE_PRIVATE_KEY not set"))
	}
	if account == "" {
		err = multierror.Append(err, fmt.Errorf("SNOWFLAKE_ACCOUNT not set"))
	}

	if database == "" {
		err = multierror.Append(err, fmt.Errorf("SNOWFLAKE_DATABASE not set"))
	}

	connURL = fmt.Sprintf("%s.snowflakecomputing.com/%s", account, database)

	if optionalQueryParams != "" {
		connURL = fmt.Sprintf("%s?%s", connURL, optionalQueryParams)
	}

	return connURL, pKey, user, err
}

func verifyConnWithKeyPairCredential(connString, username string, private *rsa.PrivateKey) error {
	var config gosnowflake.Config
	if strings.Contains(connString, "@") {
		// Password-style DSN: user:pass@account
		conf, err := gosnowflake.ParseDSN(connString)
		if err != nil {
			return err
		}
		config = gosnowflake.Config{
			Account:  conf.Account,
			Region:   conf.Region,
			Database: conf.Database,
			Schema:   conf.Schema,
		}
	} else {
		// Key-pair style URL: account.snowflakecomputing.com/db
		// ParseDSN rejects empty passwords, so extract account manually.
		// Don't set the database — the newly created user may not have access to it.
		parts := accountAndDBNameFromConnURLRegex.FindStringSubmatch(connString)
		if len(parts) != 3 {
			return fmt.Errorf("invalid key-pair connection URL format: %s", connString)
		}
		config = gosnowflake.Config{
			Account: parts[1],
		}
	}

	config.Authenticator = gosnowflake.AuthTypeJwt
	config.User = username
	config.PrivateKey = private

	connector := gosnowflake.NewConnector(gosnowflake.SnowflakeDriver{}, config)
	db := sql.OpenDB(connector)
	defer db.Close()
	return db.Ping()
}

func verifyConnWithPasswordCredential(connString, username, password string) error {
	conf, err := gosnowflake.ParseDSN(connString)
	if err != nil {
		return err
	}

	config := &gosnowflake.Config{
		Authenticator: gosnowflake.AuthTypeSnowflake,
		Account:       conf.Account,
		Region:        conf.Region,
		Database:      conf.Database,
		Schema:        conf.Schema,
		User:          username,
		Password:      password,
	}

	dsn, err := gosnowflake.DSN(config)
	if err != nil {
		return err
	}

	db, err := sql.Open("snowflake", dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	return db.Ping()
}

func assertPasswordCredentialsExist(t *testing.T, connString, username, password string) {
	t.Helper()
	err := verifyConnWithPasswordCredential(connString, username, password)
	if err != nil {
		t.Fatalf("failed to log in with password credential: %s", err)
	}
}

// assertPasswordCredentialsDoNotExist is a helper to assert db creds were
// properly removed. A successful assertion will result in the gosnowflake
// default logger to output `msg="Authentication FAILED"` in the test logs.
func assertPasswordCredentialsDoNotExist(t *testing.T, connString, username, password string) {
	t.Helper()
	err := verifyConnWithPasswordCredential(connString, username, password)
	if err == nil {
		t.Fatalf("logged in when it shouldn't have been able to")
	}
}

func assertRSAKeyPairCredentialsExist(t *testing.T, connString, username string, private *rsa.PrivateKey) {
	t.Helper()
	err := verifyConnWithKeyPairCredential(connString, username, private)
	if err != nil {
		t.Fatalf("failed to log in with RSA key pair credential: %s", err)
	}
}

func assertRSAKeyPairCredentialsDoNotExist(t *testing.T, connString, username string, private *rsa.PrivateKey) {
	t.Helper()
	err := verifyConnWithKeyPairCredential(connString, username, private)
	if err == nil {
		t.Fatalf("logged in when it shouldn't have been able to")
	}
}

// Needed to not clutter the shared instance with testing artifacts
func attemptDropUser(connString, username string) {
	db, err := sql.Open("snowflake", connString)
	if err != nil {
		log.Printf("connection issue: %s", err)
	}

	defer db.Close()
	_, err = db.Exec(fmt.Sprintf("DROP USER %s", username))
	if err != nil {
		log.Printf("query issue: %s", err)
	}
}

func getRequestTimeout(t *testing.T) time.Duration {
	rawDur := os.Getenv("VAULT_TEST_DATABASE_REQUEST_TIMEOUT")
	if rawDur == "" {
		return 1 * time.Minute
	}

	dur, err := time.ParseDuration(rawDur)
	if err != nil {
		t.Fatalf("Failed to parse custom request timeout %q: %s", rawDur, err)
	}
	return dur
}

func testGenerateRSAKeyPair(t *testing.T, bits int) ([]byte, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)
	public, err := x509.MarshalPKIXPublicKey(key.Public())
	require.NoError(t, err)
	publicBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: public,
	}
	return pem.EncodeToMemory(publicBlock), key
}
