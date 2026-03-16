// Copyright 2026 Snowflake Inc.
// SPDX-License-Identifier: MPL-2.0

package snowflake

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// SQL templates for Programmatic Access Token (PAT) lifecycle management.
//
// PATs are Snowflake-managed Bearer tokens used for API access (e.g. Cortex CLI,
// Snowflake REST API). Unlike password/key-pair credentials, Snowflake generates
// the token secret — Vault cannot return it via NewUserResponse. These helpers
// are intended for service-side token management (e.g. revocation on lease expiry,
// listing tokens for audit).
//
// Docs: https://docs.snowflake.com/en/user-guide/programmatic-access-tokens
const (
	// createPATSQL creates a PAT for an existing Snowflake user.
	// {{name}}         — Snowflake username
	// {{token_name}}   — display name for the token (must be unique per user)
	// {{expiration}}   — number of days until the token expires (integer string)
	// {{role_name}}    — Snowflake role to associate with the token
	//
	// NOTE: The generated token secret is returned by the SQL result set, not by
	// Vault. Callers must capture the result of this statement to retrieve the token.
	createPATSQL = `
ALTER USER "{{name}}" ADD PROGRAMMATIC_ACCESS_TOKEN "{{token_name}}"
  DAYS_TO_EXPIRY = {{expiration}}
  ROLE_RESTRICTION = "{{role_name}}"
  COMMENT = 'Managed by Vault';
`

	// revokePATSQL removes a PAT from a Snowflake user.
	revokePATSQL = `
ALTER USER "{{name}}" REMOVE PROGRAMMATIC_ACCESS_TOKEN "{{token_name}}";
`

	// listPATsSQL lists all PATs for a Snowflake user.
	listPATsSQL = `
SHOW PROGRAMMATIC ACCESS TOKENS FOR USER "{{name}}";
`
)

// PATInfo represents a single Programmatic Access Token as returned by
// SHOW PROGRAMMATIC ACCESS TOKENS FOR USER.
type PATInfo struct {
	// TokenName is the human-readable name of the token.
	TokenName string
	// RoleRestriction is the Snowflake role associated with the token.
	RoleRestriction string
	// ExpiresAt is when the token will expire (UTC).
	ExpiresAt time.Time
	// Comment is the optional comment set at creation time.
	Comment string
}

// createPATForUser issues a CREATE PROGRAMMATIC ACCESS TOKEN statement for the
// given user. The token secret is returned in the SQL result set; callers are
// responsible for reading it from the returned *sql.Rows before closing.
//
// This helper does NOT close the returned rows — the caller must do so.
func createPATForUser(ctx context.Context, db *sql.DB, username, tokenName, roleName, expirationDays string) (*sql.Rows, error) {
	if username == "" || tokenName == "" || roleName == "" || expirationDays == "" {
		return nil, fmt.Errorf("createPATForUser: username, tokenName, roleName, and expirationDays are all required")
	}

	query := interpolatePATQuery(createPATSQL, map[string]string{
		"name":       username,
		"token_name": tokenName,
		"expiration": expirationDays,
		"role_name":  roleName,
	})

	return db.QueryContext(ctx, query)
}

// revokePATForUser removes a named PAT from the given user.
func revokePATForUser(ctx context.Context, db *sql.DB, username, tokenName string) error {
	if username == "" || tokenName == "" {
		return fmt.Errorf("revokePATForUser: username and tokenName are required")
	}

	query := interpolatePATQuery(revokePATSQL, map[string]string{
		"name":       username,
		"token_name": tokenName,
	})

	_, err := db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to revoke PAT %q for user %q: %w", tokenName, username, err)
	}
	return nil
}

// listPATsForUser returns metadata about all PATs belonging to the given user.
func listPATsForUser(ctx context.Context, db *sql.DB, username string) ([]PATInfo, error) {
	if username == "" {
		return nil, fmt.Errorf("listPATsForUser: username is required")
	}

	query := interpolatePATQuery(listPATsSQL, map[string]string{
		"name": username,
	})

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list PATs for user %q: %w", username, err)
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, fmt.Errorf("failed to read PAT list columns: %w", err)
	}

	// Build a column-name → index map so we can handle schema evolution.
	colIdx := make(map[string]int, len(cols))
	for i, c := range cols {
		colIdx[c] = i
	}

	var tokens []PATInfo
	for rows.Next() {
		vals := make([]interface{}, len(cols))
		ptrs := make([]interface{}, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, fmt.Errorf("failed to scan PAT row: %w", err)
		}

		info := PATInfo{}
		if i, ok := colIdx["token_name"]; ok {
			info.TokenName, _ = vals[i].(string)
		}
		if i, ok := colIdx["role_restriction"]; ok {
			info.RoleRestriction, _ = vals[i].(string)
		}
		if i, ok := colIdx["comment"]; ok {
			info.Comment, _ = vals[i].(string)
		}
		if i, ok := colIdx["expires_at"]; ok {
			switch v := vals[i].(type) {
			case time.Time:
				info.ExpiresAt = v
			case string:
				t, err := time.Parse(time.RFC3339, v)
				if err == nil {
					info.ExpiresAt = t
				}
			}
		}
		tokens = append(tokens, info)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating PAT rows: %w", err)
	}

	return tokens, nil
}

// interpolatePATQuery replaces {{key}} placeholders in template with the
// values from m. Values are NOT SQL-escaped; callers must ensure that
// identifiers passed here are validated/trusted (Vault-generated usernames,
// token names, and role names originating from Vault config).
func interpolatePATQuery(template string, m map[string]string) string {
	result := template
	for k, v := range m {
		result = replaceAll(result, "{{"+k+"}}", v)
	}
	return result
}

// replaceAll replaces all occurrences of old with new in s.
func replaceAll(s, old, newStr string) string {
	for {
		idx := indexOf(s, old)
		if idx < 0 {
			break
		}
		s = s[:idx] + newStr + s[idx+len(old):]
	}
	return s
}

// indexOf returns the index of substr in s, or -1 if not found.
func indexOf(s, substr string) int {
	if len(substr) > len(s) {
		return -1
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
