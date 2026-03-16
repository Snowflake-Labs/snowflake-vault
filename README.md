# vault-plugin-database-snowflake

A community-maintained Vault plugin for Snowflake that generates ephemeral
[Database User](https://docs.snowflake.com/en/user-guide/admin-user-management.html) credentials
via the HashiCorp Vault Database Secrets Engine.

> **Note:** Community fork of [hashicorp/vault-plugin-database-snowflake](https://github.com/hashicorp/vault-plugin-database-snowflake).
> Requires Vault 1.6+.

> **⚠️ Snowflake is deprecating password authentication after November 2025.**
> Migrate service account connections and dynamic roles to key-pair auth before that date.

## Bugs and Feature Requests

File issues at [Snowflake-Labs/snowflake-vault/issues](https://github.com/Snowflake-Labs/snowflake-vault/issues).

## Quick Links

- [Database Secrets Engine - Docs](https://developer.hashicorp.com/vault/docs/secrets/databases/snowflake)
- [Database Secrets Engine - API Docs](https://developer.hashicorp.com/vault/api-docs/secret/databases/snowflake)
- [Snowflake Docs](https://docs.snowflake.com)

---

## Service Account Authentication

Four methods are supported. Set exactly one per connection config.

| Method | Field(s) | When to use |
|--------|----------|-------------|
| Key-pair | `private_key` | Recommended default |
| WIF | `workload_identity_provider` | Cloud-native environments (AWS/GCP/Azure/OIDC) |
| OAuth 2.0 | `oauth_client_id` + `oauth_client_secret` + `oauth_token_endpoint` | External IdP |
| Password | `password` | **Deprecated** — removed Nov 2025 |

### Key-Pair

Assign your public key to the Snowflake user first:
```sql
ALTER USER "VAULT-SERVICE-USER" SET RSA_PUBLIC_KEY='<base64-public-key>';
```

```sh
vault write database/config/my-snowflake \
  plugin_name=vault-plugin-database-snowflake \
  connection_url="<account>.snowflakecomputing.com/<database>" \
  username="VAULT-SERVICE-USER" \
  private_key=@/path/to/rsa_key_pkcs8.pem \
  allowed_roles="*"
```

### Workload Identity Federation (WIF)

```sh
vault write database/config/my-snowflake \
  plugin_name=vault-plugin-database-snowflake \
  connection_url="<account>.snowflakecomputing.com/<database>" \
  username="VAULT-SERVICE-USER" \
  workload_identity_provider="AWS" \   # AWS | GCP | AZURE | OIDC
  allowed_roles="*"
```

OIDC requires an explicit token: `workload_identity_token="<jwt>"`.
Azure supports an optional `workload_identity_entra_resource="<url>"`.

### OAuth 2.0 Client Credentials

```sh
vault write database/config/my-snowflake \
  plugin_name=vault-plugin-database-snowflake \
  connection_url="<account>.snowflakecomputing.com/<database>" \
  username="VAULT-SERVICE-USER" \
  oauth_client_id="<client-id>" \
  oauth_client_secret="<client-secret>" \
  oauth_token_endpoint="https://<your-idp>/oauth/token" \
  oauth_scope="session:role:SYSADMIN" \   # optional
  allowed_roles="*"
```

---

## Dynamic User Credential Types

Set `credential_type` on the role to control what Vault issues to callers.

| Type | Vault returns | Snowflake auth | Status |
|------|--------------|----------------|--------|
| `rsa_private_key` | Private key | Key-pair | **Recommended** |
| `password` | Password | Password | Deprecated Nov 2025 |

### RSA Key-Pair (Recommended)

Vault generates a fresh key pair per request. The public key is written to Snowflake at user creation; the private key is returned to the caller.

```sh
vault write database/roles/my-role \
  db_name=my-snowflake \
  credential_type=rsa_private_key \
  creation_statements="CREATE USER {{name}} LOGIN_NAME='{{name}}' DEFAULT_ROLE='PUBLIC' RSA_PUBLIC_KEY='{{public_key}}' DAYS_TO_EXPIRY=1; GRANT ROLE PUBLIC TO USER {{name}};" \
  default_ttl=1h \
  max_ttl=24h
```

```sh
vault read database/creds/my-role
# Key             Value
# rsa_private_key ***REMOVED***...
# username        v_token_my_role_xxxx_1234567890
```

### Password (Deprecated)

```sh
vault write database/roles/my-role \
  db_name=my-snowflake \
  creation_statements="CREATE USER {{name}} PASSWORD='{{password}}' LOGIN_NAME='{{name}}' DEFAULT_ROLE='PUBLIC' DAYS_TO_EXPIRY=1; GRANT ROLE PUBLIC TO USER {{name}};" \
  default_ttl=1h \
  max_ttl=24h
```

---

## Cortex Quick-Start

[Snowflake Cortex](https://docs.snowflake.com/en/user-guide/snowflake-cortex/overview) provides serverless LLM functions (`COMPLETE`, `SUMMARIZE`, `SENTIMENT`, `TRANSLATE`, `EMBED_TEXT_*`) and the [Cortex CLI](https://docs.snowflake.com/en/user-guide/snowflake-cortex/cortex-cli) for AI-powered SQL and agent workflows.

### 1. Enable `cortex_access` on the connection config

Set `cortex_access=true` to automatically grant `SNOWFLAKE.CORTEX_USER` to every dynamic user created via this connection. This saves you from adding the grant to each role's `creation_statements`.

```sh
vault write database/config/my-snowflake \
  plugin_name=vault-plugin-database-snowflake \
  connection_url="<account>.snowflakecomputing.com/<database>" \
  username="VAULT-SERVICE-USER" \
  private_key=@/path/to/rsa_key_pkcs8.pem \
  cortex_access=true \
  allowed_roles="*"
```

### 2. Create a Cortex-ready role

Use `credential_type=rsa_private_key` — key-pair is the recommended auth method for Cortex CLI and API integrations.

```sh
vault write database/roles/cortex-role \
  db_name=my-snowflake \
  credential_type=rsa_private_key \
  creation_statements="
    CREATE USER \"{{name}}\"
      LOGIN_NAME='{{name}}'
      RSA_PUBLIC_KEY='{{public_key}}'
      DEFAULT_ROLE='PUBLIC'
      DAYS_TO_EXPIRY={{expiration}}
      COMMENT='Vault-managed Cortex user';
    GRANT ROLE PUBLIC TO USER \"{{name}}\";
  " \
  default_ttl=8h \
  max_ttl=24h
```

> The `SNOWFLAKE.CORTEX_USER` grant is appended automatically because `cortex_access=true`. You do not need to include it in `creation_statements`.

### 3. Fetch credentials and connect with the Cortex CLI

```sh
# Retrieve a short-lived key pair
vault read database/creds/cortex-role

# Key             Value
# rsa_private_key -----BEGIN RSA PRIVATE KEY-----...
# username        v_token_cortex_role_xxxx_1234567890

# Save the private key and connect via Cortex CLI
vault read -field=rsa_private_key database/creds/cortex-role > /tmp/cortex_key.pem
snow cortex complete --query "Explain Snowflake clustering in one sentence" \
  --user <username> \
  --private-key-path /tmp/cortex_key.pem
```

### Programmatic Access Tokens (PATs)

Snowflake [Programmatic Access Tokens](https://docs.snowflake.com/en/user-guide/programmatic-access-tokens) are Bearer tokens that work with the Cortex CLI and REST API. Unlike password/key-pair credentials, Snowflake generates the token secret — Vault cannot return a Snowflake-generated PAT via the database secrets engine.

This plugin ships PAT management helpers (`pat.go`) for use in companion tooling:

| Function | Description |
|----------|-------------|
| `createPATForUser` | Issue a new PAT for an existing Snowflake user |
| `revokePATForUser` | Revoke a named PAT (e.g. on lease expiry) |
| `listPATsForUser` | List all PATs for a user (for audit/rotation) |

For full PAT lifecycle management integrated with Vault leases, see the companion PAT plugin.

---

## Setup

A [scripted configuration](bootstrap/configure.sh) is available via `make configure`:

```sh
PLUGIN_NAME=vault-plugin-database-snowflake \
PLUGIN_DIR=$GOPATH/vault-plugins \
CONNECTION_URL=foo.snowflakecomputing.com/BAR \
PRIVATE_KEY=/path/to/private/key/file \
SNOWFLAKE_USERNAME=user1 \
make configure
```

---

## Acceptance Testing

Set `VAULT_ACC=1` and the following environment variables, then run `make testacc`.

| Variable | Description |
|----------|-------------|
| `SNOWFLAKE_ACCOUNT` | Account identifier (e.g. `ec#####.east-us-2.azure`) |
| `SNOWFLAKE_USER` | ACCOUNTADMIN-level user for Vault |
| `SNOWFLAKE_PASSWORD` | Password (optional if using key-pair) |
| `SNOWFLAKE_PRIVATE_KEY` | Path to private key file |
| `SNOWFLAKE_DB` | optional |
| `SNOWFLAKE_SCHEMA` | optional |
| `SNOWFLAKE_WAREHOUSE` | optional |
