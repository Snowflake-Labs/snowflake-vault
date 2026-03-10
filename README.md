# vault-plugin-database-snowflake

A community-maintained Vault plugin for Snowflake that generates ephemeral
[Database User](https://docs.snowflake.com/en/user-guide/admin-user-management.html) credentials
via the HashiCorp Vault Database Secrets Engine.

> **Note:** Community fork of [hashicorp/vault-plugin-database-snowflake](https://github.com/hashicorp/vault-plugin-database-snowflake).
> Requires Vault 1.6+.

> **⚠️ Snowflake is deprecating password authentication after November 2025.**
> Migrate service account connections and dynamic roles to key-pair auth before that date.

## Bugs and Feature Requests

File issues at [sfc-gh-phorrigan/vault-plugin-database-snowflake/issues](https://github.com/sfc-gh-phorrigan/vault-plugin-database-snowflake/issues).

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
# rsa_private_key -----BEGIN PRIVATE KEY-----...
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
