## v0.16.0
### March 9, 2026

Community fork of [hashicorp/vault-plugin-database-snowflake](https://github.com/hashicorp/vault-plugin-database-snowflake).

NEW FEATURES:

* Add Workload Identity Federation (WIF) authentication support for AWS, GCP, AZURE, and OIDC providers

SECURITY:

* Bump `github.com/dvsekhvalnov/jose2go` v1.6.0 -> v1.7.0 (CVE-2025-63811)
* Bump `golang.org/x/crypto` v0.41.0 -> v0.45.0

MAINTENANCE:

* Update module path to `github.com/Snowflake-Labs/snowflake-vault`
* Replace HashiCorp-internal CI workflows with community equivalents
* Add dependabot config for automated dependency updates
* Update README, CODEOWNERS, and add MAINTAINERS.md

---

> Prior release history below is from the upstream HashiCorp repository.

## v0.15.0
### October 3, 2025

* Automated dependency upgrades (#125)
* Update dependencies (#148)
* Refresh the connection when necessary (#134)
* Enable query parameters parsing in connection URL for keypair auth (#135)
* Add backport assistant workflow (#128)
* escape dot in regex and add test to fix secvuln (#122)
* Add support for keypair root configuration (#109)

## v0.14.2
### September 17, 2025

* release/vault-1.20.x: Update dependencies (#153)
* Backport of Refresh the connection when necessary into release/vault-1.20.x (#147)
* Backport Enable query parameters parsing in connection URL for keypair auth into release/vault-1.20.x (#137)

## v0.14.1
### June 5, 2025

IMPROVEMENTS:

* Added key-pair auth support for database configuration in Vault 1.20.x

## v0.14.0
### May 23, 2025

IMPROVEMENTS:

* Updated dependencies

## v0.13.0
### Feb 11, 2025

IMPROVEMENTS:

* Updated dependencies

## v0.12.0
### Sept 4, 2024

IMPROVEMENTS:

* Updated dependencies

## v0.11.0
### May 20, 2024

IMPROVEMENTS:

* Updated dependencies
* `github.com/snowflakedb/gosnowflake` v1.7.2 -> v1.8.0

## v0.10.0
### Jan 31, 2024

CHANGES:

* Bump go.mod go version from 1.20 to 1.21

## v0.9.1
### Jan 23, 2024

IMPROVEMENTS:

* `github.com/hashicorp/vault/sdk` v0.9.2 -> v0.10.2
* `github.com/snowflakedb/gosnowflake` v1.6.24 -> v1.7.2

## v0.9.0
### August 22, 2023

IMPROVEMENTS:

* Updated dependencies
