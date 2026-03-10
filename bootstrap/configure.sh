#!/usr/bin/env bash
# Copyright 2026 Snowflake Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


PLUGIN_DIR=$1
PLUGIN_NAME=$2
CONNECTION_URL=$3
PRIVATE_KEY=$4
SNOWFLAKE_USERNAME=$5

# validate these are set
[ "${PLUGIN_DIR:?}" ]
[ "${PLUGIN_NAME:?}" ]
[ "${CONNECTION_URL:?}" ]
[ "${PRIVATE_KEY:?}" ]
[ "${SNOWFLAKE_USERNAME:?}" ]

CONFIG=snowflake
ROLE=test-role

# Try to clean-up previous runs
vault secrets disable database
vault plugin deregister database "${PLUGIN_NAME}"
sleep 1

# Copy the binary so text file is not busy when rebuilding & the plugin is registered
cp ./bin/"$PLUGIN_NAME" "$PLUGIN_DIR"

SHASUM="$(shasum -a 256 "$PLUGIN_DIR"/"$PLUGIN_NAME" | awk '{print $1}')"

if [[ -z "$SHASUM" ]]; then echo "error: shasum not set"; exit 1; fi

# Sets up the binary with local changes
vault plugin register \
    -sha256="${SHASUM}" \
    database "${PLUGIN_NAME}"

vault secrets enable database

vault write database/config/${CONFIG} \
    plugin_name=${PLUGIN_NAME} \
    allowed_roles=${ROLE} \
    connection_url=${CONNECTION_URL} \
    private_key=${PRIVATE_KEY} \
    username=${SNOWFLAKE_USERNAME}

vault write database/roles/${ROLE} \
    db_name=${CONFIG} \
    creation_statements="CREATE USER {{name}} PASSWORD = '{{password}}'
        DAYS_TO_EXPIRY = {{expiration}} DEFAULT_ROLE=public;
        GRANT ROLE public TO USER {{name}};" \
    default_ttl="1h" \
    max_ttl="24h"

vault read database/creds/${ROLE}