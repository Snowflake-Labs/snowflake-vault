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



TOOL=vault-plugin-database-snowflake
#
# This script builds the application from source for multiple platforms.
set -e

GO_CMD=${GO_CMD:-go}

# Get the parent directory of where this script is.
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ] ; do SOURCE="$(readlink "$SOURCE")"; done
DIR="$( cd -P "$( dirname "$SOURCE" )/.." && pwd )"

# Change into that directory
cd "$DIR"

# Set build tags
BUILD_TAGS="${BUILD_TAGS}:-${TOOL}"

# Get the git commit
GIT_COMMIT="$(git rev-parse HEAD)"
GIT_DIRTY="$(test -n "`git status --porcelain`" && echo "+CHANGES" || true)"

GOPATH=${GOPATH:-$(go env GOPATH)}
case $(uname) in
    CYGWIN*)
        GOPATH="$(cygpath $GOPATH)"
        ;;
esac

# Delete the old dir
echo "==> Removing old directory..."
rm -f bin/*
rm -rf pkg/*
mkdir -p bin/

# Build!
${GO_CMD} build \
    -gcflags "${GCFLAGS}" \
    -ldflags "-X github.com/sfc-gh-phorrigan/${TOOL}/version.GitCommit='${GIT_COMMIT}${GIT_DIRTY}'" \
    -o "bin/${TOOL}" \
    -tags "${BUILD_TAGS}" \
    "${DIR}/cmd/${TOOL}"

# Move all the compiled things to the $GOPATH/bin
OLDIFS=$IFS
IFS=: MAIN_GOPATH=($GOPATH)
IFS=$OLDIFS

rm -f ${MAIN_GOPATH}/bin/${TOOL}
cp bin/${TOOL} ${MAIN_GOPATH}/bin/

# Done!
echo
echo "==> Results:"
ls -hl bin/