TOOL?=snowflake-vault
TEST?=$$(go list ./...)
BUILD_TAGS?=${TOOL}
GOFMT_FILES?=$$(find . -name '*.go')
PLUGIN_NAME := $(shell ls cmd/)
PLUGIN_DIR ?= $$GOPATH/vault-plugins

default: dev

# bin generates the releasable binaries for this plugin
bin: fmtcheck generate
	@CGO_ENABLED=0 BUILD_TAGS='$(BUILD_TAGS)' sh -c "'$(CURDIR)/scripts/build.sh'"

# dev creates binaries for testing Vault locally. These are put
# into ./bin/ as well as $GOPATH/bin.
dev: fmtcheck generate
	@CGO_ENABLED=0 BUILD_TAGS='$(BUILD_TAGS)' VAULT_DEV_BUILD=1 sh -c "'$(CURDIR)/scripts/build.sh'"

# test runs the unit tests and vets the code
test: fmtcheck generate
	CGO_ENABLED=0 VAULT_TOKEN= VAULT_ACC= go test -v -tags='$(BUILD_TAGS)' $(TEST) $(TESTARGS) -count=1 -timeout=20m -parallel=4

# testacc runs the acceptance tests
testacc: fmtcheck generate
	CGO_ENABLED=0 VAULT_TOKEN= VAULT_ACC=1 go test -v -tags='$(BUILD_TAGS)' $(TEST) $(TESTARGS) -count=1 -timeout=20m -parallel=4

testcompile: fmtcheck generate
	@for pkg in $(TEST) ; do \
		go test -v -c -tags='$(BUILD_TAGS)' $$pkg -parallel=4 ; \
	done

# generate runs `go generate` to build the dynamically generated source files.
generate:
	go generate $$(go list ./...)

fmtcheck:
	@sh -c "'$(CURDIR)/scripts/gofmtcheck.sh'"

fmt:
	gofmt -w $(GOFMT_FILES)

configure: dev
	./bootstrap/configure.sh \
	$(PLUGIN_DIR) \
	$(PLUGIN_NAME) \
	$(CONNECTION_URL) \
	$(PRIVATE_KEY) \
	$(SNOWFLAKE_USERNAME)

.PHONY: bin default generate test testacc testcompile fmt fmtcheck configure
