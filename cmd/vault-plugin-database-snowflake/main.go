// Copyright 2026 Snowflake Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"log"
	"os"

	snowflake "github.com/Snowflake-Labs/snowflake-vault"
	dbplugin "github.com/hashicorp/vault/sdk/database/dbplugin/v5"
)

func main() {
	err := Run()
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
}

// Run instantiates a SnowflakeSQL object, and runs the RPC server for the plugin
func Run() error {
	dbplugin.ServeMultiplex(snowflake.New)

	return nil
}