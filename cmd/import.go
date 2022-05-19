// Copyright © 2021 Everbridge, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package cmd

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/Everbridge/generate-secure-pillar/pki"
	"github.com/spf13/cobra"
)

// importCmd represents the import command
// TODO: is this correct? verify after implimenting
var importCmd = &cobra.Command{
	Use:   "import",
	Short: "Import PGP keys",
	Long: `Import the PGP public and secret keys needed for your various environments.

This bypasses the need for the GnuPG keyring to have the keys imported prior to use.
The keys will be stored with restrictive permissions in the ~/.config/generate-secure-pillar/keys/ directory.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("import called")
		profile := strings.Trim(cmd.Flag("profile").Value.String(), "[]")
		secKey := strings.Trim(cmd.Flag("seckey").Value.String(), "[]")
		pubKey := strings.Trim(cmd.Flag("pubkey").Value.String(), "[]")

		fmt.Printf("profile: %v\n", profile)
		fmt.Printf("seckey: %v\n", secKey)
		fmt.Printf("pubkey: %v\n", pubKey)

		fullPath, err := filepath.Abs(secKey)
		if err != nil {
			logger.Fatalf("import: %s", err)
		}

		secring, err := pki.ReadKeyRing(fullPath)
		if err != nil {
			logger.Fatalf("import: %s", err)
		}
		fmt.Printf("%v\n", secring)
	},
}

func init() {
	rootCmd.AddCommand(importCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	importCmd.PersistentFlags().String("profile", "p", "The profile name to associate the keys with")
	importCmd.PersistentFlags().String("seckey", "", "secret key files to import")
	importCmd.PersistentFlags().String("pubkey", "", "public key files to import")
}
