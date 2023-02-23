// Copyright © 2018 Everbridge, Inc.
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

// Package cmd/keys is for showing what PGP keys were used to encrypt data in secure pillar files
package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Everbridge/generate-secure-pillar/sls"
	"github.com/Everbridge/generate-secure-pillar/utils"
	"github.com/spf13/cobra"
)

const count = "count"

var verbose bool

// keysCmd represents the keys command
var keysCmd = &cobra.Command{
	Use:   "keys",
	Short: "show PGP key IDs used",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			err := cmd.Help()
			if err != nil {
				logger.Fatal(err)
			}
			os.Exit(0)
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		pk := getPki()
		outputFilePath = os.Stdout.Name()
		inputFilePath, err := filepath.Abs(inputFilePath)
		if err != nil {
			logger.Fatal(err)
		}

		// process args
		switch args[0] {
		case all:
			if inputFilePath == os.Stdin.Name() && !stdinIsPiped() {
				logger.Infof("reading from %s", os.Stdin.Name())
			}
			s := sls.New(inputFilePath, pk, topLevelElement)
			buffer, err := s.PerformAction("validate")
			if err != nil {
				logger.Fatal(err)
			}
			fmt.Printf("%s\n", buffer.String())
		case recurse:
			err := utils.ProcessDir(recurseDir, ".sls", "validate", outputFilePath, topLevelElement, pk)
			if err != nil {
				logger.Warnf("keys: %s", err)
			}
		case path:
			s := sls.New(inputFilePath, pk, topLevelElement)
			utils.PathAction(&s, yamlPath, "validate")
		case count:
			s := sls.New(inputFilePath, pk, topLevelElement)
			_, err := s.PerformAction("validate")
			if err != nil {
				logger.Fatal(err)
			}
			if verbose {
				fmt.Println(s.KeyMeta)
			}
			if s.KeyCount > 1 {
				os.Exit(s.KeyCount)
			}
		default:
			logger.Fatalf("unknown argument: '%s'", args[0])
		}
	},
}

func init() {
	rootCmd.AddCommand(keysCmd)
	keysCmd.PersistentFlags().StringVarP(&yamlPath, "path", "p", "", "YAML path to examine")
	keysCmd.PersistentFlags().StringVarP(&recurseDir, "dir", "d", "", "recurse over all .sls files in the given directory")
	keysCmd.PersistentFlags().StringVarP(&inputFilePath, "file", "f", os.Stdin.Name(), "input file (defaults to STDIN)")
	keysCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
}
