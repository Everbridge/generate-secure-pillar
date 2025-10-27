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

// Package cmd/encrypt handles the encryption of secure pillar files
package cmd

import (
	"os"
	"path/filepath"

	"github.com/Everbridge/generate-secure-pillar/sls"
	"github.com/Everbridge/generate-secure-pillar/utils"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// encryptCmd represents the encrypt command
var encryptCmd = &cobra.Command{
	Use:   "encrypt",
	Short: "perform encryption operations",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			err := cmd.Help()
			if err != nil {
				return err
			}
			os.Exit(0)
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		// Validate file paths for directory traversal attacks
		if utils.ContainsDirectoryTraversal(outputFilePath) {
			logger.Fatal().Msgf("encrypt: invalid output file path - directory traversal detected in %s", outputFilePath)
		}
		if utils.ContainsDirectoryTraversal(inputFilePath) {
			logger.Fatal().Msgf("encrypt: invalid input file path - directory traversal detected in %s", inputFilePath)
		}
		if utils.ContainsDirectoryTraversal(recurseDir) {
			logger.Fatal().Msgf("encrypt: invalid directory path - directory traversal detected in %s", recurseDir)
		}

		pk := getPki()
		outputFilePath, err := filepath.Abs(outputFilePath)
		if err != nil {
			logger.Fatal().Err(err).Msg("encrypt: failed to resolve absolute path for output file")
		}
		inputFilePath, err := filepath.Abs(inputFilePath)
		if err != nil {
			logger.Fatal().Err(err).Msg("encrypt: failed to resolve absolute path for input file")
		}

		// process args
		switch args[0] {
		case all:
			if inputFilePath == os.Stdin.Name() && !stdinIsPiped() {
				logger.Info().Msgf("reading from %s", os.Stdin.Name())
			}
			s := sls.New(inputFilePath, *pk, topLevelElement)

			// Check if the file contains include statements (not supported for encryption)
			if s.IsInclude {
				logger.Fatal().Msgf("encrypt: file %s contains include statements and cannot be processed", inputFilePath)
			}

			if inputFilePath != os.Stdin.Name() && updateInPlace {
				outputFilePath = inputFilePath
			}
			buffer, err := s.PerformAction("encrypt")
			utils.SafeWrite(buffer, outputFilePath, err)
		case recurse:
			err := utils.ProcessDir(recurseDir, ".sls", "encrypt", outputFilePath, topLevelElement, *pk)
			if err != nil {
				logger.Warn().Err(err).Msg("encrypt")
			}
		case path:
			s := sls.New(inputFilePath, *pk, topLevelElement)

			// Check if the file contains include statements (not supported for path operations)
			if s.IsInclude {
				logger.Fatal().Msgf("encrypt: file %s contains include statements and cannot be processed", inputFilePath)
			}

			utils.PathAction(&s, yamlPath, "encrypt")
		default:
			err = cmd.Help()
			if err != nil {
				logger.Fatal().Err(err).Msg("encrypt: failed to display help")
			}
		}
	},
}

func init() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout})
	rootCmd.AddCommand(encryptCmd)
	encryptCmd.PersistentFlags().StringVarP(&yamlPath, "path", "p", "", "YAML path to encrypt")
	encryptCmd.PersistentFlags().StringVarP(&recurseDir, "dir", "d", "", "recurse over all .sls files in the given directory")
	encryptCmd.PersistentFlags().StringVarP(&inputFilePath, "file", "f", os.Stdin.Name(), "input file (defaults to STDIN)")
	encryptCmd.PersistentFlags().StringVarP(&outputFilePath, "outfile", "o", os.Stdout.Name(), "output file (defaults to STDOUT)")
	encryptCmd.PersistentFlags().BoolVarP(&updateInPlace, "update", "u", false, "update the input file")
}
