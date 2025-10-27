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

// Package cmd/update handles the updating of existing secure pillar files
package cmd

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/Everbridge/generate-secure-pillar/sls"
	"github.com/Everbridge/generate-secure-pillar/utils"
	"github.com/spf13/cobra"
)

// updateCmd represents the update command
var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "update the value of the given key in the given file",
	Run: func(cmd *cobra.Command, args []string) {
		// Validate path for directory traversal attacks
		if utils.ContainsDirectoryTraversal(inputFilePath) {
			logger.Fatal().Msgf("update: invalid file path - directory traversal detected in %s", inputFilePath)
		}

		inputFilePath, err := filepath.Abs(inputFilePath)
		if err != nil {
			logger.Fatal().Err(err).Msg("update: failed to resolve input file path")
		}
		if inputFilePath != os.Stdin.Name() {
			outputFilePath = inputFilePath
		}

		// Parse secret names and values with proper trimming
		nameStr := strings.TrimSpace(cmd.Flag("name").Value.String())
		valueStr := strings.TrimSpace(cmd.Flag("value").Value.String())

		// Remove surrounding brackets if present
		nameStr = strings.Trim(nameStr, "[]")
		valueStr = strings.Trim(valueStr, "[]")

		secretNames := strings.Split(nameStr, ",")
		secretValues := strings.Split(valueStr, ",")

		// Trim whitespace from individual elements
		for i := range secretNames {
			secretNames[i] = strings.TrimSpace(secretNames[i])
		}
		for i := range secretValues {
			secretValues[i] = strings.TrimSpace(secretValues[i])
		}

		// Validate input arrays
		if len(secretNames) == 0 {
			logger.Fatal().Msg("update: no secret names provided")
		}
		if len(secretValues) == 0 {
			logger.Fatal().Msg("update: no secret values provided")
		}
		if len(secretNames) != len(secretValues) {
			logger.Fatal().Msgf("update: mismatch between number of names (%d) and values (%d)", len(secretNames), len(secretValues))
		}

		// Check for empty names or values
		for i, name := range secretNames {
			if strings.TrimSpace(name) == "" {
				logger.Fatal().Msgf("update: secret name at position %d is empty", i+1)
			}
		}

		pk := getPki()
		s := sls.New(inputFilePath, *pk, topLevelElement)

		// Check if the file contains include statements (not supported)
		if s.IsInclude {
			logger.Fatal().Msgf("update: file %s contains include statements and cannot be processed", inputFilePath)
		}

		err = s.ProcessYaml(secretNames, secretValues)
		if err != nil {
			logger.Fatal().Err(err).Msg("update: failed to process YAML")
		}
		buffer, err := s.FormatBuffer("")
		if err != nil {
			logger.Fatal().Err(err).Msg("update: failed to format buffer")
		}
		_, err = sls.WriteSlsFile(buffer, outputFilePath)
		if err != nil {
			logger.Fatal().Err(err).Msg("update: failed to write output file")
		}
	},
}

func init() {
	rootCmd.AddCommand(updateCmd)
	updateCmd.PersistentFlags().StringVarP(&inputFilePath, "file", "f", os.Stdin.Name(), "input file (defaults to STDIN)")
	updateCmd.PersistentFlags().StringArrayP("name", "n", nil, "secret name(s)")
	updateCmd.PersistentFlags().StringArrayP("value", "s", nil, "secret value(s)")
}
