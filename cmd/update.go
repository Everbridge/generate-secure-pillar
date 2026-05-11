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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Everbridge/generate-secure-pillar/pki"
	"github.com/Everbridge/generate-secure-pillar/sls"
	"github.com/Everbridge/generate-secure-pillar/utils"
	"github.com/spf13/cobra"
)

// UpdateOpts is the fully-resolved input set for the update command.
type UpdateOpts struct {
	Crypter         pki.Crypter
	InputFilePath   string
	TopLevelElement string
	NameStr         string
	ValueStr        string
}

// runUpdate is the testable handler body.
func runUpdate(opts UpdateOpts) error {
	if utils.ContainsDirectoryTraversal(opts.InputFilePath) {
		return fmt.Errorf("update: invalid file path - directory traversal detected in %s", opts.InputFilePath)
	}

	inputPath, err := filepath.Abs(opts.InputFilePath)
	if err != nil {
		return fmt.Errorf("update: failed to resolve input file path: %w", err)
	}
	outputPath := inputPath
	if inputPath == os.Stdin.Name() {
		outputPath = outputFilePath
	}

	nameStr := strings.Trim(strings.TrimSpace(opts.NameStr), "[]")
	valueStr := strings.Trim(strings.TrimSpace(opts.ValueStr), "[]")
	secretNames := strings.Split(nameStr, ",")
	secretValues := strings.Split(valueStr, ",")
	for i := range secretNames {
		secretNames[i] = strings.TrimSpace(secretNames[i])
	}
	for i := range secretValues {
		secretValues[i] = strings.TrimSpace(secretValues[i])
	}

	if len(secretNames) == 0 || (len(secretNames) == 1 && secretNames[0] == "") {
		return fmt.Errorf("update: no secret names provided")
	}
	// Empty values are intentionally allowed for parity with the create command.
	if len(secretNames) != len(secretValues) {
		return fmt.Errorf("update: mismatch between number of names (%d) and values (%d)", len(secretNames), len(secretValues))
	}
	for i, name := range secretNames {
		if name == "" {
			return fmt.Errorf("update: secret name at position %d is empty", i+1)
		}
	}

	s := sls.New(inputPath, opts.Crypter, opts.TopLevelElement)
	if s.IsInclude {
		return fmt.Errorf("update: file %s contains include statements and cannot be processed", inputPath)
	}
	if err := s.ProcessYaml(secretNames, secretValues); err != nil {
		return fmt.Errorf("update: failed to process YAML: %w", err)
	}
	buffer, err := s.FormatBuffer("")
	if err != nil {
		return fmt.Errorf("update: failed to format buffer: %w", err)
	}
	if _, err = sls.WriteSlsFile(buffer, outputPath); err != nil {
		return fmt.Errorf("update: failed to write output file: %w", err)
	}
	return nil
}

// updateCmd represents the update command
var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "update the value of the given key in the given file",
	Run: func(cmd *cobra.Command, args []string) {
		pk, err := getPki()
		if err != nil {
			logger.Fatal().Err(err).Msg("failed to initialize PKI")
		}
		err = runUpdate(UpdateOpts{
			Crypter:         pk,
			InputFilePath:   inputFilePath,
			TopLevelElement: topLevelElement,
			NameStr:         cmd.Flag("name").Value.String(),
			ValueStr:        cmd.Flag("value").Value.String(),
		})
		if err != nil {
			logger.Fatal().Err(err).Msg("update")
		}
	},
}

func init() {
	rootCmd.AddCommand(updateCmd)
	updateCmd.PersistentFlags().StringVarP(&inputFilePath, "file", "f", os.Stdin.Name(), "input file (defaults to STDIN)")
	updateCmd.PersistentFlags().StringArrayP("name", "n", nil, "secret name(s)")
	updateCmd.PersistentFlags().StringArrayP("value", "s", nil, "secret value(s)")
}
