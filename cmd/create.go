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

// CreateOpts is the fully-resolved input set for the create command.
type CreateOpts struct {
	Crypter         pki.Crypter
	OutputFilePath  string
	TopLevelElement string
	NameStr         string // raw "name" flag value, comma-separated
	ValueStr        string // raw "value" flag value, comma-separated
}

// runCreate is the testable handler body.
func runCreate(opts CreateOpts) error {
	if utils.ContainsDirectoryTraversal(opts.OutputFilePath) {
		return fmt.Errorf("create: invalid output file path - directory traversal detected in %s", opts.OutputFilePath)
	}

	outputPath, err := filepath.Abs(opts.OutputFilePath)
	if err != nil {
		return fmt.Errorf("create: failed to resolve output file path: %w", err)
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

	// strings.Split("", ",") returns [""], so the right check is for a single
	// empty element after trimming.
	if len(secretNames) == 0 || (len(secretNames) == 1 && secretNames[0] == "") {
		return fmt.Errorf("create: no secret names provided")
	}
	// Empty values are intentionally allowed: encrypting an empty string is a
	// valid use case (placeholder secret to fill in later).
	if len(secretNames) != len(secretValues) {
		return fmt.Errorf("create: mismatch between number of names (%d) and values (%d)", len(secretNames), len(secretValues))
	}
	for i, name := range secretNames {
		if name == "" {
			return fmt.Errorf("create: secret name at position %d is empty", i+1)
		}
	}

	s := sls.New(outputPath, opts.Crypter, opts.TopLevelElement)
	if s.IsInclude {
		return fmt.Errorf("create: file %s contains include statements and cannot be processed", outputPath)
	}
	if err := s.ProcessYaml(secretNames, secretValues); err != nil {
		return fmt.Errorf("create: failed to process YAML: %w", err)
	}
	buffer, err := s.FormatBuffer("")
	if err != nil {
		return fmt.Errorf("create: failed to format buffer: %w", err)
	}
	if _, err = sls.WriteSlsFile(buffer, outputPath); err != nil {
		return fmt.Errorf("create: failed to write output file: %w", err)
	}
	return nil
}

// createCmd represents the create command
var createCmd = &cobra.Command{
	Use:   "create",
	Short: "create a new sls file",
	Run: func(cmd *cobra.Command, args []string) {
		pk, err := getPki()
		if err != nil {
			logger.Fatal().Err(err).Msg("failed to initialize PKI")
		}
		err = runCreate(CreateOpts{
			Crypter:         pk,
			OutputFilePath:  outputFilePath,
			TopLevelElement: topLevelElement,
			NameStr:         cmd.Flag("name").Value.String(),
			ValueStr:        cmd.Flag("value").Value.String(),
		})
		if err != nil {
			logger.Fatal().Err(err).Msg("create")
		}
	},
}

func init() {
	rootCmd.AddCommand(createCmd)
	createCmd.PersistentFlags().StringVarP(&outputFilePath, "outfile", "o", os.Stdout.Name(), "output file (defaults to STDOUT)")
	createCmd.PersistentFlags().StringArrayP("name", "n", nil, "secret name(s)")
	createCmd.PersistentFlags().StringArrayP("value", "s", nil, "secret value(s)")
}
