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

// Package cmd/decrypt handles the decryption of secure pillar files
package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Everbridge/generate-secure-pillar/pki"
	"github.com/Everbridge/generate-secure-pillar/sls"
	"github.com/Everbridge/generate-secure-pillar/utils"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// DecryptOpts is the fully-resolved input set for the decrypt command.
type DecryptOpts struct {
	Crypter         pki.Crypter
	Subcommand      string
	InputFilePath   string
	OutputFilePath  string
	RecurseDir      string
	YamlPath        string
	TopLevelElement string
	UpdateInPlace   bool
}

// runDecrypt is the testable handler body.
func runDecrypt(opts DecryptOpts) error {
	if utils.ContainsDirectoryTraversal(opts.OutputFilePath) {
		return fmt.Errorf("decrypt: invalid output file path - directory traversal detected in %s", opts.OutputFilePath)
	}
	if utils.ContainsDirectoryTraversal(opts.InputFilePath) {
		return fmt.Errorf("decrypt: invalid input file path - directory traversal detected in %s", opts.InputFilePath)
	}
	if utils.ContainsDirectoryTraversal(opts.RecurseDir) {
		return fmt.Errorf("decrypt: invalid directory path - directory traversal detected in %s", opts.RecurseDir)
	}

	outputPath, err := filepath.Abs(opts.OutputFilePath)
	if err != nil {
		return fmt.Errorf("decrypt: failed to resolve absolute path for output file: %w", err)
	}
	inputPath, err := filepath.Abs(opts.InputFilePath)
	if err != nil {
		return fmt.Errorf("decrypt: failed to resolve absolute path for input file: %w", err)
	}

	switch opts.Subcommand {
	case all:
		if inputPath == os.Stdin.Name() && !stdinIsPiped() {
			logger.Info().Msgf("reading from %s", os.Stdin.Name())
		}
		s := sls.New(inputPath, opts.Crypter, opts.TopLevelElement)
		if s.IsInclude {
			return fmt.Errorf("decrypt: file %s contains include statements and cannot be processed", inputPath)
		}
		if inputPath != os.Stdin.Name() && opts.UpdateInPlace {
			outputPath = inputPath
		}
		buffer, err := s.PerformAction(sls.Decrypt)
		if err != nil {
			return fmt.Errorf("decrypt: %w", err)
		}
		_, err = sls.WriteSlsFile(buffer, outputPath)
		return err
	case recurse:
		if err := utils.ProcessDir(opts.RecurseDir, ".sls", sls.Decrypt, outputPath, opts.TopLevelElement, opts.Crypter); err != nil {
			return recurseError{Err: err}
		}
		return nil
	case path:
		s := sls.New(inputPath, opts.Crypter, opts.TopLevelElement)
		if s.IsInclude {
			return fmt.Errorf("decrypt: file %s contains include statements and cannot be processed", inputPath)
		}
		utils.PathAction(&s, opts.YamlPath, sls.Decrypt)
		return nil
	default:
		return fmt.Errorf("decrypt: unknown subcommand %q", opts.Subcommand)
	}
}

// decryptCmd represents the decrypt command
var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "perform decryption operations",
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
		pk, err := getPki()
		if err != nil {
			logger.Fatal().Err(err).Msg("failed to initialize PKI")
		}
		err = runDecrypt(DecryptOpts{
			Crypter:         pk,
			Subcommand:      args[0],
			InputFilePath:   inputFilePath,
			OutputFilePath:  outputFilePath,
			RecurseDir:      recurseDir,
			YamlPath:        yamlPath,
			TopLevelElement: topLevelElement,
			UpdateInPlace:   updateInPlace,
		})
		var rerr recurseError
		if errors.As(err, &rerr) {
			logger.Warn().Err(rerr.Err).Msg("decrypt")
			return
		}
		if err != nil {
			logger.Fatal().Err(err).Msg("decrypt")
		}
	},
}

func init() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout})
	rootCmd.AddCommand(decryptCmd)
	decryptCmd.PersistentFlags().StringVarP(&yamlPath, "path", "p", "", "YAML path to decrypt")
	decryptCmd.PersistentFlags().StringVarP(&recurseDir, "dir", "d", "", "recurse over all .sls files in the given directory")
	decryptCmd.PersistentFlags().StringVarP(&inputFilePath, "file", "f", os.Stdin.Name(), "input file (defaults to STDIN)")
	decryptCmd.PersistentFlags().StringVarP(&outputFilePath, "outfile", "o", os.Stdout.Name(), "output file (defaults to STDOUT)")
	decryptCmd.PersistentFlags().BoolVarP(&updateInPlace, "update", "u", false, "update the input file")
}
