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

// EncryptOpts is the fully-resolved input set for the encrypt command,
// extracted from cobra flags so the handler can be unit-tested.
type EncryptOpts struct {
	Crypter         pki.Crypter
	Subcommand      string
	InputFilePath   string
	OutputFilePath  string
	RecurseDir      string
	YamlPath        string
	TopLevelElement string
	UpdateInPlace   bool
}

// runEncrypt is the testable handler body. It returns errors instead of
// calling logger.Fatal so tests can drive every branch without a subprocess.
func runEncrypt(opts EncryptOpts) error {
	if utils.ContainsDirectoryTraversal(opts.OutputFilePath) {
		return fmt.Errorf("encrypt: invalid output file path - directory traversal detected in %s", opts.OutputFilePath)
	}
	if utils.ContainsDirectoryTraversal(opts.InputFilePath) {
		return fmt.Errorf("encrypt: invalid input file path - directory traversal detected in %s", opts.InputFilePath)
	}
	if utils.ContainsDirectoryTraversal(opts.RecurseDir) {
		return fmt.Errorf("encrypt: invalid directory path - directory traversal detected in %s", opts.RecurseDir)
	}

	outputPath, err := filepath.Abs(opts.OutputFilePath)
	if err != nil {
		return fmt.Errorf("encrypt: failed to resolve absolute path for output file: %w", err)
	}
	inputPath, err := filepath.Abs(opts.InputFilePath)
	if err != nil {
		return fmt.Errorf("encrypt: failed to resolve absolute path for input file: %w", err)
	}

	switch opts.Subcommand {
	case all:
		if inputPath == os.Stdin.Name() && !stdinIsPiped() {
			logger.Info().Msgf("reading from %s", os.Stdin.Name())
		}
		s := sls.New(inputPath, opts.Crypter, opts.TopLevelElement)
		if s.IsInclude {
			return fmt.Errorf("encrypt: file %s contains include statements and cannot be processed", inputPath)
		}
		if inputPath != os.Stdin.Name() && opts.UpdateInPlace {
			outputPath = inputPath
		}
		buffer, err := s.PerformAction(sls.Encrypt)
		if err != nil {
			return fmt.Errorf("encrypt: %w", err)
		}
		_, err = sls.WriteSlsFile(buffer, outputPath)
		return err
	case recurse:
		if err := utils.ProcessDir(opts.RecurseDir, ".sls", sls.Encrypt, outputPath, opts.TopLevelElement, opts.Crypter); err != nil {
			return recurseError{Err: err}
		}
		return nil
	case path:
		s := sls.New(inputPath, opts.Crypter, opts.TopLevelElement)
		if s.IsInclude {
			return fmt.Errorf("encrypt: file %s contains include statements and cannot be processed", inputPath)
		}
		utils.PathAction(&s, opts.YamlPath, sls.Encrypt)
		return nil
	default:
		return fmt.Errorf("encrypt: unknown subcommand %q", opts.Subcommand)
	}
}

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
		pk, err := getPki()
		if err != nil {
			logger.Fatal().Err(err).Msg("failed to initialize PKI")
		}
		err = runEncrypt(EncryptOpts{
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
			logger.Warn().Err(rerr.Err).Msg("encrypt")
			return
		}
		if err != nil {
			logger.Fatal().Err(err).Msg("encrypt")
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
