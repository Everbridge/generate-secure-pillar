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
	"io"
	"os"
	"path/filepath"

	"github.com/Everbridge/generate-secure-pillar/pki"
	"github.com/Everbridge/generate-secure-pillar/sls"
	"github.com/Everbridge/generate-secure-pillar/utils"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

const count = "count"

var verbose bool

// KeysOpts is the fully-resolved input set for the keys command.
type KeysOpts struct {
	Crypter         pki.Crypter
	Subcommand      string
	InputFilePath   string
	RecurseDir      string
	YamlPath        string
	TopLevelElement string
	Verbose         bool
	Out             io.Writer // where "all" and verbose "count" output is written
}

// KeysResult communicates the key count back to the caller so the cobra
// wrapper can encode it in the exit status when the count subcommand is used.
type KeysResult struct {
	KeyCount int
}

// runKeys is the testable handler body.
func runKeys(opts KeysOpts) (KeysResult, error) {
	var res KeysResult
	if opts.Out == nil {
		opts.Out = io.Discard
	}
	if utils.ContainsDirectoryTraversal(opts.InputFilePath) {
		return res, fmt.Errorf("keys: invalid input file path - directory traversal detected in %s", opts.InputFilePath)
	}
	if utils.ContainsDirectoryTraversal(opts.RecurseDir) {
		return res, fmt.Errorf("keys: invalid directory path - directory traversal detected in %s", opts.RecurseDir)
	}

	inputPath, err := filepath.Abs(opts.InputFilePath)
	if err != nil {
		return res, fmt.Errorf("keys: failed to resolve absolute path for input file: %w", err)
	}

	switch opts.Subcommand {
	case all:
		if inputPath == os.Stdin.Name() && !stdinIsPiped() {
			logger.Info().Msgf("reading from %s", os.Stdin.Name())
		}
		s := sls.New(inputPath, opts.Crypter, opts.TopLevelElement)
		if s.IsInclude {
			return res, fmt.Errorf("keys: file %s contains include statements and cannot be processed", inputPath)
		}
		buffer, err := s.PerformAction(sls.Validate)
		if err != nil {
			return res, fmt.Errorf("keys: failed to validate PGP keys: %w", err)
		}
		fmt.Fprintf(opts.Out, "%s\n", buffer.String())
		res.KeyCount = s.KeyCount
		return res, nil
	case recurse:
		if err := utils.ProcessDir(opts.RecurseDir, ".sls", sls.Validate, os.Stdout.Name(), opts.TopLevelElement, opts.Crypter); err != nil {
			return res, recurseError{Err: err}
		}
		return res, nil
	case path:
		s := sls.New(inputPath, opts.Crypter, opts.TopLevelElement)
		if s.IsInclude {
			return res, fmt.Errorf("keys: file %s contains include statements and cannot be processed", inputPath)
		}
		utils.PathAction(&s, opts.YamlPath, sls.Validate)
		return res, nil
	case count:
		s := sls.New(inputPath, opts.Crypter, opts.TopLevelElement)
		if s.IsInclude {
			return res, fmt.Errorf("keys: file %s contains include statements and cannot be processed", inputPath)
		}
		if _, err := s.PerformAction(sls.Validate); err != nil {
			return res, fmt.Errorf("keys: failed to validate PGP keys for count: %w", err)
		}
		if opts.Verbose {
			fmt.Fprintln(opts.Out, s.KeyMeta)
		}
		res.KeyCount = s.KeyCount
		return res, nil
	default:
		return res, fmt.Errorf("keys: unknown subcommand %q", opts.Subcommand)
	}
}

// keysCmd represents the keys command
var keysCmd = &cobra.Command{
	Use:   "keys",
	Short: "show PGP key IDs used",
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
		res, err := runKeys(KeysOpts{
			Crypter:         pk,
			Subcommand:      args[0],
			InputFilePath:   inputFilePath,
			RecurseDir:      recurseDir,
			YamlPath:        yamlPath,
			TopLevelElement: topLevelElement,
			Verbose:         verbose,
			Out:             os.Stdout,
		})
		var rerr recurseError
		if errors.As(err, &rerr) {
			logger.Warn().Err(rerr.Err).Msg("keys")
			return
		}
		if err != nil {
			logger.Fatal().Err(err).Msg("keys")
		}
		if args[0] == count && res.KeyCount > 1 {
			os.Exit(res.KeyCount)
		}
	},
}

func init() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout})
	rootCmd.AddCommand(keysCmd)
	keysCmd.PersistentFlags().StringVarP(&yamlPath, "path", "p", "", "YAML path to examine")
	keysCmd.PersistentFlags().StringVarP(&recurseDir, "dir", "d", "", "recurse over all .sls files in the given directory")
	keysCmd.PersistentFlags().StringVarP(&inputFilePath, "file", "f", os.Stdin.Name(), "input file (defaults to STDIN)")
	keysCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "verbose output")
}
