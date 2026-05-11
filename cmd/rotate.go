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

// Package cmd/rotate handles the rotation of PGP keys by decrypting and re-encrypting data in secure pillar files
package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/Everbridge/generate-secure-pillar/pki"
	"github.com/Everbridge/generate-secure-pillar/sls"
	"github.com/Everbridge/generate-secure-pillar/utils"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// errRotateNoInput is returned when neither a file nor a recurse directory is
// supplied to the rotate command, so the cobra wrapper can render the help
// message instead of treating it as a hard error.
var errRotateNoInput = errors.New("rotate: no input file or directory specified")

// RotateOpts is the fully-resolved input set for the rotate command.
type RotateOpts struct {
	Crypter         pki.Crypter
	InputFilePath   string
	OutputFilePath  string
	RecurseDir      string
	TopLevelElement string
}

// runRotate is the testable handler body.
func runRotate(opts RotateOpts) error {
	if utils.ContainsDirectoryTraversal(opts.InputFilePath) {
		return fmt.Errorf("rotate: invalid input file path - directory traversal detected in %s", opts.InputFilePath)
	}
	if utils.ContainsDirectoryTraversal(opts.RecurseDir) {
		return fmt.Errorf("rotate: invalid directory path - directory traversal detected in %s", opts.RecurseDir)
	}
	if utils.ContainsDirectoryTraversal(opts.OutputFilePath) {
		return fmt.Errorf("rotate: invalid output file path - directory traversal detected in %s", opts.OutputFilePath)
	}

	switch {
	case opts.RecurseDir != "":
		if err := utils.ProcessDir(opts.RecurseDir, ".sls", sls.Rotate, opts.OutputFilePath, opts.TopLevelElement, opts.Crypter); err != nil {
			return recurseError{Err: err}
		}
		return nil
	case opts.InputFilePath != "":
		s := sls.New(opts.InputFilePath, opts.Crypter, opts.TopLevelElement)
		if s.IsInclude {
			return fmt.Errorf("rotate: file %s contains include statements and cannot be processed", opts.InputFilePath)
		}
		buf, err := s.PerformAction(sls.Rotate)
		if err != nil {
			return fmt.Errorf("rotate: %w", err)
		}
		_, err = sls.WriteSlsFile(buf, opts.OutputFilePath)
		return err
	default:
		return errRotateNoInput
	}
}

// rotateCmd represents the rotate command
var rotateCmd = &cobra.Command{
	Use:   "rotate",
	Short: "decrypt existing files and re-encrypt with a new key",
	Run: func(cmd *cobra.Command, args []string) {
		pk, err := getPki()
		if err != nil {
			logger.Fatal().Err(err).Msg("failed to initialize PKI")
		}
		err = runRotate(RotateOpts{
			Crypter:         pk,
			InputFilePath:   inputFilePath,
			OutputFilePath:  outputFilePath,
			RecurseDir:      recurseDir,
			TopLevelElement: topLevelElement,
		})
		if errors.Is(err, errRotateNoInput) {
			if helpErr := cmd.Help(); helpErr != nil {
				logger.Fatal().Err(helpErr).Msg("rotate: failed to display help")
			}
			return
		}
		var rerr recurseError
		if errors.As(err, &rerr) {
			logger.Warn().Err(rerr.Err).Msg("rotate: failed to process directory")
			return
		}
		if err != nil {
			logger.Fatal().Err(err).Msg("rotate")
		}
	},
}

func init() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout})
	rootCmd.AddCommand(rotateCmd)
	rotateCmd.PersistentFlags().StringVarP(&recurseDir, "dir", "d", "", "recurse over all .sls files in the given directory")
	rotateCmd.PersistentFlags().StringVarP(&inputFilePath, "file", "f", "", "input file (defaults to STDIN)")
}
