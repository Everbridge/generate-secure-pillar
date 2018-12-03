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
	"os"
	"path/filepath"

	"github.com/Everbridge/generate-secure-pillar/sls"
	"github.com/Everbridge/generate-secure-pillar/utils"
	"github.com/spf13/cobra"
)

// decryptCmd represents the decrypt command
var decryptCmd = &cobra.Command{
	Use:   "decrypt",
	Short: "perform decryption operations",
	Run: func(cmd *cobra.Command, args []string) {
		pk := getPki()
		outputFilePath, err := filepath.Abs(outputFilePath)
		if err != nil {
			logger.Fatal(err)
		}
		inputFilePath, err := filepath.Abs(inputFilePath)
		if err != nil {
			logger.Fatal(err)
		}

		// process args
		switch args[0] {
		case all:
			if inputFilePath == os.Stdin.Name() {
				logger.Infof("reading from %s", os.Stdin.Name())
			}
			s := sls.New(inputFilePath, pk, topLevelElement)
			if inputFilePath != os.Stdin.Name() && updateInPlace {
				outputFilePath = inputFilePath
			}
			buffer, err := s.PerformAction("decrypt")
			utils.SafeWrite(buffer, outputFilePath, err)
		case recurse:
			err := utils.ProcessDir(recurseDir, ".sls", "decrypt", outputFilePath, topLevelElement, pk)
			if err != nil {
				logger.Warnf("decrypt: %s", err)
			}
		case path:
			s := sls.New(inputFilePath, pk, topLevelElement)
			utils.PathAction(&s, yamlPath, "decrypt")
		default:
			logger.Fatalf("unknown argument: '%s'", args[0])
		}
	},
}

func init() {
	rootCmd.AddCommand(decryptCmd)
	decryptCmd.PersistentFlags().StringVarP(&yamlPath, "path", "p", "", "YAML path to decrypt")
	decryptCmd.PersistentFlags().StringVarP(&recurseDir, "dir", "d", "", "recurse over all .sls files in the given directory")
	decryptCmd.PersistentFlags().StringVarP(&inputFilePath, "file", "f", os.Stdin.Name(), "input file (defaults to STDIN)")
	decryptCmd.PersistentFlags().StringVarP(&outputFilePath, "outfile", "o", os.Stdout.Name(), "output file (defaults to STDOUT)")
	decryptCmd.PersistentFlags().BoolVarP(&updateInPlace, "update", "u", false, "update the input file")
}
