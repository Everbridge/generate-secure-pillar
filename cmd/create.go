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
	"strings"

	"github.com/Everbridge/generate-secure-pillar/sls"
	"github.com/spf13/cobra"
)

// createCmd represents the create command
var createCmd = &cobra.Command{
	Use:   "create",
	Short: "create a new sls file",
	Run: func(cmd *cobra.Command, args []string) {
		outputFilePath, err := filepath.Abs(outputFilePath)
		if err != nil {
			logger.Fatal(err)
		}
		secretNames := strings.Split(strings.Trim(cmd.Flag("name").Value.String(), "[]"), ",")
		secretValues := strings.Split(strings.Trim(cmd.Flag("value").Value.String(), "[]"), ",")
		pk := getPki()
		s := sls.New(outputFilePath, pk, topLevelElement)
		err = s.ProcessYaml(secretNames, secretValues)
		if err != nil {
			logger.Fatalf("create: %s", err)
		}
		buffer, err := s.FormatBuffer("")
		if err != nil {
			logger.Fatalf("create: %s", err)
		}
		_, err = sls.WriteSlsFile(buffer, outputFilePath)
		if err != nil {
			logger.Fatalf("create: %s", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(createCmd)
	createCmd.PersistentFlags().StringVarP(&outputFilePath, "outfile", "o", os.Stdout.Name(), "output file (defaults to STDOUT)")
	createCmd.PersistentFlags().StringArrayP("name", "n", nil, "secret name(s)")
	createCmd.PersistentFlags().StringArrayP("value", "s", nil, "secret value(s)")
}
