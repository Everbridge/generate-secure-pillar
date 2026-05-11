// Package cmd implements the generate-secure-pillar CLI: cobra command
// wiring, configuration loading, and the runX handlers that each command's
// Run closure delegates to.
package cmd

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

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/Everbridge/generate-secure-pillar/pki"
	"github.com/Everbridge/generate-secure-pillar/utils"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// initLogger initializes a logger instance for the cmd package
func initLogger() zerolog.Logger {
	return zerolog.New(os.Stdout)
}

// Package-level variables for CLI configuration
// These are initialized by cobra flags and used across commands
var (
	logger = initLogger()

	// File path configuration
	inputFilePath  string
	outputFilePath = os.Stdout.Name()
	cfgFile        string
	recurseDir     string
	yamlPath       string

	// Profile and encryption configuration
	profile         string
	pgpKeyName      string
	gnupgHome       = "~/.gnupg"
	topLevelElement string

	// Operation flags
	updateInPlace bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "generate-secure-pillar",
	Short: "Create and update encrypted content or decrypt encrypted content.",
	Example: `
# specify a config profile and create a new file
$ generate-secure-pillar --profile dev create --name secret_name1 --value secret_value1 --name secret_name2 --value secret_value2 --outfile new.sls

# create a new sls file
$ generate-secure-pillar -k "Salt Master" create --name secret_name1 --value secret_value1 --name secret_name2 --value secret_value2 --outfile new.sls

# add to the new file
$ generate-secure-pillar -k "Salt Master" update --name new_secret_name --value new_secret_value --file new.sls

# update an existing value
$ generate-secure-pillar -k "Salt Master" update --name secret_name --value secret_value3 --file new.sls

# encrypt all plain text values in a file
$ generate-secure-pillar -k "Salt Master" encrypt all --file us1.sls --outfile us1.sls
# or use --update flag
$ generate-secure-pillar -k "Salt Master" encrypt all --file us1.sls --update

# encrypt all plain text values in a file under the element 'secret_stuff'
$ generate-secure-pillar -k "Salt Master" --element secret_stuff encrypt all --file us1.sls --outfile us1.sls

# recurse through all sls files, encrypting all values
$ generate-secure-pillar -k "Salt Master" encrypt recurse -d /path/to/pillar/secure/stuff

# recurse through all sls files, decrypting all values (requires secret key in gpg-agent)
$ generate-secure-pillar decrypt recurse -d /path/to/pillar/secure/stuff

# decrypt a specific existing value (requires secret key in gpg-agent)
$ generate-secure-pillar decrypt path --path "some:yaml:path" --file new.sls

# decrypt all files and re-encrypt with given key (requires secret key in gpg-agent)
$ generate-secure-pillar -k "New Salt Master Key" rotate -d /path/to/pillar/secure/stuff

# show all PGP key IDs used in a file
$ generate-secure-pillar keys all --file us1.sls

# show all keys used in all files in a given directory
$ generate-secure-pillar keys recurse -d /path/to/pillar/secure/stuff

# show the PGP Key ID used for an element at a path in a file
$ generate-secure-pillar keys path --path "some:yaml:path" --file new.sls
`,
	Version: "2.0.1",
}

const all = "all"
const recurse = "recurse"
const path = "path"

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		logger.Error().Err(err).Msg("Command execution failed")
		os.Exit(1)
	}
}

func init() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout})
	cobra.OnInitialize(initConfig)

	// respect the env var if set
	gpgHomeEnv := os.Getenv("GNUPGHOME")
	if gpgHomeEnv != "" {
		gnupgHome = gpgHomeEnv
	}

	rootCmd.PersistentFlags().Bool("version", false, "print the version")
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.config/generate-secure-pillar/config.yaml)")
	rootCmd.PersistentFlags().StringVar(&profile, "profile", "", "profile name from profile specified in the config file")
	rootCmd.PersistentFlags().StringVarP(&pgpKeyName, "pgp_key", "k", pgpKeyName, "PGP key name, email, or ID to use for encryption")
	rootCmd.PersistentFlags().StringVar(&gnupgHome, "gnupg-home", gnupgHome, "GnuPG home directory (default is $HOME/.gnupg)")
	rootCmd.PersistentFlags().StringVarP(&topLevelElement, "element", "e", "", "Name of the top level element under which encrypted key/value pairs are kept")
}

// recurseError wraps errors from the recurse subcommand so the cobra wrapper
// can downgrade them from Fatal to Warn. This preserves the historical
// behavior where partial failures during recurse don't kill the process,
// while still letting tests inspect the error returned by the handler.
type recurseError struct{ Err error }

func (r recurseError) Error() string { return r.Err.Error() }
func (r recurseError) Unwrap() error { return r.Err }

// initConfig is the cobra-compatible callback. It defers to initConfigE and
// halts the process on error.
func initConfig() {
	if err := initConfigE(); err != nil {
		logger.Fatal().Err(err).Msg("config initialization failed")
	}
}

// initConfigE reads in config file and ENV variables if set, returning the
// first error encountered instead of calling logger.Fatal. Split out from
// initConfig so tests can drive it without subprocess execution.
func initConfigE() error {
	if cfgFile != "" {
		if utils.ContainsDirectoryTraversal(cfgFile) {
			return fmt.Errorf("invalid config file path: directory traversal detected in %s", cfgFile)
		}
		viper.SetConfigFile(cfgFile)
	} else {
		home, err := homedir.Dir()
		if err != nil {
			return fmt.Errorf("failed to determine home directory: %w", err)
		}

		configPath := fmt.Sprintf("%s/.config/generate-secure-pillar/", home)
		dir := filepath.Clean(configPath)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("error creating config file path: %w", err)
		}
		configFile, err := os.OpenFile(dir+"/config.yaml", os.O_RDONLY|os.O_CREATE, 0660)
		if err != nil {
			return fmt.Errorf("error creating config file: %w", err)
		}
		defer configFile.Close()

		viper.AddConfigPath(configPath)
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		return fmt.Errorf("fatal error config file: %w", err)
	}
	return readProfileE()
}

// getPki constructs a Pki from the current pgpKeyName/gnupgHome globals.
// Returns an error so tests can verify failure modes without process exit.
func getPki() (*pki.Pki, error) {
	return pki.New(pgpKeyName, gnupgHome)
}

// readProfileE applies the active profile (or default) from viper to the
// pgpKeyName/gnupgHome globals. Returns an error instead of warning so callers
// (and tests) can react to malformed config.
func readProfileE() error {
	if !viper.IsSet("profiles") {
		return nil
	}
	profiles := viper.Get("profiles")
	profName := ""
	if rootCmd.Flag("profile") != nil && rootCmd.Flag("profile").Value != nil {
		profName = rootCmd.Flag("profile").Value.String()
	}

	if profName == "" && pgpKeyName != "" {
		return nil
	}

	profileList, ok := profiles.([]interface{})
	if !ok {
		return fmt.Errorf("profiles configuration is not a valid array")
	}
	for _, prof := range profileList {
		profileMap, ok := prof.(map[string]interface{})
		if !ok {
			logger.Warn().Msg("profile entry is not a valid map")
			continue
		}
		if profileMap["default"] != true && profName != profileMap["name"] {
			continue
		}
		if gnupgHomeVal, exists := profileMap["gnupg_home"]; exists {
			if gpgHome, ok := gnupgHomeVal.(string); ok && gpgHome != "" {
				if utils.ContainsDirectoryTraversal(gpgHome) {
					logger.Warn().Msgf("Invalid gnupg_home path: directory traversal detected in %s", gpgHome)
					continue
				}
				gnupgHome = gpgHome
			}
		}
		if defaultKeyVal, exists := profileMap["default_key"]; exists && defaultKeyVal != nil {
			if defaultKey, ok := defaultKeyVal.(string); ok {
				pgpKeyName = defaultKey
			}
		}
	}
	return nil
}

// if we are getting stdin from a pipe we don't want
// to output log info about it that could mess up parsing
func stdinIsPiped() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		// Log error but don't use Fatal as this could be recoverable
		logger.Error().Err(err).Msg("Error checking stdin status")
		// assume we are piped if we can't determine
		return true
	}
	if fi != nil {
		return ((fi.Mode() & os.ModeCharDevice) == 0)
	}

	// if something goes wrong assume we are piped
	return true
}
