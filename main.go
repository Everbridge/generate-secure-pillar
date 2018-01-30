package main

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
	"menteslibres.net/gosexy/yaml"
)

var logger = logrus.New()

var secretValue string
var inputFilePath string
var outputFilePath = os.Stdout.Name()
var pgpKeyName string
var secretName string
var publicKeyRing string
var secureKeyRing string
var debug bool
var recurseDir string
var secretNames cli.StringSlice
var secretValues cli.StringSlice

var usr, _ = user.Current()
var defaultPubRing = filepath.Join(usr.HomeDir, ".gnupg/pubring.gpg")
var defaultSecRing = filepath.Join(usr.HomeDir, ".gnupg/secring.gpg")

var inputFlag = cli.StringFlag{
	Name:        "file, f",
	Value:       os.Stdin.Name(),
	Usage:       "input file (defaults to STDIN)",
	Destination: &inputFilePath,
}

var outputFlag = cli.StringFlag{
	Name:        "outfile, o",
	Value:       os.Stdout.Name(),
	Usage:       "output file (defaults to STDOUT)",
	Destination: &outputFilePath,
}

var fileFlags = []cli.Flag{
	inputFlag,
	outputFlag,
}

const pgpHeader = "-----BEGIN PGP MESSAGE-----"

// SlsData salt pillar data
type SlsData map[interface{}]interface{}

func main() {
	if debug {
		logger.Level = logrus.DebugLevel
	}
	app := cli.NewApp()
	app.Version = "1.0.61"
	app.Authors = []cli.Author{
		cli.Author{
			Name:  "Ed Silva",
			Email: "ed.silva@everbridge.com",
		},
	}

	cli.AppHelpTemplate = fmt.Sprintf(`%s
EXAMPLES:
# create a new sls file
$ generate-secure-pillar -k "Salt Master" create --name secret_name1 --value secret_value1 --name secret_name2 --value secret_value2 --outfile new.sls

# add to the new file
$ generate-secure-pillar -k "Salt Master" update --name new_secret_name --value new_secret_value --file new.sls --outfile new.sls

# update an existing value
$ generate-secure-pillar -k "Salt Master" update --name secret_name --value secret_value3 --file new.sls --outfile new.sls

# encrypt all plain text values in a file
$ generate-secure-pillar -k "Salt Master" encrypt all --file us1.sls --outfile us1.sls

# recurse through all sls files, creating new encrypted files with a .new extension
$ generate-secure-pillar -k "Salt Master" encrypt recurse /path/to/pillar/secure/stuff`, cli.AppHelpTemplate)

	app.Copyright = "(c) 2017 Everbridge, Inc."
	app.Usage = "add or update secure salt pillar content"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:        "pubring, pub",
			Value:       defaultPubRing,
			Usage:       "PGP public keyring",
			Destination: &publicKeyRing,
		},
		cli.StringFlag{
			Name:        "secring, sec",
			Value:       defaultSecRing,
			Usage:       "PGP private keyring",
			Destination: &secureKeyRing,
		},
		cli.StringFlag{
			Name:        "pgp_key, k",
			Usage:       "PGP key name, email, or ID to use for encryption",
			Destination: &pgpKeyName,
		},
		cli.BoolFlag{
			Name:        "debug",
			Usage:       "adds line number info to log output",
			Destination: &debug,
		},
	}

	app.Commands = []cli.Command{
		{
			Name:    "create",
			Aliases: []string{"c"},
			Usage:   "create a new sls file",
			Action: func(c *cli.Context) error {
				pillar := yaml.New()
				pillar = processPillar(pillar)
				buffer := formatBuffer(pillar)
				writeSlsFile(buffer, outputFilePath)
				return nil
			},
			Flags: []cli.Flag{
				outputFlag,
				cli.StringSliceFlag{
					Name:  "name, n",
					Usage: "secret name(s)",
					Value: &secretNames,
				},
				cli.StringSliceFlag{
					Name:  "secret, s",
					Usage: "secret value(s)",
					Value: &secretValues,
				},
			},
		},
		{
			Name:    "update",
			Aliases: []string{"u"},
			Usage:   "update the value of the given key in the given file",
			Action: func(c *cli.Context) error {
				if inputFilePath != os.Stdin.Name() {
					outputFilePath = inputFilePath
				}
				buffer := pillarBuffer(inputFilePath, false)
				writeSlsFile(buffer, outputFilePath)
				return nil
			},
			Flags: []cli.Flag{
				inputFlag,
				cli.StringFlag{
					Name:        "name, n",
					Usage:       "secret name",
					Destination: &secretName,
				},
				cli.StringFlag{
					Name:        "value, s",
					Usage:       "secret value",
					Destination: &secretValue,
				},
			},
		},
		{
			Name:    "encrypt",
			Aliases: []string{"e"},
			Usage:   "perform encryption operations",
			Action: func(c *cli.Context) error {
				return nil
			},
			Subcommands: []cli.Command{
				{
					Name:  "all",
					Flags: fileFlags,
					Action: func(c *cli.Context) error {
						if inputFilePath != os.Stdin.Name() && outputFilePath == "" {
							outputFilePath = inputFilePath
						}
						buffer := pillarBuffer(inputFilePath, true)
						writeSlsFile(buffer, outputFilePath)
						return nil
					},
				},
				{
					Name: "recurse",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:        "dir, d",
							Usage:       "recurse over all .sls files in the given directory",
							Destination: &recurseDir,
						},
					},
					Action: func(c *cli.Context) error {
						info, err := os.Stat(recurseDir)
						if err != nil {
							logger.Fatalf("cannot stat %s: %s", recurseDir, err)
						}
						if info.IsDir() {
							slsFiles, count := findSlsFiles(recurseDir)
							if count == 0 {
								logger.Fatalf("%s has no sls files", recurseDir)
							}
							for _, file := range slsFiles {
								writeSlsData(file)
							}
						} else {
							logger.Fatalf("%s is not a directory", recurseDir)
						}

						return nil
					},
				},
			},
		},
		{
			Name:    "decrypt",
			Aliases: []string{"d"},
			Usage:   "perform decryption operations",
			Flags:   fileFlags,
			Action: func(c *cli.Context) error {
				buffer := plainTextPillarBuffer(inputFilePath)
				writeSlsFile(buffer, outputFilePath)
				return nil
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		logger.Fatal(err)
	}
}
