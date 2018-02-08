package main

import (
	"fmt"
	"os"

	"eb-github.com/ed-silva/generate-secure-pillar/sls"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

var logger = logrus.New()

var inputFilePath string
var outputFilePath = os.Stdout.Name()
var pgpKeyName string
var publicKeyRing = ""
var secretKeyRing = ""
var debug bool
var recurseDir string
var secretNames cli.StringSlice
var secretValues cli.StringSlice
var topLevelElement string

var defaultPubRing = "~/.gnupg/pubring.gpg"
var defaultSecRing = "~/.gnupg/secring.gpg"
var defaultElement = "secure_vars"

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

func main() {
	if debug {
		logger.Level = logrus.DebugLevel
	}
	app := cli.NewApp()
	app.Version = "1.0.91"
	app.Authors = []cli.Author{
		cli.Author{
			Name:  "Ed Silva",
			Email: "ed.silva@everbridge.com",
		},
	}

	cli.AppHelpTemplate = fmt.Sprintf(`%s
SLS FORMAT:
This tool assumes a top level element in .sls files (named 'secure_vars' by default)
under which are the key/value pairs meant to be secured. The reson for this
is so that the files in question can easily have a mix of plain text and
secured/encrypted values in an organized way, allowing for the bulk encryption
or decryption of just those values (useful for automation).

The name of the top level element can be specified using the --element flag.

SAMPLE SLS FILE FORMAT:

$ cat example.sls
#!yaml|gpg

key: value
secure_vars:
  password: secret
  api_key: key_value


EXAMPLES:
# create a new sls file
$ generate-secure-pillar -k "Salt Master" create --name secret_name1 --value secret_value1 --name secret_name2 --value secret_value2 --outfile new.sls

# add to the new file
$ generate-secure-pillar -k "Salt Master" update --name new_secret_name --value new_secret_value --file new.sls --outfile new.sls

# update an existing value
$ generate-secure-pillar -k "Salt Master" update --name secret_name --value secret_value3 --file new.sls --outfile new.sls

# encrypt all plain text values in a file
$ generate-secure-pillar -k "Salt Master" encrypt all --file us1.sls --outfile us1.sls

# encrypt all plain text values in a file under the element 'secret_stuff'
$ generate-secure-pillar -k "Salt Master" --element secret_stuff encrypt all --file us1.sls --outfile us1.sls

# recurse through all sls files, encrypting all key/value pairs under top level secure_vars element
$ generate-secure-pillar -k "Salt Master" encrypt recurse -d /path/to/pillar/secure/stuff

# recurse through all sls files, decrypting all key/value pairs under top level secure_vars element
$ generate-secure-pillar -k "Salt Master" decrypt recurse -d /path/to/pillar/secure/stuff

`, cli.AppHelpTemplate)

	app.Copyright = "(c) 2018 Everbridge, Inc."
	app.Usage = "Create and update encrypted content or decrypt encrypted content."
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
			Destination: &secretKeyRing,
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
		cli.StringFlag{
			Name:        "element, e",
			Value:       defaultElement,
			Usage:       "Name of the top level element under which encrypted key/value pairs are kept",
			Destination: &topLevelElement,
		},
	}

	app.Commands = []cli.Command{
		{
			Name:    "create",
			Aliases: []string{"c"},
			Usage:   "create a new sls file",
			Action: func(c *cli.Context) error {
				s := sls.New(secretNames, secretValues, topLevelElement, publicKeyRing, secretKeyRing, pgpKeyName, logger)
				s.ProcessYaml()
				buffer := s.FormatBuffer()
				s.WriteSlsFile(buffer, outputFilePath)
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
				s := sls.New(secretNames, secretValues, topLevelElement, publicKeyRing, secretKeyRing, pgpKeyName, logger)
				buffer := s.YamlBuffer(inputFilePath, false)
				s.WriteSlsFile(buffer, outputFilePath)
				return nil
			},
			Flags: []cli.Flag{
				inputFlag,
				cli.StringSliceFlag{
					Name:  "name, n",
					Usage: "secret name",
					Value: &secretNames,
				},
				cli.StringSliceFlag{
					Name:  "value, s",
					Usage: "secret value",
					Value: &secretValues,
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
						s := sls.New(secretNames, secretValues, topLevelElement, publicKeyRing, secretKeyRing, pgpKeyName, logger)
						if inputFilePath != os.Stdin.Name() && outputFilePath == "" {
							outputFilePath = inputFilePath
						}
						buffer := s.YamlBuffer(inputFilePath, true)
						s.WriteSlsFile(buffer, outputFilePath)
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
						s := sls.New(secretNames, secretValues, topLevelElement, publicKeyRing, secretKeyRing, pgpKeyName, logger)
						s.ProcessDir(recurseDir, "encrypt")
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
				s := sls.New(secretNames, secretValues, topLevelElement, publicKeyRing, secretKeyRing, pgpKeyName, logger)
				buffer := s.PlainTextYamlBuffer(inputFilePath)
				s.WriteSlsFile(buffer, outputFilePath)
				return nil
			},
			Subcommands: []cli.Command{
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
						s := sls.New(secretNames, secretValues, topLevelElement, publicKeyRing, secretKeyRing, pgpKeyName, logger)
						s.ProcessDir(recurseDir, "decrypt")
						return nil
					},
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		logger.Fatal(err)
	}
}
