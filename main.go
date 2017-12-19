package main

import (
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"

	"github.com/urfave/cli"
)

var secretsString string
var inputFilePath string
var outputFilePath = os.Stdout.Name()
var pgpKeyName string
var secretName string
var publicKeyRing string
var secureKeyRing string
var debug bool
var recurseDir string

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

// SecurePillar secure pillar vars
type SecurePillar map[string]interface{}

func main() {
	if debug {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	}
	app := cli.NewApp()
	app.Version = "1.0"
	app.Authors = []cli.Author{
		cli.Author{
			Name:  "Ed Silva",
			Email: "ed.silva@everbridge.com",
		},
	}

	cli.AppHelpTemplate = fmt.Sprintf(`%s
EXAMPLES:
# create a new sls file
$ ./generate-secure-pillar -k "Salt Master" create --secret_name secret_name --secret_value secret_value --outfile new.sls

# add to the new file
$ ./generate-secure-pillar -k "Salt Master" update --secret_name new_secret_name --secret_value new_secret_value --file new.sls

# update an existing value
$ ./generate-secure-pillar -k "Salt Master" update --secret_name secret_name --secret_value secret_value3 --file new.sls

# encrypt all plain text values in a file
$ ./generate-secure-pillar -k "Salt Master" encrypt all --file us1.sls --outfile us1.sls

# recurse through all sls files, creating new encrypted files with a .new extension
$ ./generate-secure-pillar -k "Salt Master" encrypt recurse /path/to/pillar/secure/stuff`, cli.AppHelpTemplate)

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
				var securePillar SecurePillar
				cipherText := encryptSecret(secretsString)
				securePillar["secure_vars"].(map[string]interface{})[secretName] = cipherText
				buffer := formatBuffer(securePillar)
				writeSlsFile(buffer, outputFilePath)
				return nil
			},
			Flags: []cli.Flag{
				outputFlag,
				cli.StringFlag{
					Name:        "secure_name, n",
					Usage:       "secure variable name",
					Destination: &secretName,
				},
				cli.StringFlag{
					Name:        "secret_value, s",
					Usage:       "secret string value to be encrypted",
					Destination: &secretsString,
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
					Name:        "secure_name, n",
					Usage:       "secure variable name",
					Destination: &secretName,
				},
				cli.StringFlag{
					Name:        "secret_value, s",
					Usage:       "secret string value to be encrypted",
					Destination: &secretsString,
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
							log.Fatal(err)
						}
						if info.IsDir() {
							slsFiles := findSlsFiles(recurseDir)
							for _, file := range slsFiles {
								pillar := readSlsFile(file)
								if len(pillar["secure_vars"].(map[string]interface{})) > 0 {
									buffer := pillarBuffer(file, true)
									writeSlsFile(buffer, fmt.Sprintf("%s.new", file))
								}
							}
						} else {
							log.Fatal(fmt.Sprintf("%s is not a directory", info.Name()))
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
		log.Fatal(err)
	}
}
