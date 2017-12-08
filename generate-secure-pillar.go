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

const pgpHeader = "-----BEGIN PGP MESSAGE-----"

// SecurePillar secure pillar vars
type SecurePillar struct {
	SecureVars map[string]string `yaml:"secure_vars"`
}

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
		cli.Command{
			Name:    "create",
			Aliases: []string{"e"},
			Usage:   "create a new sls file",
			Action: func(c *cli.Context) error {
				var securePillar SecurePillar
				securePillar.SecureVars = make(map[string]string)
				cipherText := encryptSecret(secretsString)
				securePillar.SecureVars[secretName] = cipherText
				buffer := formatBuffer(securePillar)
				writeSlsFile(buffer, outputFilePath)
				return nil
			},
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:        "outfile, o",
					Value:       os.Stdout.Name(),
					Usage:       "path to a file to be written (defaults to STDOUT)",
					Destination: &outputFilePath,
				},
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
		cli.Command{
			Name:    "update",
			Aliases: []string{"e"},
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
				cli.StringFlag{
					Name:        "file, f",
					Value:       os.Stdin.Name(),
					Usage:       "encrypt all unencrypted values in the given file (defaults to STDIN)",
					Destination: &inputFilePath,
				},
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
		cli.Command{
			Name:    "encrypt",
			Aliases: []string{"e"},
			Usage:   "perform encryption operations",
			Action: func(c *cli.Context) error {
				return nil
			},
			Subcommands: cli.Commands{
				cli.Command{
					Name: "all",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:        "file, f",
							Value:       os.Stdin.Name(),
							Usage:       "encrypt all unencrypted values in the given file (defaults to STDIN)",
							Destination: &inputFilePath,
						},
						cli.StringFlag{
							Name:        "outfile, o",
							Value:       os.Stdout.Name(),
							Usage:       "path to a file to be written (defaults to STDOUT)",
							Destination: &outputFilePath,
						},
					},
					Action: func(c *cli.Context) error {
						if inputFilePath != os.Stdin.Name() && outputFilePath == "" {
							outputFilePath = inputFilePath
						}
						buffer := pillarBuffer(inputFilePath, true)
						writeSlsFile(buffer, outputFilePath)
						return nil
					},
				},
				cli.Command{
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
								if len(pillar.SecureVars) > 0 {
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
		cli.Command{
			Name:    "decrypt",
			Aliases: []string{"d"},
			Usage:   "perform decryption operations",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:        "file, f",
					Value:       os.Stdin.Name(),
					Usage:       "decrypt all encrypted values in the given file (defaults to STDIN)",
					Destination: &inputFilePath,
				},
				cli.StringFlag{
					Name:        "outfile, o",
					Value:       os.Stdout.Name(),
					Usage:       "path to a file to be written (defaults to STDOUT)",
					Destination: &outputFilePath,
				},
			},
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
