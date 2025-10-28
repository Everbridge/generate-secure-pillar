# generate-secure-pillar

[![Go Report Card](https://goreportcard.com/badge/github.com/Everbridge/generate-secure-pillar)](https://goreportcard.com/report/github.com/Everbridge/generate-secure-pillar)

## Create and update encrypted content or decrypt encrypted content in YAML files

<https://blog.edlitmus.info/generate-secure-pillar/>

## USAGE

   generate-secure-pillar [command] [flags]

## VERSION 1.0.640

## AUTHOR

   Ed Silva <ed.silva@everbridge.com>

## HOMEBREW INSTALL

``` shell
brew tap esilva-everbridge/homebrew-generate-secure-pillar
brew install generate-secure-pillar
```

## CONFIG FILE USAGE

A config file can be used to set default values, and an example file is created if there isn't one already, with commented out values. The file location defaults to `~/.config/generate-secure-pillar/config.yaml`.
Profiles can be specified and selected via a command line option.

``` yaml
profiles:
  - name: dev
    default: true
    default_key: Dev Salt Master
    gnupg_home: ~/.gnupg
  - name: prod
    default: false
    default_key: Prod Salt Master
    gnupg_home: ~/.gnupg
...
```

## ABOUT PGP KEYS

The PGP keys you import for use with this tool need to be 'trusted' keys.
An easy way to do this is, after importing a key, run the following commands:

``` shell
expect -c "spawn gpg --edit-key '<the PGP key id here>' trust quit; send \"5\ry\r\"; expect eof"
```

(found here: <https://gist.github.com/chrisroos/1205934#gistcomment-2203760)>

## COMMANDS

```text
     completion  Generate the autocompletion script for the specified shell
     create      create a new sls file
     decrypt     perform decryption operations
     encrypt     perform encryption operations
     help        Help about any command
     keys        show PGP key IDs used
     rotate      decrypt existing files and re-encrypt with a new key
     update      update the value of the given key in the given file
```

## GLOBAL OPTIONS

- `--config string`            config file (default is $HOME/.config/generate-secure-pillar/config.yaml)
- `--profile string`           profile name from profile specified in the config file
- `--pubring string`           PGP public keyring (default is $HOME/.gnupg/pubring.gpg)
- `--secring string`           PGP private keyring (default is $HOME/.gnupg/secring.gpg)  
- `-k, --pgp_key string`       PGP key name, email, or ID to use for encryption
- `-e, --element string`       Name of the top level element under which encrypted key/value pairs are kept
- `-h, --help`                 help for generate-secure-pillar
- `--version`                  print the version

## COPYRIGHT

   (c) 2018 Everbridge, Inc.

**CAVEAT: YAML files with include statements are not handled properly, so we skip them.**

## EXAMPLES

### specify a config profile and create a new file

```bash
$ generate-secure-pillar --profile dev create -n secret_name1 -s secret_value1 -n secret_name2 -s secret_value2 -o new.sls
```

### create a new sls file

```bash
$ generate-secure-pillar -k "Salt Master" create -n secret_name1 -s secret_value1 -n secret_name2 -s secret_value2 -o new.sls
```

### add to the new file

```bash
$ generate-secure-pillar -k "Salt Master" update -n new_secret_name -s new_secret_value -f new.sls
```

### update an existing value

```bash
$ generate-secure-pillar -k "Salt Master" update -n secret_name -s secret_value3 -f new.sls
```

### encrypt all plain text values in a file

```bash
$ generate-secure-pillar -k "Salt Master" encrypt all -f us1.sls -o us1.sls
```

### or use --update flag

```bash
$ generate-secure-pillar -k "Salt Master" encrypt all -f us1.sls --update
```

### encrypt all plain text values in a file under the element 'secret_stuff'

```bash
$ generate-secure-pillar -k "Salt Master" --element secret_stuff encrypt all -f us1.sls -o us1.sls
```

### recurse through all sls files, encrypting all values

```bash
$ generate-secure-pillar -k "Salt Master" encrypt recurse -d /path/to/pillar/secure/stuff
```

### recurse through all sls files, decrypting all values (requires imported private key)

```bash
$ generate-secure-pillar decrypt recurse -d /path/to/pillar/secure/stuff
```

### decrypt a specific existing value (requires imported private key)

```bash
$ generate-secure-pillar decrypt path --path "some:yaml:path" -f new.sls
```

### decrypt all files and re-encrypt with given key (requires imported private key)

```bash
$ generate-secure-pillar -k "New Salt Master Key" rotate -d /path/to/pillar/secure/stuff
```

### show all PGP key IDs used in a file

```bash
$ generate-secure-pillar keys all -f us1.sls
```

### show all keys used in all files in a given directory

```bash
$ generate-secure-pillar keys recurse -d /path/to/pillar/secure/stuff
```

### show the PGP key ID used for an element at a path in a file

```bash
$ generate-secure-pillar keys path --path "some:yaml:path" -f new.sls
```
