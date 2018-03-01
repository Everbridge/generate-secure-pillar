NAME:
   generate-secure-pillar - Create and update encrypted content or decrypt encrypted content.

USAGE:
   generate-secure-pillar [global options] command [command options] [arguments...]

VERSION:
   1.0.156

AUTHOR:
   Ed Silva <ed.silva@everbridge.com>

COMMANDS:
     create, c   create a new sls file
     update, u   update the value of the given key in the given file
     encrypt, e  perform encryption operations
     decrypt, d  perform decryption operations
     rotate, r   decrypt existing files and re-encrypt with a new key
     help, h     Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --pubring value, --pub value  PGP public keyring (default: "~/.gnupg/pubring.gpg")
   --secring value, --sec value  PGP private keyring (default: "~/.gnupg/secring.gpg")
   --pgp_key value, -k value     PGP key name, email, or ID to use for encryption
   --debug                       adds line number info to log output
   --element value, -e value     Name of the top level element under which encrypted key/value pairs are kept
   --help, -h                    show help
   --version, -v                 print the version

COPYRIGHT:
   (c) 2018 Everbridge, Inc.

CAVEAT: YAML files with include statements are not handled properly.

EXAMPLES:
# create a new sls file
$ generate-secure-pillar -k "Salt Master" create --name secret_name1 --value secret_value1 --name secret_name2 --value secret_value2 --outfile new.sls

# add to the new file
$ generate-secure-pillar -k "Salt Master" update --name new_secret_name --value new_secret_value --file new.sls

# update an existing value
$ generate-secure-pillar -k "Salt Master" update --name secret_name --value secret_value3 --file new.sls

# encrypt all plain text values in a file
$ generate-secure-pillar -k "Salt Master" encrypt all --file us1.sls --outfile us1.sls

# encrypt all plain text values in a file under the element 'secret_stuff'
$ generate-secure-pillar -k "Salt Master" --element secret_stuff encrypt all --file us1.sls --outfile us1.sls

# recurse through all sls files, encrypting all values
$ generate-secure-pillar -k "Salt Master" encrypt recurse -d /path/to/pillar/secure/stuff

# recurse through all sls files, decrypting all values (requires imported private key)
$ generate-secure-pillar decrypt recurse -d /path/to/pillar/secure/stuff

# decrypt a specific existing value (requires imported private key)
$ generate-secure-pillar decrypt path --path "some:yaml:path" --file new.sls

