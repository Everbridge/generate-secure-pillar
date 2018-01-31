NAME:
   generate-secure-pillar - add or update secure salt pillar content

USAGE:
   generate-secure-pillar [global options] command [command options] [arguments...]

VERSION:
   1.0.73

AUTHOR:
   Ed Silva <ed.silva@everbridge.com>

COMMANDS:
     create, c   create a new sls file
     update, u   update the value of the given key in the given file
     encrypt, e  perform encryption operations
     decrypt, d  perform decryption operations
     help, h     Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --pubring value, --pub value  PGP public keyring (default: "~/.gnupg/pubring.gpg")
   --secring value, --sec value  PGP private keyring (default: "~/.gnupg/secring.gpg")
   --pgp_key value, -k value     PGP key name, email, or ID to use for encryption
   --debug                       adds line number info to log output
   --help, -h                    show help
   --version, -v                 print the version

COPYRIGHT:
   (c) 2017 Everbridge, Inc.

SLS FORMAT:
This tool assumes a top level element in .sls files named 'secure_vars'
under which are the key/value pairs meant to be secured. The reson for this
is so that the files in question can easily have a mix of plain text and
secured/encrypted values in an organized way, allowing for the bulk encryption
or decryption of just those values (useful for automation).

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

# recurse through all sls files, encrypting all key/value pairs under top level secure_vars element
$ generate-secure-pillar -k "Salt Master" encrypt recurse -d /path/to/pillar/secure/stuff

# recurse through all sls files, decrypting all key/value pairs under top level secure_vars element
$ generate-secure-pillar -k "Salt Master" decrypt recurse -d /path/to/pillar/secure/stuff

