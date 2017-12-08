NAME:
   generate-secure-pillar - add or update secure salt pillar content

USAGE:
   generate-secure-pillar [global options] command [command options] [arguments...]

VERSION:
   0.1

AUTHOR:
   Ed Silva <ed.silva@everbridge.com>

COMMANDS:
     create, e   create a new sls file
     update, e   update the value of the given key in the given file
     encrypt, e  perform encryption operations
     decrypt, d  perform decryption operations
     help, h     Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --pubring value, --pub value  PGP public keyring (default: "/Users/ed.silva/.gnupg/pubring.gpg")
   --secring value, --sec value  PGP private keyring (default: "/Users/ed.silva/.gnupg/secring.gpg")
   --pgp_key value, -k value     PGP key name, email, or ID to use for encryption
   --debug                       adds line number info to log output
   --help, -h                    show help
   --version, -v                 print the version

COPYRIGHT:
   (c) 2017 Everbridge, Inc.

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
$ ./generate-secure-pillar -k "Salt Master" encrypt recurse /path/to/pillar/secure/stuff