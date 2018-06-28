#!/usr/bin/env bash

set -e
set -x

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo $DIR

# find the gpg binary
GPG=`which gpg1`
if [[ ! -x $GPG ]]; then
    GPG=`which gpg`
    if [[ ! -x $GPG ]]; then
        echo "cannot find gnupg binary"
        exit -1;
    fi
fi

# test the gpg version (only works with gpg1)
GPG_MAJOR_VERSION=`$GPG --version | head -1 | cut -d ' ' -f 3 | cut -d '.' -f 1`
if [[ $GPG_MAJOR_VERSION != "1" ]]; then
    echo "GNUPGv1 required for tests"
    exit -1;
fi

mkdir -p $DIR/gnupg
chmod 700 $DIR/gnupg
$GPG --homedir $DIR/gnupg/ --gen-key --batch < $DIR/gpginit.txt
$GPG --homedir $DIR/gnupg/ --expert --armor --export | gpg1 --homedir $DIR/gnupg/ --import
$GPG --homedir $DIR/gnupg/ --expert --armor --export-secret-key | gpg1 --homedir $DIR/gnupg/ --import
SECKEY=`$GPG --homedir $DIR/gnupg --list-secret-keys | grep 'sec ' | cut -d '/' -f 2 | cut -d ' ' -f 1`
expect -c "spawn $GPG --homedir $DIR/gnupg --edit-key $SECKEY trust quit; send \"5\ry\r\"; expect eof"

exit 0
