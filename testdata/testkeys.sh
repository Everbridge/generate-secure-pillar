#!/usr/bin/env bash

set -e
set -x

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo $DIR

GPG=`which gpg1`
if [! -f $GPG]; then
    exit -1;
fi

$GPG --homedir $DIR/gnupg/ --gen-key --batch < $DIR/gpginit.txt
$GPG --homedir $DIR/gnupg/ --expert --armor --export | gpg1 --homedir $DIR/gnupg/ --import
$GPG --homedir $DIR/gnupg/ --expert --armor --export-secret-key | gpg1 --homedir $DIR/gnupg/ --import
SECKEY=`$GPG --homedir $DIR/gnupg --list-secret-keys | grep 'sec ' | cut -d '/' -f 2 | cut -d ' ' -f 1`
expect -c "spawn $GPG --homedir $DIR/gnupg --edit-key $SECKEY trust quit; send \"5\ry\r\"; expect eof"

exit 0
