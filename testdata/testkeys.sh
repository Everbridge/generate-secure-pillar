#!/usr/bin/env bash

set -e
# set -x

PATH=$PATH:/usr/local/bin

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo $DIR

# find the gpg binary (prefer gpg2, fall back to gpg)
if command -v gpg2 &> /dev/null; then
  GPG=gpg2
elif command -v gpg &> /dev/null; then
  GPG=gpg
else
  echo "cannot find gpg binary"
  exit 1
fi

# test the gpg version (requires gpg 2.x)
GPG_MAJOR_VERSION=$($GPG --version | head -1 | cut -d ' ' -f 3 | cut -d '.' -f 1)
if [[ $GPG_MAJOR_VERSION != "2" ]]; then
    echo "GnuPG 2.x required for tests (found version $GPG_MAJOR_VERSION)"
    exit 1
fi

GNUPGHOME=$DIR/gnupg
export GNUPGHOME

mkdir -p $GNUPGHOME
chmod 700 $GNUPGHOME

# Generate a test key with no passphrase using GnuPG 2.x batch mode
$GPG --homedir $GNUPGHOME --batch --passphrase '' --quick-gen-key "Test Salt Master (test key)" rsa2048 encrypt,sign 0

# Trust the key ultimately
KEYID=$($GPG --homedir $GNUPGHOME --list-keys --with-colons | grep '^fpr' | head -1 | cut -d ':' -f 10)
echo -e "5\ny\n" | $GPG --homedir $GNUPGHOME --batch --command-fd 0 --edit-key $KEYID trust quit 2>/dev/null || true

exit 0
