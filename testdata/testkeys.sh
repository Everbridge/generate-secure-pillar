#!/usr/bin/env bash

set -e
# set -x

PATH=$PATH:/usr/local/bin

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

# macOS caps Unix-socket paths at ~104 chars (sockaddr_un.sun_path). The repo
# checkout path under testdata/ blows past that, so gpg-agent fails to bind its
# socket. Honor an inherited GNUPGHOME if it points somewhere short; otherwise
# fall back to a short, stable path under /tmp.
if [[ -z "$GNUPGHOME" || ${#GNUPGHOME} -gt 80 ]]; then
    GNUPGHOME="/tmp/gsp-test-gnupg-${USER:-$(id -un)}"
fi
export GNUPGHOME
echo "$GNUPGHOME"

# stop any agent attached to a previous keyring so we get a clean state
gpgconf --kill all 2>/dev/null || true

rm -rf "$GNUPGHOME"
mkdir -p "$GNUPGHOME"
chmod 700 "$GNUPGHOME"

# Generate a test key with no passphrase using GnuPG 2.x batch mode
$GPG --batch --passphrase '' --quick-gen-key "Test Salt Master (test key)" rsa2048 encrypt,sign 0

# Trust the key ultimately
KEYID=$($GPG --list-keys --with-colons | grep '^fpr' | head -1 | cut -d ':' -f 10)
echo -e "5\ny\n" | $GPG --batch --command-fd 0 --edit-key $KEYID trust quit 2>/dev/null || true

exit 0
