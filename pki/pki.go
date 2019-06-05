// Copyright © 2018 Everbridge, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package pki

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/ProtonMail/gopenpgp/crypto"
	"github.com/keybase/go-crypto/openpgp"
	"github.com/keybase/go-crypto/openpgp/armor"
	"github.com/sirupsen/logrus"
)

var logger = logrus.New()
var debug = true
var pgp = crypto.GopenPGP{}

// PGPHeader header const
const PGPHeader string = "-----BEGIN PGP MESSAGE-----"

// Pki pki info
type Pki struct {
	PublicKeyRing *crypto.KeyRing
	SecretKeyRing *crypto.KeyRing
	PgpKeyName    string
	PGP           *crypto.GopenPGP
	SecRing       *openpgp.EntityList
}

// New returns a pki object
func New(pgpKeyName string, publicKeyRing string, secretKeyRing string) Pki {
	if os.Getenv("GSPPKI_DEBUG") != "" {
		debug = true
	}
	logger.Out = os.Stdout
	var err error

	p := Pki{
		PublicKeyRing: nil,
		SecretKeyRing: nil,
		PgpKeyName:    pgpKeyName,
		PGP:           &pgp,
	}
	publicKeyRing, err = p.ExpandTilde(publicKeyRing)
	if err != nil {
		logger.Fatal("cannot expand public key ring path: ", err)
	}
	var buf []byte
	buf, err = ioutil.ReadFile(filepath.Clean(publicKeyRing))
	if err != nil {
		logger.Fatalf("Pki: %s", err)
	}
	p.PublicKeyRing, err = pgp.BuildKeyRing(buf)
	if err != nil {
		logger.Fatalf("Pki: %s", err)
	}

	secretKeyRing, err = p.ExpandTilde(secretKeyRing)
	if err != nil {
		logger.Fatal("cannot expand secret key ring path: ", err)
	}
	buf, err = ioutil.ReadFile(filepath.Clean(secretKeyRing))
	if err != nil {
		logger.Fatalf("Pki: %s", err)
	}
	p.SecretKeyRing, err = pgp.BuildKeyRing(buf)
	if err != nil {
		logger.Fatalf("Pki: %s", err)
	}
	p.SecRing, err = p.setKeyRing(secretKeyRing)
	if err != nil {
		logger.Warnf("Pki: %s", err)
	}

	return p
}

func (p *Pki) setKeyRing(keyRingPath string) (*openpgp.EntityList, error) {
	keyRing, err := p.ExpandTilde(keyRingPath)
	if err != nil {
		return nil, fmt.Errorf("error reading secring: %s", err)
	}
	keyRingFile, err := os.Open(filepath.Clean(keyRing))
	if err != nil {
		return nil, fmt.Errorf("unable to open key ring: %s", err)
	}
	ring, err := openpgp.ReadKeyRing(keyRingFile)
	if err != nil {
		return nil, fmt.Errorf("cannot read private keys: %s", err)
	} else if ring == nil {
		return nil, fmt.Errorf("%s is empty", p.SecretKeyRing)
	}
	if err = keyRingFile.Close(); err != nil {
		return &ring, fmt.Errorf("error closing secring: %s", err)
	}

	return &ring, nil
}

// ExpandTilde does exactly what it says on the tin
func (p *Pki) ExpandTilde(path string) (string, error) {
	if len(path) == 0 || path[0] != '~' {
		return path, nil
	}

	usr, err := user.Current()
	if err != nil {
		return "", err
	}
	return filepath.Join(usr.HomeDir, path[1:]), nil
}

// KeyUsedForEncryptedFile gets the key used to encrypt a file
func (p *Pki) KeyUsedForEncryptedFile(file string) (string, error) {
	filePath, err := filepath.Abs(file)
	if err != nil {
		return "", err
	}

	in, err := os.Open(filepath.Clean(filePath))
	if err != nil {
		return "", err
	}

	block, err := armor.Decode(in)
	if err != nil {
		return "", err
	}

	if block.Type != "PGP MESSAGE" {
		return "", fmt.Errorf("error decoding private key")
	}
	md, err := openpgp.ReadMessage(block.Body, p.SecRing, nil, nil)
	if err != nil {
		return "", fmt.Errorf("unable to read PGP message: %s", err)
	}

	for index := 0; index < len(md.EncryptedToKeyIds); index++ {
		id := md.EncryptedToKeyIds[index]
		keyStr := p.keyStringForID(id)
		if keyStr != "" {
			return keyStr, nil
		}
	}

	return "", fmt.Errorf("unable to find key for ids used")
}

func (p *Pki) keyStringForID(id uint64) string {
	keys := p.SecRing.KeysById(id, nil)
	if len(keys) > 0 {
		for n := 0; n < len(keys); n++ {
			key := keys[n]
			if key.Entity != nil {
				str := strings.ToUpper(hex.EncodeToString(key.Entity.PrimaryKey.Fingerprint[:]))
				for k := range key.Entity.Identities {
					// return the first found uid
					return fmt.Sprintf("%s (%s)", k, str)
				}
			}
		}
	}
	return ""
}
