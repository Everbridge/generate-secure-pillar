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
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"

	"github.com/ProtonMail/gopenpgp/crypto"
	// "github.com/keybase/go-crypto/openpgp"
	// "github.com/keybase/go-crypto/openpgp/armor"
	"github.com/sirupsen/logrus"
	"github.com/y0ssar1an/q"
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
}

// if debug==true this can be used to dump values from the var(s) passed in
func dbg() func(thing ...interface{}) {
	return func(thing ...interface{}) {
		if debug {
			q.Q(thing)
		}
	}
}

var dumper = dbg()

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

	return p
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

	dec, sig, err := p.SecretKeyRing.DecryptArmored(in)
	if err != nil {
		return "", err
	}
	fmt.Printf("%#v\n", dec)
	fmt.Printf("%#v\n", sig)

	return "", fmt.Errorf("unable to find key for ids used")
}
