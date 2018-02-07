package pki

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"github.com/keybase/go-crypto/openpgp"
	"github.com/keybase/go-crypto/openpgp/armor"
	"github.com/sirupsen/logrus"
)

var logger *logrus.Logger

// Pki pki info
type Pki struct {
	PublicKeyRing string
	SecretKeyRing string
	PgpKeyName    string
}

// New returns a pki struct
func New(pgpKeyName string, publicKeyRing string, secretKeyRing string, log *logrus.Logger) Pki {
	var err error
	if log != nil {
		logger = log
	} else {
		logger = logrus.New()
	}

	p := Pki{publicKeyRing, secretKeyRing, pgpKeyName}
	publicKeyRing, err = p.ExpandTilde(p.PublicKeyRing)
	if err != nil {
		logger.Fatal("cannot expand public key ring path: ", err)
	}
	p.PublicKeyRing = publicKeyRing
	secretKeyRing, err = p.ExpandTilde(p.SecretKeyRing)
	if err != nil {
		logger.Fatal("cannot expand secret key ring path: ", err)
	}
	p.PublicKeyRing = publicKeyRing
	p.SecretKeyRing = secretKeyRing

	return p
}

// EncryptSecret returns encrypted plainText
func (p *Pki) EncryptSecret(plainText string) (cipherText string) {
	var memBuffer bytes.Buffer

	pubringFile, err := os.Open(p.PublicKeyRing)
	if err != nil {
		logger.Fatal("cannot read public key ring: ", err)
	}
	pubring, err := openpgp.ReadKeyRing(pubringFile)
	if err != nil {
		logger.Fatal("cannot read public keys: ", err)
	}
	publicKey := p.GetKeyByID(pubring, p.PgpKeyName)

	hints := openpgp.FileHints{IsBinary: false, ModTime: time.Time{}}
	writer := bufio.NewWriter(&memBuffer)
	w, err := armor.Encode(writer, "PGP MESSAGE", nil)
	if err != nil {
		logger.Fatal("Encode error: ", err)
	}

	plainFile, err := openpgp.Encrypt(w, []*openpgp.Entity{publicKey}, nil, &hints, nil)
	if err != nil {
		logger.Fatal("Encryption error: ", err)
	}

	if _, err = fmt.Fprintf(plainFile, "%s", plainText); err != nil {
		logger.Fatal(err)
	}

	if err = plainFile.Close(); err != nil {
		logger.Fatal("unable to close file: ", err)
	}
	if err = w.Close(); err != nil {
		logger.Fatal(err)
	}
	if err = writer.Flush(); err != nil {
		logger.Fatal("error flusing writer: ", err)
	}
	if err = pubringFile.Close(); err != nil {
		logger.Fatal("error closing pubring: ", err)
	}

	return memBuffer.String()
}

// DecryptSecret returns decrypted cipherText
func (p *Pki) DecryptSecret(cipherText string) (plainText string) {
	privringFile, err := os.Open(p.SecretKeyRing)
	if err != nil {
		logger.Fatal("unable to open secring: ", err)
	}
	privring, err := openpgp.ReadKeyRing(privringFile)
	if err != nil {
		logger.Fatal("cannot read private keys: ", err)
	} else if privring == nil {
		logger.Fatal(fmt.Sprintf("%s is empty!", p.SecretKeyRing))
	}

	decbuf := bytes.NewBuffer([]byte(cipherText))
	block, err := armor.Decode(decbuf)
	if block.Type != "PGP MESSAGE" {
		logger.Fatal("block type is not PGP MESSAGE: ", err)
	}

	md, err := openpgp.ReadMessage(block.Body, privring, nil, nil)
	if err != nil {
		logger.Fatal("unable to read PGP message: ", err)
	}

	bytes, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		logger.Fatal("unable to read message body: ", err)
	}

	return string(bytes)
}

// GetKeyByID returns a keyring by the given ID
func (p *Pki) GetKeyByID(keyring openpgp.EntityList, id string) *openpgp.Entity {
	for _, entity := range keyring {
		for _, ident := range entity.Identities {
			if ident.Name == id {
				return entity
			}
			if ident.UserId.Email == id {
				return entity
			}
			if ident.UserId.Name == id {
				return entity
			}
		}
	}

	return nil
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
