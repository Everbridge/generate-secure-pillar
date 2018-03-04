package pki

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/jcmdev0/gpgagent"
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
	PublicKey     *openpgp.Entity
}

// New returns a pki struct
func New(pgpKeyName string, publicKeyRing string, secretKeyRing string, log *logrus.Logger) Pki {
	var err error
	if log != nil {
		logger = log
	} else {
		logger = logrus.New()
	}

	p := Pki{publicKeyRing, secretKeyRing, pgpKeyName, nil}
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

	pubringFile, err := os.Open(p.PublicKeyRing)
	if err != nil {

		logger.Fatal("cannot read public key ring: ", err)
	}
	pubring, err := openpgp.ReadKeyRing(pubringFile)
	if err != nil {
		logger.Fatal("cannot read public keys: ", err)
	}
	p.PublicKey = p.GetKeyByID(pubring, p.PgpKeyName)
	if err = pubringFile.Close(); err != nil {
		logger.Fatal("error closing pubring: ", err)
	}

	return p
}

// PromptFunction prompts for secure key pass phrase
func (p *Pki) PromptFunction(keys []openpgp.Key, symmetric bool) ([]byte, error) {
	conn, err := gpgagent.NewGpgAgentConn()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	for _, key := range keys {
		cacheID := strings.ToUpper(hex.EncodeToString(key.PublicKey.Fingerprint[:]))

		// TODO: Add prompt, etc.
		request := gpgagent.PassphraseRequest{CacheKey: cacheID}

		passphrase, err := conn.GetPassphrase(&request)
		if err != nil {
			return nil, err
		}

		err = key.PrivateKey.Decrypt([]byte(passphrase))
		if err != nil {
			return nil, err
		}

		return []byte(passphrase), nil
	}

	return nil, fmt.Errorf("Unable to find key")
}

// EncryptSecret returns encrypted plainText
func (p *Pki) EncryptSecret(plainText string) (cipherText string) {
	var memBuffer bytes.Buffer

	hints := openpgp.FileHints{IsBinary: false, ModTime: time.Time{}}
	writer := bufio.NewWriter(&memBuffer)
	w, err := armor.Encode(writer, "PGP MESSAGE", nil)
	if err != nil {
		logger.Fatal("Encode error: ", err)
	}

	plainFile, err := openpgp.Encrypt(w, []*openpgp.Entity{p.PublicKey}, nil, &hints, nil)
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

	return memBuffer.String()
}

// DecryptSecret returns decrypted cipherText
func (p *Pki) DecryptSecret(cipherText string) (plainText string, err error) {
	privringFile, err := os.Open(p.SecretKeyRing)
	if err != nil {
		return "", fmt.Errorf("unable to open secring: %s", err)
	}
	privring, err := openpgp.ReadKeyRing(privringFile)
	if err != nil {
		return "", fmt.Errorf("cannot read private keys: %s", err)
	} else if privring == nil {
		return "", fmt.Errorf(fmt.Sprintf("%s is empty!", p.SecretKeyRing))
	}

	decbuf := bytes.NewBuffer([]byte(cipherText))
	block, err := armor.Decode(decbuf)
	if block.Type != "PGP MESSAGE" {
		return "", fmt.Errorf("block type is not PGP MESSAGE: %s", err)
	}

	md, err := openpgp.ReadMessage(block.Body, privring, nil, nil)
	if err != nil {
		return "", fmt.Errorf("unable to read PGP message: %s", err)
	}

	bytes, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return "", fmt.Errorf("unable to read message body: %s", err)
	}

	return string(bytes), err
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
