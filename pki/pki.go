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

var logger = logrus.New()

// Pki pki info
type Pki struct {
	PublicKeyRing string
	SecretKeyRing string
	PgpKeyName    string
	PublicKey     *openpgp.Entity
	PubRing       openpgp.EntityList
	SecRing       openpgp.EntityList
}

// New returns a pki object
func New(pgpKeyName string, publicKeyRing string, secretKeyRing string) Pki {
	var err error

	p := Pki{publicKeyRing, secretKeyRing, pgpKeyName, nil, nil, nil}
	publicKeyRing, err = p.ExpandTilde(p.PublicKeyRing)
	if err != nil {
		logger.Fatal("cannot expand public key ring path: ", err)
	}
	p.PublicKeyRing = publicKeyRing

	secKeyRing, err := p.ExpandTilde(p.SecretKeyRing)
	if err != nil {
		logger.Fatal("cannot expand secret key ring path: ", err)
	}
	p.SecretKeyRing = secKeyRing

	err = p.setSecKeyRing()
	if err != nil {
		logger.Warnf("Pki: %s", err)
	}
	err = p.setPubKeyRing()
	if err != nil {
		logger.Fatalf("Pki: %s", err)
	}

	// TODO: Something is goofy here sometimes when getting a key to decrypt
	p.PublicKey = p.GetKeyByID(p.PubRing, p.PgpKeyName)
	if p.PublicKey == nil {
		logger.Fatalf("unable to find key '%s' in %s", p.PgpKeyName, p.PublicKeyRing)
	}

	return p
}

func (p *Pki) setSecKeyRing() error {
	secretKeyRing, err := p.ExpandTilde(p.SecretKeyRing)
	if err != nil {
		return fmt.Errorf("error reading secring: %s", err)
	}
	p.SecretKeyRing = secretKeyRing
	privringFile, err := os.Open(secretKeyRing)
	if err != nil {
		return fmt.Errorf("unable to open secring: %s", err)
	}
	privring, err := openpgp.ReadKeyRing(privringFile)
	if err != nil {
		return fmt.Errorf("cannot read private keys: %s", err)
	} else if privring == nil {
		return fmt.Errorf("%s is empty", p.SecretKeyRing)
	} else {
		p.SecRing = privring
	}
	if err = privringFile.Close(); err != nil {
		return fmt.Errorf("error closing secring: %s", err)
	}

	return nil
}

func (p *Pki) setPubKeyRing() error {
	publicKeyRing, err := p.ExpandTilde(p.PublicKeyRing)
	if err != nil {
		return fmt.Errorf("error reading pubring: %s", err)
	}
	p.PublicKeyRing = publicKeyRing
	pubringFile, err := os.Open(p.PublicKeyRing)
	if err != nil {
		return fmt.Errorf("cannot read public key ring: %s", err)
	}
	pubring, err := openpgp.ReadKeyRing(pubringFile)
	if err != nil {
		return fmt.Errorf("cannot read public keys: %s", err)
	}
	p.PubRing = pubring
	if err = pubringFile.Close(); err != nil {
		return fmt.Errorf("error closing pubring: %s", err)
	}

	return nil
}

// EncryptSecret returns encrypted plainText
func (p *Pki) EncryptSecret(plainText string) (string, error) {
	var memBuffer bytes.Buffer

	hints := openpgp.FileHints{IsBinary: false, ModTime: time.Time{}}
	writer := bufio.NewWriter(&memBuffer)
	w, err := armor.Encode(writer, "PGP MESSAGE", nil)
	if err != nil {
		return plainText, fmt.Errorf("encode error: %s", err)
	}

	plainFile, err := openpgp.Encrypt(w, []*openpgp.Entity{p.PublicKey}, nil, &hints, nil)
	if err != nil {
		return plainText, fmt.Errorf("encryption error: %s", err)
	}

	if _, err = fmt.Fprintf(plainFile, "%s", plainText); err != nil {
		return plainText, fmt.Errorf("encryption error: %s", err)
	}

	if err = plainFile.Close(); err != nil {
		return plainText, fmt.Errorf("encryption error: %s", err)
	}
	if err = w.Close(); err != nil {
		return plainText, fmt.Errorf("encryption error: %s", err)
	}
	if err = writer.Flush(); err != nil {
		return plainText, fmt.Errorf("encryption error: %s", err)
	}

	return memBuffer.String(), nil
}

// DecryptSecret returns decrypted cipherText
func (p *Pki) DecryptSecret(cipherText string) (plainText string, err error) {
	privringFile, err := os.Open(p.SecretKeyRing)
	if err != nil {
		return cipherText, fmt.Errorf("unable to open secring: %s", err)
	}
	privring, err := openpgp.ReadKeyRing(privringFile)
	if err != nil {
		return cipherText, fmt.Errorf("cannot read private keys: %s", err)
	} else if privring == nil {
		return cipherText, fmt.Errorf(fmt.Sprintf("%s is empty!", p.SecretKeyRing))
	}

	decbuf := bytes.NewBuffer([]byte(cipherText))
	block, err := armor.Decode(decbuf)
	if err != nil {
		return cipherText, fmt.Errorf("Decode error: %s", err)
	}
	if block.Type != "PGP MESSAGE" {
		return cipherText, fmt.Errorf("block type is not PGP MESSAGE: %s", err)
	}

	md, err := openpgp.ReadMessage(block.Body, privring, nil, nil)
	if err != nil {
		return cipherText, fmt.Errorf("unable to read PGP message: %s", err)
	}

	body, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return cipherText, fmt.Errorf("unable to read message body: %s", err)
	}

	return string(body), err
}

// GetKeyByID returns a keyring by the given ID
func (p *Pki) GetKeyByID(keyring openpgp.EntityList, id interface{}) *openpgp.Entity {
	for _, entity := range keyring {
		if entity.PrimaryKey != nil && entity.PrimaryKey.KeyIdString() == id.(string) {
			return entity
		}
		if entity.PrivateKey != nil && entity.PrivateKey.KeyIdString() == id.(string) {
			return entity
		}

		for _, ident := range entity.Identities {
			if id.(string) == ident.Name {
				return entity
			}
			if id.(string) == ident.UserId.Email {
				return entity
			}
			if id.(string) == ident.UserId.Name {
				return entity
			}
			if id.(string) == ident.UserId.Id {
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

// KeyUsedForEncryptedFile gets the key used to encrypt a file
func (p *Pki) KeyUsedForEncryptedFile(file string) (string, error) {
	filePath, err := filepath.Abs(file)
	if err != nil {
		return "", err
	}

	in, err := os.Open(filePath)
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
				for k := range key.Entity.Identities {
					// return the first valid key
					return fmt.Sprintf("%X: %s\n", id, k)
				}
			}
		}
	}
	return ""
}
