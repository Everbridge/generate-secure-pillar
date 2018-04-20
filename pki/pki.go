package pki

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os/user"
	"path/filepath"

	"github.com/proglottis/gpgme"
	"github.com/sirupsen/logrus"
)

var logger *logrus.Logger

// Pki pki info
type Pki struct {
	PgpKeyName string
}

// New returns a pki object
func New(pgpKeyName string, publicKeyRing string, secretKeyRing string) Pki {
	logger = logrus.New()

	return Pki{pgpKeyName}
}

// EncryptSecret returns encrypted plainText
func (p *Pki) EncryptSecret(plainText string) (cipherText string) {
	var memBuffer bytes.Buffer
	clearBuffer := bytes.NewBufferString(plainText)
	writer := bufio.NewWriter(&memBuffer)
	recipients, err := gpgme.FindKeys(p.PgpKeyName, false)
	if err != nil {
		panic(err)
	}
	plain, err := gpgme.NewDataReader(clearBuffer)
	if err != nil {
		panic(err)
	}
	cipher, err := gpgme.NewDataWriter(writer)
	if err != nil {
		panic(err)
	}
	ctx, err := gpgme.New()
	if err != nil {
		panic(err)
	}
	ctx.SetArmor(true)
	if err = ctx.Encrypt(recipients, 0, plain, cipher); err != nil {
		panic(err)
	}
	if err = writer.Flush(); err != nil {
		logger.Fatal("error flusing writer: ", err)
	}

	return memBuffer.String()
}

// DecryptSecret returns decrypted cipherText
func (p *Pki) DecryptSecret(cipherText string) (plainText string, err error) {
	decbuf := bytes.NewBuffer([]byte(cipherText))
	plain, err := gpgme.Decrypt(decbuf)
	if err != nil {
		return cipherText, fmt.Errorf("unable to decrypt PGP message: %s", err)
	}

	var memBuffer bytes.Buffer
	writer := bufio.NewWriter(&memBuffer)
	if _, err = io.Copy(writer, plain); err != nil {
		return cipherText, fmt.Errorf("unable to copy plain text: %s", err)
	}

	err = plain.Close()
	if err != nil {
		return cipherText, fmt.Errorf("cannot close decrypted Data: %s", err)
	}

	return memBuffer.String(), err
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

// KeyUsedForData gets the key used to encrypt a file
func (p *Pki) KeyUsedForData(cipherText string) (string, error) {
	keys, err := gpgme.FindKeys(p.PgpKeyName, false)
	if err != nil {
		return "", fmt.Errorf("unable to find key '%s'", p.PgpKeyName)
	}
	return keys[0].UserIDs().UID(), nil
}
