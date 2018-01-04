package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

var logger = logrus.New()

func encryptSecret(plainText string) (cipherText string) {
	var memBuffer bytes.Buffer

	pubringFile, err := os.Open(publicKeyRing)
	if err != nil {
		logger.Fatal("cannot read public key ring: ", err)
	}
	pubring, err := openpgp.ReadKeyRing(pubringFile)
	if err != nil {
		logger.Fatal("cannot read public keys: ", err)
	}
	publicKey := getKeyByID(pubring, pgpKeyName)

	hints := openpgp.FileHints{IsBinary: false, ModTime: time.Time{}}
	writer := bufio.NewWriter(&memBuffer)
	w, _ := armor.Encode(writer, "PGP MESSAGE", nil)
	plainFile, _ := openpgp.Encrypt(w, []*openpgp.Entity{publicKey}, nil, &hints, nil)
	fmt.Fprintf(plainFile, plainText)
	if err := plainFile.Close(); err != nil {
		logger.Fatal("unable to close file: ", err)
	}
	if err := w.Close(); err != nil {
		logger.Fatal(err)
	}
	if err := writer.Flush(); err != nil {
		logger.Fatal("error flusing writer: ", err)
	}
	if err := pubringFile.Close(); err != nil {
		logger.Fatal("error closing pubring: ", err)
	}

	return memBuffer.String()
}

func decryptSecret(cipherText string) (plainText string) {
	privringFile, err := os.Open(secureKeyRing)
	if err != nil {
		logger.Fatal("unable to open secring: ", err)
	}
	privring, err := openpgp.ReadKeyRing(privringFile)
	if err != nil {
		logger.Fatal("cannot read private keys: ", err)
	} else if privring == nil {
		logger.Fatal(fmt.Sprintf("%s is empty!", secureKeyRing))
	}

	decbuf := bytes.NewBuffer([]byte(cipherText))
	block, err := armor.Decode(decbuf)
	if block.Type != "PGP MESSAGE" {
		logger.Fatal("block type is not PGP MESSAGE: ", err)
	}

	md, err := openpgp.ReadMessage(block.Body, privring, nil, nil)
	if err != nil {
		logger.Fatal("unadle to read PGP message: ", err)
	}

	bytes, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		logger.Fatal("unable to read message body: ", err)
	}

	return string(bytes)
}

func getKeyByID(keyring openpgp.EntityList, id string) *openpgp.Entity {
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
