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

// Package pki handles PGP for pillar content
package pki

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/keybase/go-crypto/openpgp"
	"github.com/keybase/go-crypto/openpgp/armor"
	"github.com/rs/zerolog"
	"github.com/ryboe/q"
)

// PGPHeader header const
const PGPHeader string = "-----BEGIN PGP MESSAGE-----"

// Pki pki info
type Pki struct {
	PublicKey     *openpgp.Entity
	SecretKey     *openpgp.Entity
	PubRing       *openpgp.EntityList
	SecRing       *openpgp.EntityList
	PublicKeyRing string
	SecretKeyRing string
	PgpKeyName    string
	logger        zerolog.Logger
	debug         bool
}

// dbg creates a debug dumper function
func (p *Pki) dbg() func(thing ...interface{}) {
	return func(thing ...interface{}) {
		if p.debug {
			q.Q(thing)
		}
	}
}

// New returns a pki object and an error
func New(pgpKeyName string, publicKeyRing string, secretKeyRing string) (*Pki, error) {
	// Initialize logger
	logger := zerolog.New(os.Stdout).Output(zerolog.ConsoleWriter{Out: os.Stdout})

	// Check for debug mode
	debugMode := os.Getenv("GSPPKI_DEBUG") != ""

	var err error

	// Validate input parameters
	if pgpKeyName == "" {
		return nil, fmt.Errorf("PGP key name cannot be empty")
	}
	if publicKeyRing == "" {
		return nil, fmt.Errorf("public key ring path cannot be empty")
	}
	if secretKeyRing == "" {
		return nil, fmt.Errorf("secret key ring path cannot be empty")
	}

	p := &Pki{
		PublicKey:     nil,
		SecretKey:     nil,
		PubRing:       nil,
		SecRing:       nil,
		PublicKeyRing: publicKeyRing,
		SecretKeyRing: secretKeyRing,
		PgpKeyName:    pgpKeyName,
		logger:        logger,
		debug:         debugMode,
	}

	// Expand and validate public key ring path
	publicKeyRing, err = p.ExpandTilde(p.PublicKeyRing)
	if err != nil {
		return nil, fmt.Errorf("cannot expand public key ring path: %w", err)
	}
	p.PublicKeyRing = publicKeyRing

	// Load public key ring
	p.PubRing, err = p.setKeyRing(p.PublicKeyRing)
	if err != nil {
		return nil, fmt.Errorf("failed to load public key ring '%s': %w", p.PublicKeyRing, err)
	}

	// Expand and validate secret key ring path
	secKeyRing, err := p.ExpandTilde(p.SecretKeyRing)
	if err != nil {
		return nil, fmt.Errorf("cannot expand secret key ring path: %w", err)
	}
	p.SecretKeyRing = secKeyRing

	// Load secret key ring (this may fail and is non-fatal for encryption-only operations)
	p.SecRing, err = p.setKeyRing(p.SecretKeyRing)
	if err != nil {
		p.logger.Warn().Err(err).Str("keyring", p.SecretKeyRing).Msg("failed to load secret key ring - decryption operations will not be available")
	}

	// Load keys
	if p.SecRing != nil {
		p.SecretKey = p.GetKeyByID(p.SecRing, p.PgpKeyName)
	}
	p.PublicKey = p.GetKeyByID(p.PubRing, p.PgpKeyName)
	if p.PublicKey == nil {
		return nil, fmt.Errorf("unable to find key '%s' in public key ring '%s'", p.PgpKeyName, p.PublicKeyRing)
	}

	// Debug dump if enabled
	dumper := p.dbg()
	dumper(p)

	return p, nil
}

func (p *Pki) setKeyRing(keyRingPath string) (*openpgp.EntityList, error) {
	if keyRingPath == "" {
		return nil, fmt.Errorf("key ring path cannot be empty")
	}

	keyRing, err := p.ExpandTilde(keyRingPath)
	if err != nil {
		return nil, fmt.Errorf("error expanding key ring path '%s': %w", keyRingPath, err)
	}

	keyRingFile, err := os.Open(filepath.Clean(keyRing))
	if err != nil {
		return nil, fmt.Errorf("unable to open key ring file '%s': %w", keyRing, err)
	}
	defer func() {
		if closeErr := keyRingFile.Close(); closeErr != nil {
			p.logger.Warn().Err(closeErr).Str("keyring", keyRing).Msg("failed to close key ring file")
		}
	}()

	ring, err := openpgp.ReadKeyRing(keyRingFile)
	if err != nil {
		return nil, fmt.Errorf("cannot read key ring from file '%s': %w", keyRing, err)
	}
	if ring == nil {
		return nil, fmt.Errorf("key ring file '%s' is empty or invalid", keyRing)
	}

	return &ring, nil
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
	if plainFile == nil {
		return plainText, fmt.Errorf("encryption error: plainFile is nil")
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
	if p.SecRing == nil {
		return cipherText, fmt.Errorf("no secring set")
	}
	if p.SecretKey == nil {
		return cipherText, fmt.Errorf("unable to load PGP secret key for '%s'", p.PgpKeyName)
	}

	decbuf := bytes.NewBuffer([]byte(cipherText))
	block, err := armor.Decode(decbuf)
	if err != nil {
		return cipherText, fmt.Errorf("decode error: %w", err)
	}
	if block.Type != "PGP MESSAGE" {
		return cipherText, fmt.Errorf("block type is not PGP MESSAGE: %s", err)
	}

	md, err := openpgp.ReadMessage(block.Body, p.SecRing, nil, nil)
	if err != nil {
		return cipherText, fmt.Errorf("unable to read PGP message: %s", err)
	}
	if md == nil {
		return cipherText, fmt.Errorf("unable to read PGP message: md is nil")
	}

	body, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		return cipherText, fmt.Errorf("unable to read message body: %s", err)
	}

	return string(body), err
}

// GetKeyByID returns a keyring by the given ID
func (p *Pki) GetKeyByID(keyring *openpgp.EntityList, id interface{}) *openpgp.Entity {
	if keyring == nil {
		return nil
	}

	// Type assert and validate the id parameter
	idStr, ok := id.(string)
	if !ok {
		p.logger.Warn().Interface("id", id).Msg("GetKeyByID: id parameter is not a string")
		return nil
	}

	if idStr == "" {
		p.logger.Warn().Msg("GetKeyByID: id parameter is empty")
		return nil
	}

	for _, entity := range *keyring {
		if entity == nil {
			continue
		}

		if entity.PrivateKey != nil && entity.PrivateKey.KeyIdString() == idStr {
			return entity
		}
		if entity.PrimaryKey != nil && entity.PrimaryKey.KeyIdString() == idStr {
			return entity
		}

		if checkIdentities(idStr, entity) {
			return entity
		}
	}

	return nil
}

func checkIdentities(id string, entity *openpgp.Entity) bool {
	if entity == nil || entity.Identities == nil {
		return false
	}

	for _, ident := range entity.Identities {
		if ident == nil {
			continue
		}

		if id == ident.Name {
			return true
		}

		if ident.UserId != nil {
			if id == ident.UserId.Email {
				return true
			}
			if id == ident.UserId.Name {
				return true
			}
			if id == ident.UserId.Id {
				return true
			}
		}
	}

	return false
}

// ExpandTilde expands tilde paths and validates against directory traversal
func (p *Pki) ExpandTilde(path string) (string, error) {
	if len(path) == 0 {
		return "", fmt.Errorf("path cannot be empty")
	}

	var expandedPath string
	if path[0] == '~' {
		usr, err := user.Current()
		if err != nil {
			return "", fmt.Errorf("cannot get current user: %w", err)
		}
		expandedPath = filepath.Join(usr.HomeDir, path[1:])
	} else {
		expandedPath = path
	}

	// Clean the path and validate against directory traversal
	cleanedPath := filepath.Clean(expandedPath)

	// Check for directory traversal attempts
	if containsDirectoryTraversal(cleanedPath) {
		return "", fmt.Errorf("directory traversal detected in path: %s", path)
	}

	return cleanedPath, nil
}

// containsDirectoryTraversal checks for directory traversal patterns
func containsDirectoryTraversal(path string) bool {
	// Check for obvious traversal patterns
	if strings.Contains(path, ".."+string(filepath.Separator)) ||
		strings.Contains(path, string(filepath.Separator)+"..") ||
		strings.HasPrefix(path, ".."+string(filepath.Separator)) ||
		strings.HasSuffix(path, string(filepath.Separator)+"..") ||
		path == ".." {
		return true
	}
	return false
}

// KeyUsedForEncryptedFile gets the key used to encrypt a file
func (p *Pki) KeyUsedForEncryptedFile(file string) (string, error) {
	if file == "" {
		return "", fmt.Errorf("file path cannot be empty")
	}

	filePath, err := filepath.Abs(file)
	if err != nil {
		return "", fmt.Errorf("cannot get absolute path for file '%s': %w", file, err)
	}

	// Validate file path to prevent directory traversal
	if containsDirectoryTraversal(filePath) {
		return "", fmt.Errorf("directory traversal detected in file path: %s", file)
	}

	in, err := os.Open(filepath.Clean(filePath))
	if err != nil {
		return "", fmt.Errorf("cannot open file '%s': %w", filePath, err)
	}
	defer func() {
		if closeErr := in.Close(); closeErr != nil {
			p.logger.Warn().Err(closeErr).Str("file", filePath).Msg("failed to close file")
		}
	}()

	block, err := armor.Decode(in)
	if err != nil {
		return "", fmt.Errorf("armor decode error for file '%s': %w", filePath, err)
	}

	if block.Type != "PGP MESSAGE" {
		return "", fmt.Errorf("invalid block type '%s', expected 'PGP MESSAGE' in file '%s'", block.Type, filePath)
	}

	md, err := openpgp.ReadMessage(block.Body, p.SecRing, nil, nil)
	if err != nil {
		return "", fmt.Errorf("unable to read PGP message from file '%s': %w", filePath, err)
	}
	if md == nil {
		return "", fmt.Errorf("PGP message is nil in file '%s'", filePath)
	}

	for index := 0; index < len(md.EncryptedToKeyIds); index++ {
		id := md.EncryptedToKeyIds[index]
		keyStr := p.keyStringForID(id)
		if keyStr != "" {
			return keyStr, nil
		}
	}

	return "", fmt.Errorf("unable to find key for encrypted key IDs in file '%s'", filePath)
}

func (p *Pki) keyStringForID(id uint64) string {
	if p.SecRing == nil {
		return ""
	}

	keys := p.SecRing.KeysById(id, nil)
	if len(keys) == 0 {
		return ""
	}

	for _, key := range keys {
		if key.Entity == nil || key.Entity.Identities == nil {
			continue
		}

		for identityName := range key.Entity.Identities {
			if identityName != "" {
				// return the first valid key identity
				return fmt.Sprintf("%X: %s\n", id, identityName)
			}
		}
	}

	return ""
}
