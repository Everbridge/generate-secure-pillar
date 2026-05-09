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
	"bytes"
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/rs/zerolog"
	"github.com/ryboe/q"
)

// PGPHeader header const
const PGPHeader string = "-----BEGIN PGP MESSAGE-----"

// Pki pki info
type Pki struct {
	PublicKey  *openpgp.Entity
	SecretKey  *openpgp.Entity
	PubRing   *openpgp.EntityList
	SecRing   *openpgp.EntityList
	GnupgHome string
	PgpKeyName string
	logger     zerolog.Logger
	debug      bool
}

// dbg creates a debug dumper function
func (p *Pki) dbg() func(thing ...interface{}) {
	return func(thing ...interface{}) {
		if p.debug {
			q.Q(thing)
		}
	}
}

// findGPGBinary locates the gpg binary, preferring gpg2
func findGPGBinary() (string, error) {
	for _, name := range []string{"gpg2", "gpg"} {
		path, err := exec.LookPath(name)
		if err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("cannot find gpg or gpg2 binary in PATH")
}

// exportKeysFromGPG runs gpg to export keys and returns them as an EntityList
func exportKeysFromGPG(gnupgHome string, secret bool) (*openpgp.EntityList, error) {
	gpgBin, err := findGPGBinary()
	if err != nil {
		return nil, err
	}

	args := []string{"--homedir", gnupgHome, "--batch", "--yes", "--export"}
	if secret {
		args = []string{"--homedir", gnupgHome, "--batch", "--yes", "--export-secret-keys"}
	}

	cmd := exec.Command(gpgBin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("gpg export failed: %w: %s", err, stderr.String())
	}

	if stdout.Len() == 0 {
		return nil, fmt.Errorf("gpg exported zero bytes (no keys found in %s)", gnupgHome)
	}

	ring, err := openpgp.ReadKeyRing(&stdout)
	if err != nil {
		return nil, fmt.Errorf("cannot parse exported keys: %w", err)
	}
	if ring == nil {
		return nil, fmt.Errorf("exported keyring is empty")
	}

	return &ring, nil
}

// New returns a pki object and an error
func New(pgpKeyName string, gnupgHome string) (*Pki, error) {
	// Initialize logger
	logger := zerolog.New(os.Stdout).Output(zerolog.ConsoleWriter{Out: os.Stdout})

	// Check for debug mode
	debugMode := os.Getenv("GSPPKI_DEBUG") != ""

	// Validate input parameters
	if pgpKeyName == "" {
		return nil, fmt.Errorf("PGP key name cannot be empty")
	}
	if gnupgHome == "" {
		return nil, fmt.Errorf("GnuPG home directory cannot be empty")
	}

	p := &Pki{
		PublicKey:  nil,
		SecretKey:  nil,
		PubRing:    nil,
		SecRing:    nil,
		GnupgHome: gnupgHome,
		PgpKeyName: pgpKeyName,
		logger:     logger,
		debug:      debugMode,
	}

	// Expand tilde in gnupg home path
	expandedHome, err := p.ExpandTilde(gnupgHome)
	if err != nil {
		return nil, fmt.Errorf("cannot expand GnuPG home path: %w", err)
	}
	p.GnupgHome = expandedHome

	// Verify the GnuPG home directory exists
	if fi, err := os.Stat(p.GnupgHome); err != nil {
		return nil, fmt.Errorf("GnuPG home directory '%s' not accessible: %w", p.GnupgHome, err)
	} else if !fi.IsDir() {
		return nil, fmt.Errorf("GnuPG home '%s' is not a directory", p.GnupgHome)
	}

	// Export public keys from GnuPG
	p.PubRing, err = exportKeysFromGPG(p.GnupgHome, false)
	if err != nil {
		return nil, fmt.Errorf("failed to export public keys: %w", err)
	}

	// Export secret keys from GnuPG (non-fatal if it fails)
	p.SecRing, err = exportKeysFromGPG(p.GnupgHome, true)
	if err != nil {
		p.logger.Warn().Err(err).Msg("failed to export secret keys - decryption operations will not be available")
	}

	// Load keys
	if p.SecRing != nil {
		p.SecretKey = p.GetKeyByID(p.SecRing, p.PgpKeyName)
	}
	p.PublicKey = p.GetKeyByID(p.PubRing, p.PgpKeyName)
	if p.PublicKey == nil {
		return nil, fmt.Errorf("unable to find key '%s' in public keyring", p.PgpKeyName)
	}

	// Debug dump if enabled
	dumper := p.dbg()
	dumper(p)

	return p, nil
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
		return cipherText, fmt.Errorf("no secret keyring available")
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

	md, err := openpgp.ReadMessage(block.Body, *p.SecRing, nil, nil)
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

	md, err := openpgp.ReadMessage(block.Body, *p.SecRing, nil, nil)
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

	keys := p.SecRing.KeysById(id)
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
