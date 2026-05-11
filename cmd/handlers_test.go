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

package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Everbridge/generate-secure-pillar/pki"
)

// fakeCrypter is a deterministic in-memory pki.Crypter for handler tests.
// Ciphertext is wrapped with the PGP armor header so sls.isEncrypted() picks
// it up; the inner payload is the original plaintext.
type fakeCrypter struct {
	encryptErr error
	decryptErr error
	keyUsedErr error

	encrypted []string
	decrypted []string
}

func (f *fakeCrypter) EncryptSecret(plain string) (string, error) {
	if f.encryptErr != nil {
		return plain, f.encryptErr
	}
	f.encrypted = append(f.encrypted, plain)
	return pki.PGPHeader + "\nENC[" + plain + "]\n-----END PGP MESSAGE-----", nil
}

func (f *fakeCrypter) DecryptSecret(cipher string) (string, error) {
	if f.decryptErr != nil {
		return cipher, f.decryptErr
	}
	f.decrypted = append(f.decrypted, cipher)
	start := strings.Index(cipher, "ENC[")
	if start < 0 {
		return cipher, errors.New("not fake-encrypted")
	}
	end := strings.Index(cipher[start:], "]")
	if end < 0 {
		return cipher, errors.New("malformed fake ciphertext")
	}
	return cipher[start+4 : start+end], nil
}

func (f *fakeCrypter) KeyUsedForEncryptedFile(file string) (string, error) {
	if f.keyUsedErr != nil {
		return "", f.keyUsedErr
	}
	return "DEADBEEF: TEST KEY", nil
}

// fakeEncrypt returns the ciphertext shape produced by fakeCrypter for plain.
func fakeEncrypt(plain string) string {
	return pki.PGPHeader + "\nENC[" + plain + "]\n-----END PGP MESSAGE-----"
}

// writeSlsFile writes contents to a .sls file in tempDir and returns the path.
func writeSlsFile(t *testing.T, tempDir, name, contents string) string {
	t.Helper()
	p := filepath.Join(tempDir, name)
	if err := os.WriteFile(p, []byte(contents), 0600); err != nil {
		t.Fatalf("writeSlsFile: %v", err)
	}
	return p
}
