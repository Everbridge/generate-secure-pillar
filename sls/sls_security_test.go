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

package sls

import (
	"errors"
	"strings"
	"testing"

	"github.com/Everbridge/generate-secure-pillar/pki"
)

// fakeCrypter is a deterministic in-memory pki.Crypter for testing the
// encrypt/decrypt/validate/rotate code paths in sls without a real keyring.
//
// Ciphertext format is "<PGP header>\nENC[<plain>]\n<PGP footer>" so the
// isEncrypted() check in sls passes on values produced by EncryptSecret.
type fakeCrypter struct {
	keyName string

	// per-call hook: return non-nil to make the call fail; called BEFORE
	// recording in the slices below.
	encryptErr func(plain string) error
	decryptErr func(cipher string) error
	keyUsedErr func(file string) error

	encrypted  []string
	decrypted  []string
	keyLookups []string
}

func (f *fakeCrypter) EncryptSecret(plain string) (string, error) {
	if f.encryptErr != nil {
		if err := f.encryptErr(plain); err != nil {
			return plain, err
		}
	}
	f.encrypted = append(f.encrypted, plain)
	return pki.PGPHeader + "\nENC[" + plain + "]\n-----END PGP MESSAGE-----", nil
}

func (f *fakeCrypter) DecryptSecret(cipher string) (string, error) {
	if f.decryptErr != nil {
		if err := f.decryptErr(cipher); err != nil {
			return cipher, err
		}
	}
	f.decrypted = append(f.decrypted, cipher)
	start := strings.Index(cipher, "ENC[")
	if start < 0 {
		return cipher, errors.New("fakeCrypter: not a fake-encrypted value")
	}
	end := strings.Index(cipher[start:], "]")
	if end < 0 {
		return cipher, errors.New("fakeCrypter: malformed ciphertext")
	}
	return cipher[start+4 : start+end], nil
}

func (f *fakeCrypter) KeyUsedForEncryptedFile(file string) (string, error) {
	if f.keyUsedErr != nil {
		if err := f.keyUsedErr(file); err != nil {
			return "", err
		}
	}
	f.keyLookups = append(f.keyLookups, file)
	name := f.keyName
	if name == "" {
		name = "TEST KEY"
	}
	return "DEADBEEF: " + name, nil
}

// fakeEncrypt returns the ciphertext that fakeCrypter would produce for plain.
func fakeEncrypt(plain string) string {
	return pki.PGPHeader + "\nENC[" + plain + "]\n-----END PGP MESSAGE-----"
}

// --- doString ---------------------------------------------------------------

func TestDoString(t *testing.T) {
	t.Run("encrypt plaintext calls Pki.EncryptSecret", func(t *testing.T) {
		fc := &fakeCrypter{}
		s := New("", fc, "")
		out, err := s.doString("hello", Encrypt)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if out != fakeEncrypt("hello") {
			t.Errorf("ciphertext mismatch: %q", out)
		}
		if len(fc.encrypted) != 1 || fc.encrypted[0] != "hello" {
			t.Errorf("expected one encryption of %q, got %v", "hello", fc.encrypted)
		}
	})

	t.Run("encrypt already-encrypted value is skipped", func(t *testing.T) {
		fc := &fakeCrypter{}
		s := New("", fc, "")
		ct := fakeEncrypt("secret")
		out, err := s.doString(ct, Encrypt)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if out != ct {
			t.Errorf("expected unchanged ciphertext, got %q", out)
		}
		if len(fc.encrypted) != 0 {
			t.Errorf("EncryptSecret should not have been called, got %v", fc.encrypted)
		}
	})

	t.Run("decrypt ciphertext calls Pki.DecryptSecret", func(t *testing.T) {
		fc := &fakeCrypter{}
		s := New("", fc, "")
		ct := fakeEncrypt("hello")
		out, err := s.doString(ct, Decrypt)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if out != "hello" {
			t.Errorf("expected decrypted plaintext, got %q", out)
		}
		if len(fc.decrypted) != 1 {
			t.Errorf("expected one decryption, got %d", len(fc.decrypted))
		}
	})

	t.Run("decrypt plaintext is a no-op", func(t *testing.T) {
		fc := &fakeCrypter{}
		s := New("", fc, "")
		out, err := s.doString("not encrypted", Decrypt)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if out != "not encrypted" {
			t.Errorf("expected unchanged plaintext, got %q", out)
		}
		if len(fc.decrypted) != 0 {
			t.Errorf("DecryptSecret should not have been called")
		}
	})

	t.Run("encrypt error propagates", func(t *testing.T) {
		fc := &fakeCrypter{encryptErr: func(string) error { return errors.New("boom") }}
		s := New("", fc, "")
		_, err := s.doString("hello", Encrypt)
		if err == nil || !strings.Contains(err.Error(), "boom") {
			t.Errorf("expected encrypt error, got %v", err)
		}
	})

	t.Run("decrypt error propagates", func(t *testing.T) {
		fc := &fakeCrypter{decryptErr: func(string) error { return errors.New("kaboom") }}
		s := New("", fc, "")
		_, err := s.doString(fakeEncrypt("x"), Decrypt)
		if err == nil || !strings.Contains(err.Error(), "kaboom") {
			t.Errorf("expected decrypt error, got %v", err)
		}
	})
}

// --- rotateVal --------------------------------------------------------------

func TestRotateVal(t *testing.T) {
	t.Run("encrypted value: decrypt then re-encrypt", func(t *testing.T) {
		fc := &fakeCrypter{}
		s := New("", fc, "")
		ct := fakeEncrypt("payload")
		out, err := s.rotateVal(ct)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if out != fakeEncrypt("payload") {
			t.Errorf("expected re-encrypted payload, got %q", out)
		}
		if len(fc.decrypted) != 1 || len(fc.encrypted) != 1 {
			t.Errorf("expected one decrypt + one encrypt, got %d/%d", len(fc.decrypted), len(fc.encrypted))
		}
	})

	t.Run("decrypt failure short-circuits", func(t *testing.T) {
		fc := &fakeCrypter{decryptErr: func(string) error { return errors.New("nope") }}
		s := New("", fc, "")
		_, err := s.rotateVal(fakeEncrypt("x"))
		if err == nil {
			t.Errorf("expected error, got nil")
		}
		if len(fc.encrypted) != 0 {
			t.Errorf("EncryptSecret should not have been called after decrypt failure")
		}
	})
}

// --- decryptVal -------------------------------------------------------------

func TestDecryptValPaths(t *testing.T) {
	t.Run("plaintext bypasses crypter", func(t *testing.T) {
		fc := &fakeCrypter{}
		s := New("", fc, "")
		out, err := s.decryptVal("plain")
		if err != nil || out != "plain" {
			t.Errorf("expected plain/no-err, got %q/%v", out, err)
		}
		if len(fc.decrypted) != 0 {
			t.Errorf("DecryptSecret was unexpectedly called")
		}
	})

	t.Run("error from crypter is wrapped", func(t *testing.T) {
		fc := &fakeCrypter{decryptErr: func(string) error { return errors.New("bad key") }}
		s := New("", fc, "")
		_, err := s.decryptVal(fakeEncrypt("x"))
		if err == nil || !strings.Contains(err.Error(), "error decrypting value") {
			t.Errorf("expected wrapped decrypt error, got %v", err)
		}
	})
}

// --- doSlice ----------------------------------------------------------------

func TestDoSlice(t *testing.T) {
	t.Run("encrypts strings in slice", func(t *testing.T) {
		fc := &fakeCrypter{}
		s := New("", fc, "")
		out, err := s.doSlice([]interface{}{"a", "b"}, Encrypt)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		got := out.([]interface{})
		if len(got) != 2 || got[0] != fakeEncrypt("a") || got[1] != fakeEncrypt("b") {
			t.Errorf("unexpected slice result: %v", got)
		}
	})

	t.Run("recurses into nested slice", func(t *testing.T) {
		fc := &fakeCrypter{}
		s := New("", fc, "")
		_, err := s.doSlice([]interface{}{[]interface{}{"x"}}, Encrypt)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if len(fc.encrypted) != 1 || fc.encrypted[0] != "x" {
			t.Errorf("expected nested element encrypted, got %v", fc.encrypted)
		}
	})

	t.Run("recurses into nested map", func(t *testing.T) {
		fc := &fakeCrypter{}
		s := New("", fc, "")
		_, err := s.doSlice([]interface{}{map[string]interface{}{"k": "v"}}, Encrypt)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if len(fc.encrypted) != 1 || fc.encrypted[0] != "v" {
			t.Errorf("expected map value encrypted, got %v", fc.encrypted)
		}
	})

	t.Run("skips nil items", func(t *testing.T) {
		fc := &fakeCrypter{}
		s := New("", fc, "")
		out, err := s.doSlice([]interface{}{nil, "x", nil}, Encrypt)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		got := out.([]interface{})
		if len(got) != 1 {
			t.Errorf("nil items not skipped: got %d items", len(got))
		}
	})

	t.Run("wrong input type returns error", func(t *testing.T) {
		fc := &fakeCrypter{}
		s := New("", fc, "")
		_, err := s.doSlice("not a slice", Encrypt)
		if err == nil {
			t.Errorf("expected type-mismatch error")
		}
	})

	t.Run("crypter error propagates up", func(t *testing.T) {
		fc := &fakeCrypter{encryptErr: func(string) error { return errors.New("fail") }}
		s := New("", fc, "")
		_, err := s.doSlice([]interface{}{"a"}, Encrypt)
		if err == nil {
			t.Errorf("expected error from crypter")
		}
	})
}

// --- doMap ------------------------------------------------------------------

func TestDoMap(t *testing.T) {
	t.Run("encrypts string values", func(t *testing.T) {
		fc := &fakeCrypter{}
		s := New("", fc, "")
		out, err := s.doMap(map[string]interface{}{"a": "1", "b": "2"}, Encrypt)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if out["a"] != fakeEncrypt("1") || out["b"] != fakeEncrypt("2") {
			t.Errorf("unexpected map result: %v", out)
		}
	})

	t.Run("recurses into nested map", func(t *testing.T) {
		fc := &fakeCrypter{}
		s := New("", fc, "")
		_, err := s.doMap(map[string]interface{}{
			"outer": map[string]interface{}{"inner": "secret"},
		}, Encrypt)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if len(fc.encrypted) != 1 || fc.encrypted[0] != "secret" {
			t.Errorf("expected nested value encrypted, got %v", fc.encrypted)
		}
	})

	t.Run("handles slice values", func(t *testing.T) {
		fc := &fakeCrypter{}
		s := New("", fc, "")
		_, err := s.doMap(map[string]interface{}{
			"list": []interface{}{"a", "b"},
		}, Encrypt)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if len(fc.encrypted) != 2 {
			t.Errorf("expected slice contents encrypted, got %v", fc.encrypted)
		}
	})

	t.Run("crypter error propagates from nested map", func(t *testing.T) {
		fc := &fakeCrypter{encryptErr: func(string) error { return errors.New("x") }}
		s := New("", fc, "")
		_, err := s.doMap(map[string]interface{}{
			"a": map[string]interface{}{"b": "secret"},
		}, Encrypt)
		if err == nil {
			t.Errorf("expected error to bubble up")
		}
	})
}

// --- PerformAction (end-to-end via Yaml.Values) -----------------------------

func TestPerformAction(t *testing.T) {
	t.Run("encrypt flat values", func(t *testing.T) {
		fc := &fakeCrypter{}
		s := New("", fc, "")
		s.Yaml.Values = map[string]interface{}{"k1": "v1", "k2": "v2"}
		_, err := s.PerformAction(Encrypt)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if len(fc.encrypted) != 2 {
			t.Errorf("expected 2 encryptions, got %d (%v)", len(fc.encrypted), fc.encrypted)
		}
		// values in place should be ciphertext
		for k, v := range s.Yaml.Values {
			if !strings.Contains(v.(string), "ENC[") {
				t.Errorf("value at %q not encrypted: %q", k, v)
			}
		}
	})

	t.Run("decrypt roundtrip", func(t *testing.T) {
		fc := &fakeCrypter{}
		s := New("", fc, "")
		s.Yaml.Values = map[string]interface{}{
			"plaintext": "hello",
			"cipher":    fakeEncrypt("world"),
		}
		_, err := s.PerformAction(Decrypt)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if s.Yaml.Values["plaintext"] != "hello" {
			t.Errorf("plaintext should be untouched")
		}
		if s.Yaml.Values["cipher"] != "world" {
			t.Errorf("cipher should be decrypted to 'world', got %q", s.Yaml.Values["cipher"])
		}
		if len(fc.decrypted) != 1 {
			t.Errorf("DecryptSecret should be called exactly once, got %d", len(fc.decrypted))
		}
	})

	t.Run("rotate: decrypt then re-encrypt", func(t *testing.T) {
		fc := &fakeCrypter{}
		s := New("", fc, "")
		s.Yaml.Values = map[string]interface{}{"k": fakeEncrypt("payload")}
		_, err := s.PerformAction(Rotate)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if len(fc.decrypted) != 1 || len(fc.encrypted) != 1 {
			t.Errorf("rotate should call decrypt+encrypt once each, got %d/%d", len(fc.decrypted), len(fc.encrypted))
		}
	})

	t.Run("invalid action: no encrypt/decrypt happens", func(t *testing.T) {
		fc := &fakeCrypter{}
		s := New("", fc, "")
		s.Yaml.Values = map[string]interface{}{"k": "v"}
		// PerformAction with an unknown action skips processing but still formats
		_, _ = s.PerformAction("garbage")
		if len(fc.encrypted) != 0 || len(fc.decrypted) != 0 {
			t.Errorf("unknown action should not invoke crypter")
		}
	})

	t.Run("EncryptionPath limits scope", func(t *testing.T) {
		fc := &fakeCrypter{}
		s := New("", fc, "secret_stuff")
		s.Yaml.Values = map[string]interface{}{
			"secret_stuff": "should encrypt",
			"public":       "should NOT encrypt",
		}
		_, err := s.PerformAction(Encrypt)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if len(fc.encrypted) != 1 || fc.encrypted[0] != "should encrypt" {
			t.Errorf("only secret_stuff should be encrypted, got %v", fc.encrypted)
		}
		if !strings.Contains(s.Yaml.Values["secret_stuff"].(string), "ENC[") {
			t.Errorf("secret_stuff should now be encrypted")
		}
		if s.Yaml.Values["public"] != "should NOT encrypt" {
			t.Errorf("public should be untouched, got %q", s.Yaml.Values["public"])
		}
	})

	t.Run("encrypt error propagates", func(t *testing.T) {
		fc := &fakeCrypter{encryptErr: func(string) error { return errors.New("crypto failure") }}
		s := New("", fc, "")
		s.Yaml.Values = map[string]interface{}{"k": "v"}
		_, err := s.PerformAction(Encrypt)
		if err == nil || !strings.Contains(err.Error(), "crypto failure") {
			t.Errorf("expected crypto failure error, got %v", err)
		}
	})

	t.Run("validate calls KeyUsedForEncryptedFile for encrypted values", func(t *testing.T) {
		fc := &fakeCrypter{keyName: "Salt Master"}
		s := New("", fc, "")
		s.Yaml.Values = map[string]interface{}{
			"k1": fakeEncrypt("v1"),
			"k2": fakeEncrypt("v2"),
		}
		_, err := s.PerformAction(Validate)
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if len(fc.keyLookups) != 2 {
			t.Errorf("expected two key lookups, got %d", len(fc.keyLookups))
		}
		if !strings.Contains(s.KeyMeta, "Salt Master") {
			t.Errorf("KeyMeta should mention the test key name, got %q", s.KeyMeta)
		}
	})

	t.Run("validate on plaintext value returns an error", func(t *testing.T) {
		// This documents existing behavior: validate is only meaningful on
		// encrypted .sls files, so a plaintext value surfaces a hard error.
		fc := &fakeCrypter{}
		s := New("", fc, "")
		s.Yaml.Values = map[string]interface{}{"k": "plaintext"}
		_, err := s.PerformAction(Validate)
		if err == nil || !strings.Contains(err.Error(), "not encrypted") {
			t.Errorf("expected 'value is not encrypted' error, got %v", err)
		}
	})
}

// --- ProcessValues dispatch -------------------------------------------------

func TestProcessValuesDispatch(t *testing.T) {
	fc := &fakeCrypter{}
	s := New("", fc, "")
	cases := []struct {
		name string
		val  interface{}
		want int // expected EncryptSecret call count
	}{
		{"nil bypasses", nil, 0},
		{"string goes to doString", "hello", 1},
		{"slice goes to doSlice", []interface{}{"a", "b"}, 2},
		{"map goes to doMap", map[string]interface{}{"k": "v"}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fc.encrypted = nil
			_, err := s.ProcessValues(tc.val, Encrypt)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if len(fc.encrypted) != tc.want {
				t.Errorf("expected %d encryptions, got %d (%v)", tc.want, len(fc.encrypted), fc.encrypted)
			}
		})
	}
}

// --- ProcessYaml ------------------------------------------------------------

func TestProcessYaml(t *testing.T) {
	t.Run("encrypts each name/value pair into Yaml.Values", func(t *testing.T) {
		fc := &fakeCrypter{}
		s := New("", fc, "")
		err := s.ProcessYaml([]string{"k1", "k2"}, []string{"v1", "v2"})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if len(fc.encrypted) != 2 {
			t.Errorf("expected 2 encryptions, got %d", len(fc.encrypted))
		}
	})

	t.Run("encrypt failure short-circuits", func(t *testing.T) {
		fc := &fakeCrypter{encryptErr: func(p string) error {
			if p == "v2" {
				return errors.New("denied")
			}
			return nil
		}}
		s := New("", fc, "")
		err := s.ProcessYaml([]string{"k1", "k2"}, []string{"v1", "v2"})
		if err == nil || !strings.Contains(err.Error(), "denied") {
			t.Errorf("expected denied error, got %v", err)
		}
		// first one should have succeeded before the failure
		if len(fc.encrypted) != 1 {
			t.Errorf("expected 1 successful encryption before failure, got %d", len(fc.encrypted))
		}
	})

	t.Run("fewer values than names: missing values become empty ciphertext", func(t *testing.T) {
		fc := &fakeCrypter{}
		s := New("", fc, "")
		err := s.ProcessYaml([]string{"k1", "k2"}, []string{"v1"})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		// k2 has no corresponding value, so no encryption happens for it
		if len(fc.encrypted) != 1 {
			t.Errorf("expected 1 encryption, got %d", len(fc.encrypted))
		}
	})
}

// --- keyInfo / validate path -------------------------------------------------

func TestKeyInfo(t *testing.T) {
	t.Run("plain value returns error", func(t *testing.T) {
		fc := &fakeCrypter{}
		s := New("", fc, "")
		_, err := s.keyInfo("not encrypted")
		if err == nil || !strings.Contains(err.Error(), "not encrypted") {
			t.Errorf("expected not-encrypted error, got %v", err)
		}
	})

	t.Run("encrypted value writes temp file and calls crypter", func(t *testing.T) {
		fc := &fakeCrypter{keyName: "MyKey"}
		s := New("", fc, "")
		out, err := s.keyInfo(fakeEncrypt("v"))
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		if !strings.Contains(out, "MyKey") {
			t.Errorf("expected output to mention key name, got %q", out)
		}
		if len(fc.keyLookups) != 1 {
			t.Errorf("expected one keyLookup call, got %d", len(fc.keyLookups))
		}
	})

	t.Run("crypter error wrapped", func(t *testing.T) {
		fc := &fakeCrypter{keyUsedErr: func(string) error { return errors.New("missing") }}
		s := New("", fc, "")
		_, err := s.keyInfo(fakeEncrypt("v"))
		if err == nil || !strings.Contains(err.Error(), "missing") {
			t.Errorf("expected wrapped error, got %v", err)
		}
	})
}
