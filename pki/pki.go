package pki

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
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
	PublicKey     *openpgp.Entity
}

// PGPKey struct
type PGPKey struct {
	Pub     string
	UIDs    []string
	SubKeys []string
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
	if p.PublicKey == nil {
		logger.Fatalf("unable to find key '%s' in %s", p.PgpKeyName, p.PublicKeyRing)
	}

	if err = pubringFile.Close(); err != nil {
		logger.Fatal("error closing pubring: ", err)
	}

	return p
}

// PromptFunction prompts for secure key pass phrase
// func (p *Pki) PromptFunction(keys []openpgp.Key, symmetric bool) ([]byte, error) {
// 	conn, err := gpgagent.NewGpgAgentConn()
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer conn.Close()

// 	for _, key := range keys {
// 		cacheID := strings.ToUpper(hex.EncodeToString(key.PublicKey.Fingerprint[:]))

// 		// TODO: Add prompt, etc.
// 		request := gpgagent.PassphraseRequest{CacheKey: cacheID}

// 		passphrase, err := conn.GetPassphrase(&request)
// 		if err != nil {
// 			return nil, err
// 		}

// 		err = key.PrivateKey.Decrypt([]byte(passphrase))
// 		if err != nil {
// 			return nil, err
// 		}

// 		return []byte(passphrase), nil
// 	}

// 	return nil, fmt.Errorf("Unable to find key")
// }

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
func (p *Pki) GetKeyByID(keyring openpgp.EntityList, id interface{}) *openpgp.Entity {
	for _, entity := range keyring {

		idType := reflect.TypeOf(id).Kind()
		switch idType {
		case reflect.Uint64:
			if entity.PrimaryKey.KeyId == id.(uint64) {
				return entity
			} else if entity.PrivateKey.KeyId == id.(uint64) {
				return entity
			}
		case reflect.String:
			for _, ident := range entity.Identities {
				if ident.Name == id.(string) {
					return entity
				}
				if ident.UserId.Email == id.(string) {
					return entity
				}
				if ident.UserId.Name == id.(string) {
					return entity
				}
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
	filePath, err := checkPGPFile(file)
	if err != nil {
		return "", err
	}

	gpgCmd, err := gpgPath()
	if err != nil {
		return "", err
	}

	var cmd exec.Cmd
	cmd.Path = gpgCmd
	cmd.Args = []string{gpgCmd, "--list-packets", "--list-only", "--keyid-format", "long", filePath}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}

	var keyStr string
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, " keyid ") {
			words := strings.Split(line, ",")
			line = words[len(words)-1]
			words = strings.Split(line, " ")
			keyStr = strings.TrimSpace(words[len(words)-1])
		}
	}
	if keyStr == "" {
		return "", fmt.Errorf("can't parse pgp key info")
	}

	keyInfo, err := p.PGPKeyInfo(keyStr)
	if err != nil {
		return "", err
	}

	return keyInfo.Pub, nil
}

// PGPKeyInfo return long format key info
func (p *Pki) PGPKeyInfo(keyID string) (PGPKey, error) {
	var key PGPKey
	gpgCmd, err := gpgPath()
	if err != nil {
		return key, err
	}

	var cmd exec.Cmd
	cmd.Path = gpgCmd
	cmd.Args = []string{gpgCmd, "--list-keys", "--keyid-format", "long", keyID}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return key, err
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		part := pubType(line)
		if part != "" {
			key.Pub = part
		}
		part = uidType(line)
		if part != "" {
			key.UIDs = append(key.UIDs, part)
		}
		part = subType(line)
		if part != "" {
			key.SubKeys = append(key.SubKeys, part)
		}
	}

	return key, nil
}

func gpgPath() (string, error) {
	gpgCmd, err := exec.LookPath("gpg1")
	if err != nil {
		return exec.LookPath("gpg")
	}
	return gpgCmd, err
}

func checkPGPFile(file string) (string, error) {
	filePath, err := filepath.Abs(file)
	if err != nil {
		return filePath, err
	}

	in, err := os.Open(filePath)
	if err != nil {
		return filePath, err
	}

	block, err := armor.Decode(in)
	if err != nil {
		return filePath, err
	}

	if block.Type != "PGP MESSAGE" {
		return filePath, fmt.Errorf("error decoding private key")
	}

	return filePath, in.Close()
}

func pubType(line string) string {
	re := regexp.MustCompile(`^pub\s+(.*?)$`)
	return regexMatch(re, line)
}

func uidType(line string) string {
	re := regexp.MustCompile(`^uid\s+(.*?)$`)
	return regexMatch(re, line)
}

func subType(line string) string {
	re := regexp.MustCompile(`^sub\s+(.*?)$`)
	return regexMatch(re, line)
}

func regexMatch(re *regexp.Regexp, line string) string {
	match := re.FindStringSubmatch(line)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}
