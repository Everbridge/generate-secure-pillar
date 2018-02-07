package sls

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"eb-github.com/ed-silva/generate-secure-pillar/pki"
	"github.com/sirupsen/logrus"
	yaml "menteslibres.net/gosexy/yaml"
)

// pgpHeader header const
const pgpHeader = "-----BEGIN PGP MESSAGE-----"

var logger *logrus.Logger
var p pki.Pki

// Sls sls data
type Sls struct {
	SecretNames     []string
	SecretValues    []string
	TopLevelElement string
	PublicKeyRing   string
	SecretKeyRing   string
	PgpKeyName      string
	Pillar          *yaml.Yaml
}

// New return Sls struct
func New(secretNames []string, secretValues []string, topLevelElement string, publicKeyRing string, secretKeyRing string, pgpKeyName string, log *logrus.Logger) Sls {
	if log != nil {
		logger = log
	} else {
		logger = logrus.New()
	}

	s := Sls{secretNames, secretValues, topLevelElement, publicKeyRing, secretKeyRing, pgpKeyName, yaml.New()}
	p = pki.New(pgpKeyName, publicKeyRing, secretKeyRing, logger)

	return s
}

// WriteSlsFile writes a buffer to the specified file
// If the outFilePath is not stdout an INFO string will be printed to stdout
func (s *Sls) WriteSlsFile(buffer bytes.Buffer, outFilePath string) {
	fullPath, err := filepath.Abs(outFilePath)
	if err != nil {
		fullPath = outFilePath
	}

	stdOut := false
	if fullPath == os.Stdout.Name() {
		stdOut = true
	}

	err = ioutil.WriteFile(fullPath, buffer.Bytes(), 0644)
	if err != nil {
		logger.Fatal("error writing sls file: ", err)
	}
	if !stdOut {
		logger.Printf("Wrote out to file: '%s'\n", outFilePath)
	}
}

// FindSlsFiles recurses through the given searchDir returning a list of .sls files and it's length
func (s *Sls) FindSlsFiles(searchDir string) ([]string, int) {
	searchDir, err := filepath.Abs(searchDir)
	if err != nil {
		logger.Fatal(err)
	}
	fileList := []string{}
	err = filepath.Walk(searchDir, func(path string, f os.FileInfo, err error) error {
		if !f.IsDir() && strings.Contains(f.Name(), ".sls") {
			fileList = append(fileList, path)
		}
		return nil
	})
	if err != nil {
		logger.Fatal("error walking file path: ", err)
	}

	return fileList, len(fileList)
}

// PillarBuffer returns a buffer with encrypted and formatted yaml text
// If the 'all' flag is set all values under the designated top level element are encrypted
func (s *Sls) PillarBuffer(filePath string, all bool) bytes.Buffer {
	err := s.CheckForFile(filePath)
	if err != nil {
		logger.Fatal(err)
	}
	filePath, err = filepath.Abs(filePath)
	if err != nil {
		logger.Fatal(err)
	}

	err = s.Pillar.Read(filePath)
	if err != nil {
		logger.Fatal(err)
	}
	dataChanged := false

	if all {
		if s.Pillar.Get(s.TopLevelElement) != nil {
			dataChanged = s.PillarRange()
		} else {
			logger.Infof(fmt.Sprintf("%s has no %s element", filePath, s.TopLevelElement))
		}
	} else {
		s.ProcessPillar()
		dataChanged = true
	}

	if !dataChanged {
		var buffer bytes.Buffer
		return buffer
	}

	return s.FormatBuffer()
}

// ProcessPillar encrypts elements matching keys specified on the command line
func (s *Sls) ProcessPillar() {
	for index := 0; index < len(s.SecretNames); index++ {
		cipherText := ""
		if index >= 0 && index < len(s.SecretValues) {
			cipherText = p.EncryptSecret(s.SecretValues[index])
		}
		if s.Pillar.Get(s.TopLevelElement) != nil {
			err := s.Pillar.Set(s.TopLevelElement, s.SecretNames[index], cipherText)
			if err != nil {
				logger.Fatalf("error setting value: %s", err)
			}
		} else {
			err := s.Pillar.Set(s.SecretNames[index], cipherText)
			if err != nil {
				logger.Fatalf("error setting value: %s", err)
			}
		}
	}
}

// PillarRange encrypts any plain text values in the top level element
func (s *Sls) PillarRange() bool {
	var dataChanged = false
	secureVars := s.Pillar.Get(s.TopLevelElement)
	for k, v := range secureVars.(map[interface{}]interface{}) {
		if !strings.Contains(v.(string), pgpHeader) {
			cipherText := p.EncryptSecret(v.(string))
			err := s.Pillar.Set(s.TopLevelElement, k, cipherText)
			if err != nil {
				logger.Fatalf("error setting value: %s", err)
			}
			dataChanged = true
		}
	}
	return dataChanged
}

// PlainTextPillarBuffer decrypts all values under the top level element and returns a formatted buffer
func (s *Sls) PlainTextPillarBuffer(filePath string) bytes.Buffer {
	err := s.CheckForFile(filePath)
	if err != nil {
		logger.Fatal(err)
	}
	filePath, err = filepath.Abs(filePath)
	if err != nil {
		logger.Fatal(err)
	}

	err = s.Pillar.Read(filePath)
	if err != nil {
		logger.Fatal(err)
	}

	if s.Pillar.Get(s.TopLevelElement) != nil {
		for k, v := range s.Pillar.Get(s.TopLevelElement).(map[interface{}]interface{}) {
			if strings.Contains(v.(string), pgpHeader) {
				plainText := p.DecryptSecret(v.(string))
				err := s.Pillar.Set(s.TopLevelElement, k, plainText)
				if err != nil {
					logger.Fatalf("error setting value: %s", err)
				}
			}
		}
	} else {
		logger.Fatal("WTF")
	}

	return s.FormatBuffer()
}

// FormatBuffer returns a formatted .sls buffer with the gpg renderer line
func (s *Sls) FormatBuffer() bytes.Buffer {
	var buffer bytes.Buffer

	tmpfile, err := ioutil.TempFile("", "gsp_")
	if err != nil {
		logger.Fatal(err)
	}

	err = s.Pillar.Write(tmpfile.Name())
	if err != nil {
		logger.Fatal(err)
	}

	yamlData, err := ioutil.ReadFile(tmpfile.Name())
	if err != nil {
		logger.Fatal("error reading YAML file: ", err)
	}

	buffer.WriteString("#!yaml|gpg\n\n")
	buffer.WriteString(string(yamlData))

	err = os.Remove(tmpfile.Name())
	if err != nil {
		logger.Fatal(err)
	}

	return buffer
}

// CheckForFile does exactly what it says on the tin
func (s *Sls) CheckForFile(filePath string) error {
	fi, err := os.Stat(filePath)
	if err != nil {
		logger.Fatalf("cannot stat %s: %s", filePath, err)
	}
	switch mode := fi.Mode(); {
	case mode.IsRegular():
		return nil
	case mode.IsDir():
		logger.Fatalf("%s is a directory", filePath)
	}

	return err
}

// ProcessDir will recursively apply fileSlsFiles
// It will either encrypt or decrypt, as specified by the action flag
// It writes replaces the files found
func (s *Sls) ProcessDir(recurseDir string, action string) {
	info, err := os.Stat(recurseDir)
	if err != nil {
		logger.Fatalf("cannot stat %s: %s", recurseDir, err)
	}
	if info.IsDir() {
		slsFiles, count := s.FindSlsFiles(recurseDir)
		if count == 0 {
			logger.Fatalf("%s has no sls files", recurseDir)
		}
		for _, file := range slsFiles {
			var buffer bytes.Buffer
			if action == "encrypt" {
				buffer = s.PillarBuffer(file, true)
			} else if action == "decrypt" {
				buffer = s.PlainTextPillarBuffer(file)
			} else {
				logger.Fatalf("unknown action: %s", action)
			}
			s.WriteSlsFile(buffer, file)
		}
	} else {
		logger.Fatalf("%s is not a directory", recurseDir)
	}
}
