package sls

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"eb-github.com/ed-silva/generate-secure-pillar/pki"
	yaml "github.com/esilva-everbridge/yaml"
	"github.com/sirupsen/logrus"
	yamlv1 "gopkg.in/yaml.v1"
	"menteslibres.net/gosexy/to"
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
	Yaml            *yaml.Yaml
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

// YamlBuffer returns a buffer with encrypted and formatted yaml text
// If the 'all' flag is set all values under the designated top level element are encrypted
func (s *Sls) YamlBuffer(filePath string, all bool) bytes.Buffer {
	var dataChanged bool

	err := s.CheckForFile(filePath)
	if err != nil {
		logger.Fatal(err)
	}
	filePath, err = filepath.Abs(filePath)
	if err != nil {
		logger.Fatal(err)
	}

	err = s.Yaml.Read(filePath)
	if err != nil {
		logger.Fatal(err)
	}

	if all {
		// if s.Yaml.Get(s.TopLevelElement) != nil {
		dataChanged = s.YamlRange()
		// } else {
		// 	logger.Infof(fmt.Sprintf("%s has no %s element", filePath, s.TopLevelElement))
		// }
	} else {
		s.ProcessYaml()
		dataChanged = true
	}

	if !dataChanged {
		var buffer bytes.Buffer
		return buffer
	}

	return s.FormatBuffer()
}

// ProcessYaml encrypts elements matching keys specified on the command line
func (s *Sls) ProcessYaml() {
	for index := 0; index < len(s.SecretNames); index++ {
		cipherText := ""
		if index >= 0 && index < len(s.SecretValues) {
			cipherText = p.EncryptSecret(s.SecretValues[index])
		}
		if s.Yaml.Get(s.TopLevelElement) != nil {
			err := s.Yaml.Set(s.TopLevelElement, s.SecretNames[index], cipherText)
			if err != nil {
				logger.Fatalf("error setting value: %s", err)
			}
		} else {
			fmt.Printf("PATH: %s\n", s.SecretNames[index])
			err := s.SetValueFromPath(s.SecretNames[index], cipherText)
			if err != nil {
				logger.Fatalf("error setting value: %s", err)
			}
		}
	}
}

// YamlRange encrypts any plain text values in the top level element
func (s *Sls) YamlRange() bool {
	var dataChanged = false
	secureVars := s.Yaml.Get(s.TopLevelElement)
	for k, v := range secureVars.(map[interface{}]interface{}) {
		if !strings.Contains(v.(string), pgpHeader) {
			cipherText := p.EncryptSecret(v.(string))
			err := s.Yaml.Set(s.TopLevelElement, k, cipherText)
			if err != nil {
				logger.Fatalf("error setting value: %s", err)
			}
			dataChanged = true
		}
	}
	return dataChanged
}

// PlainTextYamlBuffer decrypts all values under the top level element and returns a formatted buffer
func (s *Sls) PlainTextYamlBuffer(filePath string) bytes.Buffer {
	err := s.CheckForFile(filePath)
	if err != nil {
		logger.Fatal(err)
	}
	filePath, err = filepath.Abs(filePath)
	if err != nil {
		logger.Fatal(err)
	}

	err = s.Yaml.Read(filePath)
	if err != nil {
		logger.Fatal(err)
	}

	// if s.Yaml.Get(s.TopLevelElement) != nil {
	for k, v := range s.Yaml.Get(s.TopLevelElement).(map[interface{}]interface{}) {
		// fmt.Printf("k: %s\n", k)
		// fmt.Printf("v: %#v\n", v)
		if isEncrypted(v.(string)) {
			plainText := p.DecryptSecret(v.(string))
			err := s.Yaml.Set(s.TopLevelElement, k, plainText)
			if err != nil {
				logger.Fatalf("error setting value: %s", err)
			}
		}
	}
	// } else {
	// 	logger.Fatal("WTF")
	// }

	return s.FormatBuffer()
}

// FormatBuffer returns a formatted .sls buffer with the gpg renderer line
func (s *Sls) FormatBuffer() bytes.Buffer {
	var buffer bytes.Buffer

	out, err := yamlv1.Marshal(s.Yaml.Values)
	if err != nil {
		logger.Fatal(err)
	}

	buffer.WriteString("#!yaml|gpg\n\n")
	buffer.WriteString(string(out))

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
				buffer = s.YamlBuffer(file, true)
			} else if action == "decrypt" {
				buffer = s.PlainTextYamlBuffer(file)
			} else {
				logger.Fatalf("unknown action: %s", action)
			}
			s.WriteSlsFile(buffer, file)
		}
	} else {
		logger.Fatalf("%s is not a directory", recurseDir)
	}
}

// DecryptSecrets decrypts secret strings
func (s *Sls) DecryptSecrets() bytes.Buffer {
	for index := 0; index < len(s.SecretNames); index++ {
		vals := s.GetValueFromPath(s.SecretNames[index])
		for _, val := range vals {
			if val.Interface() != nil && isEncrypted(to.String(val)) {
				plainText := p.DecryptSecret(to.String(val))
				fmt.Printf("PLAIN TEXT: %s\n", plainText)
				err := s.SetValueFromPath(s.SecretNames[index], plainText)
				if err != nil {
					logger.Fatalf("Error setting value: %s", err)
				}
			}
		}
	}

	return s.FormatBuffer()
}

// Stuff does stuff
func (s *Sls) Stuff() bytes.Buffer {
	for key := range s.Yaml.Values {
		var isEnc bool
		var path string

		fmt.Printf("TOP KEY: %#v\n", key)

		vals := s.Yaml.Get(key)
		vtype := reflect.TypeOf(vals).Kind()
		if vtype == reflect.Map {
			path, isEnc = processMap(key, vals.(map[interface{}]interface{}))
		} else if vtype == reflect.Slice {
			path, isEnc = processSlice(key, vals.([]interface{}))
		} else if vtype == reflect.String {
			path = key
			isEnc = isEncrypted(vals.(string))
		}

		fmt.Printf("%s isEnc: %v\n", path, to.String(isEnc))
		if isEnc {
			results := s.GetValueFromPath(path)
			for i, res := range results {
				val := res.Interface()
				vtype = reflect.TypeOf(val).Kind()
				fmt.Printf("vtype: %v\n", vtype)
				if vtype == reflect.String && isEncrypted(val.(string)) {
					plainText := p.DecryptSecret(val.(string))
					fmt.Printf("RESULT %d: %#v\n", i+1, plainText)
					err := s.SetValueFromPath(path, plainText)
					if err != nil {
						logger.Fatalf("Error setting value: %s", err)
					}
				}
				fmt.Printf("final path: %s\n", path)
			}
		}
	}

	return s.FormatBuffer()
}

// GetValueFromPath returns the value from a path string
func (s *Sls) GetValueFromPath(path string) []reflect.Value {
	parts := strings.Split(path, ":")

	fnValue := reflect.ValueOf(s.Yaml.Get)
	args := make([]reflect.Value, len(parts))
	for i := 0; i < len(parts); i++ {
		args[i] = reflect.ValueOf(parts[i])
	}
	return fnValue.Call(args)
}

// SetValueFromPath returns the value from a path string
func (s *Sls) SetValueFromPath(path string, value string) error {
	parts := strings.Split(path, ":")

	fnValue := reflect.ValueOf(s.Yaml.Set)
	args := make([]reflect.Value, len(parts)+1)
	for i := 0; i < len(parts); i++ {
		args[i] = reflect.ValueOf(parts[i])
	}
	args[len(parts)] = reflect.ValueOf(value)
	results := fnValue.Call(args)
	err := results[0].Interface()
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s", err.(string))
}

func processMap(parentKey string, vals map[interface{}]interface{}) (string, bool) {
	var path string
	var matches bool

	fmt.Printf("PARENT: %s\n", parentKey)

	// the top level of the YAML will be a map, after that we aren't sure
	for k, v := range vals {
		matches = false
		var buffer bytes.Buffer
		buffer.WriteString(parentKey)

		vtype := reflect.TypeOf(v).Kind()
		fmt.Printf("K: %s vtype: %v\n", k, vtype)
		if vtype == reflect.Map {
			if buffer.Len() > 0 {
				buffer.WriteString(":")
			}
			buffer.WriteString(to.String(k))
			path, matches = processMap(buffer.String(), v.(map[interface{}]interface{}))
			buffer.Reset()
			buffer.WriteString(path)
		} else if vtype == reflect.Slice {
			if buffer.Len() > 0 {
				buffer.WriteString(":")
			}
			buffer.WriteString(to.String(k))
			path, matches = processSlice(buffer.String(), v.([]interface{}))
			buffer.Reset()
			buffer.WriteString(path)
		} else if vtype == reflect.String {
			if isEncrypted(v.(string)) {
				if buffer.Len() > 0 {
					buffer.WriteString(":")
				}
				buffer.WriteString(to.String(k))
				matches = true
			}
		}
		path = buffer.String()
	}

	return path, matches
}

func processSlice(parentKey string, vals []interface{}) (string, bool) {
	var path string
	var matches bool

	for v := range vals {
		matches = false
		var buffer bytes.Buffer
		buffer.WriteString(parentKey)

		vtype := reflect.TypeOf(vals[v]).Kind()
		if vtype == reflect.Map {
			path, matches = processMap(buffer.String(), vals[v].(map[interface{}]interface{}))
			buffer.Reset()
			buffer.WriteString(path)
		} else if vtype == reflect.Slice {
			path, matches = processSlice(buffer.String(), vals[v].([]interface{}))
			buffer.Reset()
			buffer.WriteString(path)
		} else if vtype == reflect.String {
			if isEncrypted(vals[v].(string)) {
				matches = true
			}
		}
		path = buffer.String()
	}

	return path, matches
}

func isEncrypted(str string) bool {
	return strings.Contains(str, pgpHeader)
}
