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
const encrypt = "encrypt"
const decrypt = "decrypt"

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

// PerformAction takes an action string (encrypt ot decrypt)
// and applies that action on all items
func (s *Sls) PerformAction(action string) bytes.Buffer {
	var stuff = make(map[string]interface{})

	for key := range s.Yaml.Values {
		vals := s.Yaml.Get(key)
		vtype := reflect.TypeOf(vals).Kind()

		var res interface{}
		switch vtype {
		case reflect.Slice:
			res = doSlice(vals, action)
		case reflect.Map:
			res = doMap(vals.(map[interface{}]interface{}), action)
		case reflect.String:
			switch action {
			case decrypt:
				if isEncrypted(vals.(string)) {
					vals = p.DecryptSecret(vals.(string))
				}
			case encrypt:
				if !isEncrypted(vals.(string)) {
					vals = p.EncryptSecret(vals.(string))
				}
			}
			res = vals.(string)
		}

		stuff[key] = res
	}

	// replace the values in the Yaml object
	s.Yaml.Values = stuff

	return s.FormatBuffer()
}

func doSlice(vals interface{}, action string) interface{} {
	var things []interface{}

	for _, item := range vals.([]interface{}) {
		vtype := reflect.TypeOf(item).Kind()

		switch vtype {
		case reflect.Slice:
			things = append(things, doSlice(item, action))
		case reflect.Map:
			things = append(things, doMap(item.(map[interface{}]interface{}), action))
		case reflect.String:
			switch action {
			case decrypt:
				if isEncrypted(item.(string)) {
					item = p.DecryptSecret(item.(string))
				}
			case encrypt:
				if !isEncrypted(item.(string)) {
					item = p.EncryptSecret(item.(string))
				}
			}
			things = append(things, item)
		}
	}

	return things
}

func doMap(vals map[interface{}]interface{}, action string) map[interface{}]interface{} {
	var ret = make(map[interface{}]interface{})

	for key, val := range vals {
		vtype := reflect.TypeOf(val).Kind()

		switch vtype {
		case reflect.Slice:
			ret[key] = doSlice(val, action)
		case reflect.Map:
			ret = doMap(val.(map[interface{}]interface{}), action)
		case reflect.String:
			switch action {
			case decrypt:
				if isEncrypted(val.(string)) {
					val = p.DecryptSecret(val.(string))
				}
			case encrypt:
				if !isEncrypted(val.(string)) {
					val = p.EncryptSecret(val.(string))
				}
			}
			ret[key] = val
		}
	}

	return ret
}

func isEncrypted(str string) bool {
	return strings.Contains(str, pgpHeader)
}
