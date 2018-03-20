package sls

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"eb-github.com/ed-silva/generate-secure-pillar/pki"
	yaml "github.com/esilva-everbridge/yaml"
	"github.com/gosexy/to"
	"github.com/sirupsen/logrus"
	yamlv2 "gopkg.in/yaml.v2"
)

// pgpHeader header const
const pgpHeader = "-----BEGIN PGP MESSAGE-----"
const encrypt = "encrypt"
const decrypt = "decrypt"
const validate = "validate"

var logger *logrus.Logger

// Sls sls data
type Sls struct {
	SecretNames     []string
	SecretValues    []string
	TopLevelElement string
	PublicKeyRing   string
	SecretKeyRing   string
	PgpKeyName      string
	Yaml            *yaml.Yaml
	Pki             *pki.Pki
}

// New return Sls struct
func New(secretNames []string, secretValues []string, topLevelElement string, publicKeyRing string, secretKeyRing string, pgpKeyName string, log *logrus.Logger) Sls {
	if log != nil {
		logger = log
	} else {
		logger = logrus.New()
	}

	p := pki.New(pgpKeyName, publicKeyRing, secretKeyRing, logger)
	s := Sls{secretNames, secretValues, topLevelElement, publicKeyRing, secretKeyRing, pgpKeyName, yaml.New(), &p}

	return s
}

// ReadBytes loads YAML from a []byte
func (s *Sls) ReadBytes(buf []byte) error {
	reader := strings.NewReader(string(buf))

	err := s.ScanForIncludes(reader)
	if err != nil {
		return err
	}

	return yamlv2.Unmarshal(buf, &s.Yaml.Values)
}

// ScanForIncludes looks for include statements in the given io.Reader
func (s *Sls) ScanForIncludes(reader io.Reader) error {
	// Splits on newlines by default.
	scanner := bufio.NewScanner(reader)

	// https://golang.org/pkg/bufio/#Scanner.Scan
	for scanner.Scan() {
		txt := scanner.Text()
		if strings.Contains(txt, "include:") {
			return fmt.Errorf("contains include directives")
		}
	}
	return scanner.Err()
}

// ReadSlsFile open and read a yaml file, if the file has include statements
// we throw an error as the YAML parser will try to act on the include directives
func (s *Sls) ReadSlsFile(filePath string) error {
	fullPath, err := filepath.Abs(filePath)
	if err != nil {
		return err
	}

	var buf []byte
	buf, err = ioutil.ReadFile(fullPath)
	if err != nil {
		return err
	}

	return s.ReadBytes(buf)
}

// WriteSlsFile writes a buffer to the specified file
// If the outFilePath is not stdout an INFO string will be printed to stdout
func WriteSlsFile(buffer bytes.Buffer, outFilePath string) {
	fullPath, err := filepath.Abs(outFilePath)
	if err != nil {
		fullPath = outFilePath
	}

	stdOut := false
	if fullPath == os.Stdout.Name() {
		stdOut = true
	}

	// check that the path exists, create it if not
	if !stdOut {
		dir := filepath.Dir(fullPath)
		err = os.MkdirAll(dir, 0700)
		if err != nil {
			logger.Fatal("error writing sls file: ", err)
		}
	}

	err = ioutil.WriteFile(fullPath, buffer.Bytes(), 0644)
	if err != nil {
		logger.Fatal("error writing sls file: ", err)
	}
	if !stdOut {
		logger.Infof("wrote out to file: '%s'", outFilePath)
	}
}

// FindSlsFiles recurses through the given searchDir returning a list of .sls files and it's length
func FindSlsFiles(searchDir string) ([]string, int) {
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

// CipherTextYamlBuffer returns a buffer with encrypted and formatted yaml text
// If the 'all' flag is set all values under the designated top level element are encrypted
func (s *Sls) CipherTextYamlBuffer(filePath string) (bytes.Buffer, error) {
	var buffer bytes.Buffer
	err := CheckForFile(filePath)
	if err != nil {
		return buffer, err
	}
	filePath, err = filepath.Abs(filePath)
	if err != nil {
		return buffer, err
	}

	err = s.ReadSlsFile(filePath)
	if err != nil {
		return buffer, err
	}

	buffer = s.PerformAction(encrypt)
	return buffer, err
}

// PlainTextYamlBuffer decrypts all values under the top level element and returns a formatted buffer
func (s *Sls) PlainTextYamlBuffer(filePath string) (bytes.Buffer, error) {
	var buffer bytes.Buffer
	err := CheckForFile(filePath)
	if err != nil {
		return buffer, err
	}
	filePath, err = filepath.Abs(filePath)
	if err != nil {
		return buffer, err
	}

	err = s.ReadSlsFile(filePath)
	if err != nil {
		return buffer, err
	}

	buffer = s.PerformAction(decrypt)
	return buffer, err
}

// FormatBuffer returns a formatted .sls buffer with the gpg renderer line
func (s *Sls) FormatBuffer() bytes.Buffer {
	var buffer bytes.Buffer

	if len(s.Yaml.Values) == 0 {
		logger.Error("no values to format")
	}

	out, err := yamlv2.Marshal(s.Yaml.Values)
	if err != nil {
		logger.Fatal(err)
	}

	buffer.WriteString("#!yaml|gpg\n\n")
	buffer.WriteString(string(out))

	return buffer
}

// CheckForFile does exactly what it says on the tin
func CheckForFile(filePath string) error {
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

// ProcessYaml encrypts elements matching keys specified on the command line
func (s *Sls) ProcessYaml() {
	for index := 0; index < len(s.SecretNames); index++ {
		cipherText := ""
		if index >= 0 && index < len(s.SecretValues) {
			cipherText = s.Pki.EncryptSecret(s.SecretValues[index])
		}
		err := s.SetValueFromPath(s.SecretNames[index], cipherText)
		if err != nil {
			logger.Fatalf("error setting value: %s", err)
		}
	}
}

// ProcessDir will recursively apply findSlsFiles
// It will either encrypt or decrypt, as specified by the action flag
// It writes replaces the files found
func (s *Sls) ProcessDir(recurseDir string, action string) {
	info, err := os.Stat(recurseDir)
	if err != nil {
		logger.Fatalf("cannot stat %s: %s", recurseDir, err)
	}
	if info.IsDir() && info.Name() != ".." {
		slsFiles, count := FindSlsFiles(recurseDir)
		if count == 0 {
			logger.Fatalf("%s has no sls files", recurseDir)
		}
		for _, file := range slsFiles {
			logger.Infof("processing %s", file)
			var buffer bytes.Buffer
			if action == encrypt {
				buffer, err = s.CipherTextYamlBuffer(file)
				if err != nil {
					logger.Warnf("%s", err)
					continue
				}
			} else if action == decrypt {
				buffer, err = s.PlainTextYamlBuffer(file)
				if err != nil {
					logger.Warnf("%s", err)
					continue
				}
			} else {
				logger.Fatalf("unknown action: %s", action)
			}
			WriteSlsFile(buffer, file)
		}
	} else {
		logger.Fatalf("%s is not a directory", recurseDir)
	}
}

// ValidateDir will recursively apply findSlsFiles
// It will try to get the key info from the values in each sls file
// It returns the key info with a count of instances found
// TODO: fix this
func (s *Sls) ValidateDir(recurseDir string) []map[string]map[string]int {
	var files []map[string]map[string]int
	info, err := os.Stat(recurseDir)
	if err != nil {
		logger.Fatalf("cannot stat %s: %s", recurseDir, err)
	}
	if info.IsDir() && info.Name() != ".." {
		slsFiles, count := FindSlsFiles(recurseDir)
		if count == 0 {
			logger.Fatalf("%s has no sls files", recurseDir)
		}
		for _, file := range slsFiles {
			logger.Infof("processing %s", file)
			err = s.ReadSlsFile(file)
			if err != nil {
				logger.Fatalf("%s", err)
			}

			files = append(files, s.FileInfo(file))
		}
	} else {
		logger.Fatalf("%s is not a directory", recurseDir)
	}

	return files
}

// FileInfo gets the info on PGP keys used in a file
// including the file name, the keys used with the count of instances
func (s *Sls) FileInfo(file string) map[string]map[string]int {
	fileInfo := make(map[string]map[string]int)
	err := CheckForFile(file)
	if err != nil {
		logger.Fatalf("%s", err)
	}
	file, err = filepath.Abs(file)
	if err != nil {
		logger.Fatalf("%s", err)
	}

	err = s.ReadSlsFile(file)
	if err != nil {
		logger.Fatalf("%s", err)
	}

	fileInfo[file] = s.ValidateValues()

	return fileInfo
}

// ValidateValues takes an action string (encrypt or decrypt)
// and applies that action on all items
func (s *Sls) ValidateValues() map[string]int {
	var stuff = make(map[string]interface{})

	for key := range s.Yaml.Values {
		vals := s.GetValueFromPath(key)
		stuff[key] = s.ProcessValues(vals, validate)
	}

	fmt.Printf("STUFF: %v\n", stuff)

	var foo = make(map[string]int)
	return foo
}

// GetValueFromPath returns the value from a path string
func (s *Sls) GetValueFromPath(path string) interface{} {
	parts := strings.Split(path, ":")

	args := make([]interface{}, len(parts))
	for i := 0; i < len(parts); i++ {
		args[i] = parts[i]
	}
	results := s.Yaml.Get(args...)
	return results
}

// SetValueFromPath returns the value from a path string
func (s *Sls) SetValueFromPath(path string, value string) error {
	parts := strings.Split(path, ":")

	// construct the args list
	args := make([]interface{}, len(parts)+1)
	for i := 0; i < len(parts); i++ {
		args[i] = parts[i]
	}
	args[len(args)-1] = value
	err := s.Yaml.Set(args...)
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s", err)
}

// PerformAction takes an action string (encrypt or decrypt)
// and applies that action on all items
func (s *Sls) PerformAction(action string) bytes.Buffer {

	if action == encrypt || action == decrypt {
		var stuff = make(map[string]interface{})

		for key := range s.Yaml.Values {
			if s.TopLevelElement != "" {
				vals := s.GetValueFromPath(key)
				if s.TopLevelElement == key {
					stuff[key] = s.ProcessValues(vals, action)
				} else {
					stuff[key] = vals
				}
			} else {
				vals := s.GetValueFromPath(key)
				stuff[key] = s.ProcessValues(vals, action)
			}
		}
		// replace the values in the Yaml object
		s.Yaml.Values = stuff
	}

	return s.FormatBuffer()
}

// ProcessValues will encrypt or decrypt given values
func (s *Sls) ProcessValues(vals interface{}, action string) interface{} {
	vtype := reflect.TypeOf(vals).Kind()

	var res interface{}
	switch vtype {
	case reflect.Slice:
		res = s.doSlice(vals, action)
	case reflect.Map:
		res = s.doMap(vals.(map[interface{}]interface{}), action)
	case reflect.String:
		strVal := to.String(vals)
		switch action {
		case decrypt:
			strVal = s.decryptVal(strVal)
		case encrypt:
			if !isEncrypted(strVal) {
				strVal = s.Pki.EncryptSecret(strVal)
			}
		case validate:
			if isEncrypted(strVal) {
				strVal = s.keyInfo(strVal)
			}
		}
		res = strVal
	}

	return res
}

func (s *Sls) doSlice(vals interface{}, action string) interface{} {
	var things []interface{}

	for _, item := range vals.([]interface{}) {
		var thing interface{}
		vtype := reflect.TypeOf(item).Kind()

		switch vtype {
		case reflect.Slice:
			things = append(things, s.doSlice(item, action))
		case reflect.Map:
			thing = item
			things = append(things, s.doMap(thing.(map[interface{}]interface{}), action))
		case reflect.String:
			strVal := to.String(item)
			switch action {
			case decrypt:
				thing = s.decryptVal(strVal)
			case encrypt:
				if !isEncrypted(strVal) {
					thing = s.Pki.EncryptSecret(strVal)
				}
			case validate:
				thing = s.keyInfo(strVal)
			}
			things = append(things, thing)
		}
	}

	return things
}

func (s *Sls) doMap(vals map[interface{}]interface{}, action string) map[interface{}]interface{} {
	var ret = make(map[interface{}]interface{})

	for key, val := range vals {
		vtype := reflect.TypeOf(val).Kind()

		switch vtype {
		case reflect.Slice:
			ret[key] = s.doSlice(val, action)
		case reflect.Map:
			ret[key] = s.doMap(val.(map[interface{}]interface{}), action)
		case reflect.String:
			strVal := to.String(val)
			switch action {
			case decrypt:
				val = s.decryptVal(strVal)
			case encrypt:
				if !isEncrypted(strVal) {
					val = s.Pki.EncryptSecret(strVal)
				}
			case validate:
				val = s.keyInfo(strVal)
			}
			ret[key] = val
		}
	}

	return ret
}

func isEncrypted(str string) bool {
	return strings.Contains(str, pgpHeader)
}

// RotateFile decrypts a file and re-encrypts with the given key
func (s *Sls) RotateFile(file string, limChan chan bool) {
	logger.Infof("processing %s", file)

	buffer, err := s.PlainTextYamlBuffer(file)
	if err != nil {
		logger.Errorf("%s", err)
	}
	buffer = s.PerformAction("encrypt")
	WriteSlsFile(buffer, file)
	limChan <- true
}

func (s *Sls) keyInfo(val string) string {
	tmpfile, err := ioutil.TempFile("", "gsp-")
	if err != nil {
		log.Fatal(err)
	}

	if _, err = tmpfile.Write([]byte(val)); err != nil {
		log.Fatal(err)
	}

	keyInfo, err := s.Pki.KeyUsedForEncryptedFile(tmpfile.Name())
	if err != nil {
		log.Fatal(err)
	}

	if err = tmpfile.Close(); err != nil {
		log.Fatal(err)
	}
	if err = os.Remove(tmpfile.Name()); err != nil {
		log.Fatal(err)
	}

	var keyStr string
	lines := strings.Split(keyInfo, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "encrypted with") {
			keyStr = formatLine(keyStr, line)
		}
		if strings.Contains(line, "\"") {
			keyStr = formatLine(keyStr, line)
		}
	}

	return keyStr
}

func formatLine(str string, line string) string {
	if len(str) > 0 {
		str = fmt.Sprintf("%s %s", str, line)
	} else {
		str = str + line
	}
	return str
}

func (s *Sls) decryptVal(strVal string) string {
	var plainText string

	if isEncrypted(strVal) {
		var err error
		plainText, err = s.Pki.DecryptSecret(strVal)
		if err != nil {
			logger.Errorf("error decrypting value: %s", err)
		}
	}

	return plainText
}
