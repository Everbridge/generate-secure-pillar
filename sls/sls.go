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

// Package sls handles parsing of Salt Pillar files
package sls

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/Everbridge/generate-secure-pillar/pki"
	yaml "github.com/esilva-everbridge/yaml"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	yamlv3 "gopkg.in/yaml.v3"
)

// Encrypt action
const Encrypt = "encrypt"

// Decrypt action
const Decrypt = "decrypt"

// Validate action (keys)
const Validate = "validate"

// Rotate action
const Rotate = "rotate"

var logger = zerolog.New(os.Stdout)

// Sls sls data
type Sls struct {
	Error          error
	Yaml           *yaml.Yaml
	Pki            *pki.Pki
	KeyMap         map[string]interface{}
	FilePath       string
	EncryptionPath string
	KeyMeta        string
	KeyCount       int
	IsInclude      bool
}

// New returns a Sls object
func New(filePath string, p pki.Pki, encPath string) Sls {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout})
	s := Sls{nil, yaml.New(), &p, map[string]interface{}{}, filePath, encPath, "", 0, false}
	if len(filePath) > 0 {
		err := s.ReadSlsFile()
		if err != nil {
			logger.Error().Err(err).Msgf("init error for %s", s.FilePath)
			s.Error = err
		}
	}

	return s
}

// ReadBytes loads YAML from a []byte
func (s *Sls) ReadBytes(buf []byte) error {
	reader := strings.NewReader(string(buf))

	err := s.ScanForIncludes(reader)
	if err != nil {
		s.IsInclude = true
		logger.Warn().Err(err)
	}

	return yamlv3.Unmarshal(buf, &s.Yaml.Values)
}

// ScanForIncludes looks for include statements in the given io.Reader
func (s *Sls) ScanForIncludes(reader io.Reader) error {
	// Splits on newlines by default.
	scanner := bufio.NewScanner(reader)

	// https://golang.org/pkg/bufio/#Scanner.Scan
	for scanner.Scan() {
		txt := scanner.Text()
		if strings.Contains(txt, "include:") {
			return fmt.Errorf("%s contains include directives", shortFileName(s.FilePath))
		}
	}
	return scanner.Err()
}

// ReadSlsFile open and read a yaml file, if the file has include statements
// we throw an error as the YAML parser will try to act on the include directives
func (s *Sls) ReadSlsFile() error {
	if len(s.FilePath) == 0 {
		return fmt.Errorf("no file path given")
	}

	if s.FilePath == os.Stdout.Name() {
		return nil
	}

	// this could be called when creating a new file, so check the path
	if _, statErr := os.Stat(s.FilePath); statErr == nil {
		dir := filepath.Dir(s.FilePath)
		err := os.MkdirAll(dir, 0700)
		if err != nil {
			return err
		}
		_, err = os.OpenFile(s.FilePath, os.O_RDONLY|os.O_CREATE, 0600)
		if err != nil {
			return err
		}
	}

	fullPath, err := filepath.Abs(s.FilePath)
	if err != nil {
		return err
	}

	var buf []byte
	buf, err = os.ReadFile(filepath.Clean(fullPath))
	if err != nil {
		return err
	}

	return s.ReadBytes(buf)
}

// WriteSlsFile writes a buffer to the specified file
// If the outFilePath is not stdout an INFO string will be printed to stdout
func WriteSlsFile(buffer bytes.Buffer, outFilePath string) (int, error) {
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
			return buffer.Len(), fmt.Errorf("error creating sls path: %s", err)
		}
	}

	var byteCount int
	if stdOut {
		byteCount, err = os.Stdout.Write(buffer.Bytes())
	} else {
		byteCount, err = atomicWrite(fullPath, buffer)
	}

	if !stdOut && err == nil {
		shortFile := shortFileName(outFilePath)
		logger.Info().Msgf("wrote out to file: '%s'", shortFile)
	}

	return byteCount, err
}

func atomicWrite(fullPath string, buffer bytes.Buffer) (int, error) {
	_, name := path.Split(fullPath)
	f, err := os.CreateTemp("", fmt.Sprintf("gsp-%s", name))
	if err != nil {
		return 0, err
	}
	byteCount, err := f.Write(buffer.Bytes())
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if permErr := os.Chmod(f.Name(), 0600); err == nil {
		err = permErr
	}
	if err == nil {
		err = copyFile(f.Name(), fullPath)
	}
	if err != nil {
		return byteCount, err
	}

	if _, statErr := os.Stat(f.Name()); !os.IsNotExist(statErr) {
		err = os.Remove(f.Name())
	}

	return byteCount, err
}

func copyFile(src string, dst string) error {
	srcStat, err := os.Stat(src)
	if err != nil {
		return err
	}

	fsrc, err := os.Open(filepath.Clean(src))
	if err != nil {
		return err
	}

	fdst, err := os.Create(dst)
	if err != nil {
		return err
	}

	size, err := io.Copy(fdst, fsrc)
	if err != nil {
		return err
	}
	if size != srcStat.Size() {
		return fmt.Errorf("%s: %d/%d copied", src, size, srcStat.Size())
	}

	err = fsrc.Close()
	if err != nil {
		return fdst.Close()
	}
	return err
}

// FormatBuffer returns a formatted .sls buffer with the gpg renderer line
func (s *Sls) FormatBuffer(action string) (bytes.Buffer, error) {
	var buffer bytes.Buffer
	var out []byte
	var err error
	var data map[string]interface{}

	if action != Validate {
		data = s.Yaml.Values
	} else {
		data = s.KeyMap
	}

	if len(data) == 0 {
		return buffer, fmt.Errorf("%s has no values to format", s.FilePath)
	}

	out, err = yamlv3.Marshal(data)
	if err != nil {
		return buffer, fmt.Errorf("%s format error: %s", s.FilePath, err)
	}

	if action != Validate {
		_, err = buffer.WriteString("#!yaml|gpg\n\n")
		if err != nil {
			return buffer, fmt.Errorf("%s format error: %s", s.FilePath, err)
		}
	}
	_, err = buffer.WriteString(string(out))

	return buffer, err
}

// ProcessYaml encrypts elements matching keys specified on the command line
func (s *Sls) ProcessYaml(secretNames []string, secretValues []string) error {
	var err error

	for index := 0; index < len(secretNames); index++ {
		cipherText := ""
		if index >= 0 && index < len(secretValues) {
			cipherText, err = s.Pki.EncryptSecret(secretValues[index])
			if err != nil {
				return err
			}
		}
		err = s.SetValueFromPath(secretNames[index], cipherText)
		if err != nil {
			return err
		}
	}

	return err
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
func (s *Sls) PerformAction(action string) (bytes.Buffer, error) {
	var err error
	var buf bytes.Buffer

	if validAction(action) {
		var stuff = make(map[string]interface{})

		for key := range s.Yaml.Values {
			if s.EncryptionPath != "" {
				vals := s.GetValueFromPath(key)
				if s.EncryptionPath == key {
					stuff[key], err = s.ProcessValues(vals, action)
					if err != nil {
						return buf, err
					}
				} else {
					stuff[key] = vals
				}
			} else {
				vals := s.GetValueFromPath(key)
				stuff[key], err = s.ProcessValues(vals, action)
				if err != nil {
					return buf, err
				}
			}
		}
		if action != Validate {
			// replace the values in the Yaml object
			s.Yaml.Values = stuff
		} else {
			s.KeyMap = stuff
			var vals []string
			for _, v := range s.KeyMap {
				if v != nil {
					node := getNode(v.(interface{}))
					if node != nil {
						vals = append(vals, node.(string))
					}
				}
			}
			unique := removeDuplicates(vals)
			buf := bytes.Buffer{}
			buf.WriteString(fmt.Sprintf("%d keys found:\n", len(unique)))
			for i := range unique {
				buf.WriteString(fmt.Sprintf("  %s", unique[i]))
			}
			s.KeyMeta = buf.String()
			s.KeyCount = len(unique)
		}
	}

	return s.FormatBuffer(action)
}

// ProcessValues will encrypt or decrypt given values
func (s *Sls) ProcessValues(vals interface{}, action string) (interface{}, error) {
	var res interface{}

	if vals == nil {
		return res, nil
	}
	vtype := reflect.TypeOf(vals).Kind()
	switch vtype {
	case reflect.Slice:
		return s.doSlice(vals, action)
	case reflect.Map:
		return s.doMap(vals.(map[string]interface{}), action)
	default:
		return s.doString(vals, action)
	}
}

func (s *Sls) doSlice(vals interface{}, action string) (interface{}, error) {
	var things []interface{}

	if vals == nil {
		return things, nil
	}

	for _, item := range vals.([]interface{}) {
		var thing interface{}
		vtype := reflect.TypeOf(item).Kind()

		switch vtype {
		case reflect.Slice:
			sliceStuff, err := s.doSlice(item, action)
			if err != nil {
				return vals, err
			}
			things = append(things, sliceStuff)
		case reflect.Map:
			thing = item
			mapStuff, err := s.doMap(thing.(map[string]interface{}), action)
			if err != nil {
				return vals, err
			}
			things = append(things, mapStuff)
		default:
			thing, err := s.doString(item, action)
			if err != nil {
				return vals, err
			}
			things = append(things, thing)
		}
	}

	return things, nil
}

func (s *Sls) doMap(vals map[string]interface{}, action string) (map[string]interface{}, error) {
	var ret = make(map[string]interface{})
	var err error

	for key, val := range vals {
		if val == nil {
			return ret, err
		}

		vtype := reflect.TypeOf(val).Kind()
		switch vtype {
		case reflect.Slice:
			ret[key], err = s.doSlice(val, action)
		case reflect.Map:
			ret[key], err = s.doMap(val.(map[string]interface{}), action)
		default:
			ret[key], err = s.doString(val, action)
		}
	}

	return ret, err
}

func (s *Sls) doString(val interface{}, action string) (string, error) {
	var err error

	// %v is a 'cheat' in that it will convert any type
	// and allow it to be used as a string output with sprintf
	strVal := fmt.Sprintf("%v", val)

	switch action {
	case Decrypt:
		strVal, err = s.decryptVal(strVal)
		if err != nil {
			return strVal, err
		}
	case Encrypt:
		if !isEncrypted(strVal) {
			strVal, err = s.Pki.EncryptSecret(strVal)
			if err != nil {
				return strVal, err
			}
		}
	case Validate:
		strVal, err = s.keyInfo(strVal)
		if err != nil {
			return strVal, err
		}
	case Rotate:
		strVal, err = s.rotateVal(strVal)
		if err != nil {
			return strVal, err
		}
	}

	return strVal, err
}

func (s *Sls) rotateVal(strVal string) (string, error) {
	strVal, err := s.decryptVal(strVal)
	if err != nil {
		return strVal, err
	}
	return s.Pki.EncryptSecret(strVal)
}

func isEncrypted(str string) bool {
	return strings.Contains(str, pki.PGPHeader)
}

func (s *Sls) keyInfo(val string) (string, error) {
	if !isEncrypted(val) {
		return val, fmt.Errorf("value is not encrypted")
	}

	tmpfile, err := os.CreateTemp("", "gsp-")
	if err != nil {
		return val, fmt.Errorf("keyInfo: %s", err)
	}

	if _, err = tmpfile.Write([]byte(val)); err != nil {
		return val, fmt.Errorf("keyInfo: %s", err)
	}

	keyInfo, err := s.Pki.KeyUsedForEncryptedFile(tmpfile.Name())
	if err != nil {
		return val, fmt.Errorf("keyInfo: %s", err)
	}

	if err = tmpfile.Close(); err != nil {
		return val, fmt.Errorf("keyInfo: %s", err)
	}
	if err = os.Remove(tmpfile.Name()); err != nil {
		return val, fmt.Errorf("keyInfo: %s", err)
	}

	return keyInfo, nil
}

func (s *Sls) decryptVal(strVal string) (string, error) {
	var plainText string

	if isEncrypted(strVal) {
		var err error
		plainText, err = s.Pki.DecryptSecret(strVal)
		if err != nil {
			return strVal, fmt.Errorf("error decrypting value: %s", err)
		}
	} else {
		return strVal, nil
	}

	return plainText, nil
}

func validAction(action string) bool {
	return action == Encrypt || action == Decrypt || action == Validate || action == Rotate
}

func shortFileName(file string) string {
	pwd, err := os.Getwd()
	if err != nil {
		logger.Warn().Err(err)
		return file
	}
	return strings.Replace(file, pwd+"/", "", 1)
}

func getNode(v interface{}) interface{} {
	var node interface{}
	vtype := reflect.TypeOf(v)
	kind := vtype.Kind()

	switch kind {
	case reflect.Slice:
	case reflect.Map:
		for _, v2 := range v.(map[string]interface{}) {
			node = getNode(v2.(interface{}))
		}
	default:
		node = fmt.Sprintf("%v", v)
	}
	return node
}

func removeDuplicates(elements []string) []string {
	seen := make(map[string]bool)
	var result []string

	for v := range elements {
		if seen[elements[v]] {
			// skip it
		} else {
			seen[elements[v]] = true
			result = append(result, elements[v])
		}
	}

	return result
}
