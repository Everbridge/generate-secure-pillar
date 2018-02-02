package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	yaml "menteslibres.net/gosexy/yaml"
)

// writeSlsFile writes a buffer to the specified file
// If the outFilePath is not stdout an INFO string will be printed to stdout
func writeSlsFile(buffer bytes.Buffer, outFilePath string) {
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

// fileSlsFiles recurses through the given searchDir returning a list of .sls files and it's length
func findSlsFiles(searchDir string) ([]string, int) {
	searchDir, _ = filepath.Abs(searchDir)
	fileList := []string{}
	err := filepath.Walk(searchDir, func(path string, f os.FileInfo, err error) error {
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

// pillarBuffer returns a buffer with encrypted and formatted yaml text
// If the 'all' flag is set all values under the designated top level element are encrypted
func pillarBuffer(filePath string, all bool) bytes.Buffer {
	err := checkForFile(filePath)
	if err != nil {
		logger.Fatal(err)
	}
	filePath, err = filepath.Abs(filePath)
	if err != nil {
		logger.Fatal(err)
	}

	pillar, err := yaml.Open(filePath)
	if err != nil {
		logger.Fatal(err)
	}
	dataChanged := false

	if all {
		if pillar.Get(topLevelElement) != nil {
			pillar, dataChanged = pillarRange(pillar)
		} else {
			logger.Infof(fmt.Sprintf("%s has no %s element", filePath, topLevelElement))
		}
	} else {
		pillar = processPillar(pillar)
		dataChanged = true
	}

	if !dataChanged {
		var buffer bytes.Buffer
		return buffer
	}

	return formatBuffer(pillar)
}

// processPillar encrypts elements matching keys specified on the command line
func processPillar(pillar *yaml.Yaml) *yaml.Yaml {
	for index := 0; index < len(secretNames); index++ {
		cipherText := ""
		if index >= 0 && index < len(secretValues) {
			cipherText = encryptSecret(secretValues[index])
		}
		if pillar.Get(topLevelElement) != nil {
			err := pillar.Set(topLevelElement, secretNames[index], cipherText)
			if err != nil {
				logger.Fatalf("error setting value: %s", err)
			}
		} else {
			err := pillar.Set(secretNames[index], cipherText)
			if err != nil {
				logger.Fatalf("error setting value: %s", err)
			}
		}
	}

	return pillar
}

// pillarRange encrypts any plain text values in the top level element
func pillarRange(pillar *yaml.Yaml) (*yaml.Yaml, bool) {
	var dataChanged = false
	secureVars := pillar.Get(topLevelElement)
	for k, v := range secureVars.(map[interface{}]interface{}) {
		if !strings.Contains(v.(string), pgpHeader) {
			cipherText := encryptSecret(v.(string))
			err := pillar.Set(topLevelElement, k, cipherText)
			if err != nil {
				logger.Fatalf("error setting value: %s", err)
			}
			dataChanged = true
		}
	}
	return pillar, dataChanged
}

// plainTextPillarBuffer decrypts all values under the top level element and returns a formatted buffer
func plainTextPillarBuffer(filePath string) bytes.Buffer {
	err := checkForFile(filePath)
	if err != nil {
		logger.Fatal(err)
	}
	filePath, err = filepath.Abs(filePath)
	if err != nil {
		logger.Fatal(err)
	}

	pillar, err := yaml.Open(filePath)
	if err != nil {
		logger.Fatal(err)
	}

	if pillar.Get(topLevelElement) != nil {
		for k, v := range pillar.Get(topLevelElement).(map[interface{}]interface{}) {
			if strings.Contains(v.(string), pgpHeader) {
				plainText := decryptSecret(v.(string))
				err := pillar.Set(topLevelElement, k, plainText)
				if err != nil {
					logger.Fatalf("error setting value: %s", err)
				}
			}
		}
	} else {
		logger.Fatal("WTF")
	}

	return formatBuffer(pillar)
}

// formatBuffer returns a formatted .sls buffer with the gpg renderer line
func formatBuffer(pillar *yaml.Yaml) bytes.Buffer {
	var buffer bytes.Buffer

	tmpfile, err := ioutil.TempFile("", "gsp_")
	if err != nil {
		logger.Fatal(err)
	}

	err = pillar.Write(tmpfile.Name())
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

// checkForFile does exactly what it says on the tin
func checkForFile(filePath string) error {
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

// processDir will recursively apply fileSlsFiles
// It will either encrypt or decrypt, as specified by the action flag
// It writes replaces the files found
func processDir(recurseDir string, action string) {
	info, err := os.Stat(recurseDir)
	if err != nil {
		logger.Fatalf("cannot stat %s: %s", recurseDir, err)
	}
	if info.IsDir() {
		slsFiles, count := findSlsFiles(recurseDir)
		if count == 0 {
			logger.Fatalf("%s has no sls files", recurseDir)
		}
		for _, file := range slsFiles {
			var buffer bytes.Buffer
			if action == "encrypt" {
				buffer = pillarBuffer(file, true)
			} else if action == "decrypt" {
				buffer = plainTextPillarBuffer(file)
			} else {
				logger.Fatalf("unknown action: %s", action)
			}
			writeSlsFile(buffer, file)
		}
	} else {
		logger.Fatalf("%s is not a directory", recurseDir)
	}
}
