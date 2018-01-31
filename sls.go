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
		if pillar.Get("secure_vars") != nil {
			pillar, dataChanged = pillarRange(pillar)
		} else {
			logger.Infof(fmt.Sprintf("%s has no secure_vars element", filePath))
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

func processPillar(pillar *yaml.Yaml) *yaml.Yaml {
	for index := 0; index < len(secretNames); index++ {
		cipherText := ""
		if index >= 0 && index < len(secretValues) {
			cipherText = encryptSecret(secretValues[index])
		}
		if pillar.Get("secure_vars") != nil {
			err := pillar.Set("secure_vars", secretNames[index], cipherText)
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

func pillarRange(pillar *yaml.Yaml) (*yaml.Yaml, bool) {
	var dataChanged = false
	secureVars := pillar.Get("secure_vars")
	for k, v := range secureVars.(map[interface{}]interface{}) {
		if !strings.Contains(v.(string), pgpHeader) {
			cipherText := encryptSecret(v.(string))
			err := pillar.Set("secure_vars", k, cipherText)
			if err != nil {
				logger.Fatalf("error setting value: %s", err)
			}
			dataChanged = true
		}
	}
	return pillar, dataChanged
}

func plainTextPillarBuffer(inFile string) bytes.Buffer {
	inFile, _ = filepath.Abs(inFile)
	pillar, err := yaml.Open(inFile)
	if err != nil {
		logger.Fatal(err)
	}

	if pillar.Get("secure_vars") != nil {
		for k, v := range pillar.Get("secure_vars").(map[interface{}]interface{}) {
			if strings.Contains(v.(string), pgpHeader) {
				plainText := decryptSecret(v.(string))
				err := pillar.Set("secure_vars", k, plainText)
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
