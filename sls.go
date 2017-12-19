package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	yaml "gopkg.in/yaml.v2"
)

func writeSlsFile(buffer bytes.Buffer, outFilePath string) {
	outFilePath, _ = filepath.Abs(outFilePath)

	stdOut := false
	if outFilePath == os.Stdout.Name() {
		stdOut = true
	}

	err := ioutil.WriteFile(outFilePath, buffer.Bytes(), 0644)
	if err != nil {
		log.Fatal(err)
	}
	if !stdOut {
		fmt.Printf("Wrote out to file: '%s'\n", outFilePath)
	}
}

func readSlsFile(slsPath string) SlsData {
	slsPath, _ = filepath.Abs(slsPath)
	var SlsData SlsData

	filename, _ := filepath.Abs(slsPath)
	if _, err := os.Stat(filename); !os.IsNotExist(err) {
		yamlData, err := ioutil.ReadFile(filename)
		if err != nil {
			log.Fatal(err)
		}

		err = yaml.Unmarshal(yamlData, &SlsData)
		if err != nil {
			log.Print(fmt.Sprintf("Skipping %s: %s\n", filename, err))
		}
	}

	return SlsData
}

func findSlsFiles(searchDir string) []string {
	searchDir, _ = filepath.Abs(searchDir)
	fileList := []string{}
	err := filepath.Walk(searchDir, func(path string, f os.FileInfo, err error) error {
		if !f.IsDir() && strings.Contains(f.Name(), ".sls") {
			fileList = append(fileList, path)
		}
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}

	return fileList
}

func pillarBuffer(filePath string, all bool) bytes.Buffer {
	filePath, _ = filepath.Abs(filePath)
	var buffer bytes.Buffer
	var cipherText string
	pillar := readSlsFile(filePath)
	dataChanged := false

	if all {
		for k, v := range pillar["secure_vars"].(SlsData) {
			if !strings.Contains(v.(string), pgpHeader) {
				cipherText = encryptSecret(v.(string))
				pillar["secure_vars"].(SlsData)[k] = cipherText
				dataChanged = true
			}
		}
	} else {
		cipherText = encryptSecret(secretsString)
		pillar["secure_vars"].(SlsData)[secretName] = cipherText
		dataChanged = true
	}

	if !dataChanged {
		return buffer
	}

	return formatBuffer(pillar)
}

func plainTextPillarBuffer(inFile string) bytes.Buffer {
	inFile, _ = filepath.Abs(inFile)
	pillar := readSlsFile(inFile)
	if pillar["secure_vars"] != nil {
		for k, v := range pillar["secure_vars"].(SlsData) {
			if strings.Contains(v.(string), pgpHeader) {
				plainText := decryptSecret(v.(string))
				pillar["secure_vars"].(SlsData)[k] = plainText
			}
		}
	}

	return formatBuffer(pillar)
}

func formatBuffer(pillar SlsData) bytes.Buffer {
	var buffer bytes.Buffer

	yamlBytes, err := yaml.Marshal(pillar)
	if err != nil {
		log.Fatal(err)
	}

	buffer.WriteString("#!yaml|gpg\n\n")
	buffer.WriteString(string(yamlBytes))

	return buffer
}
