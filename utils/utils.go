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

package utils

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Everbridge/generate-secure-pillar/pki"
	"github.com/Everbridge/generate-secure-pillar/sls"
	"github.com/sirupsen/logrus"
)

var logger = logrus.New()

func init() {
	logger.Out = os.Stdout
}

// SafeWrite checks that there is no error priot to trying to write a file
func SafeWrite(buffer bytes.Buffer, outputFilePath string, err error) {
	if err != nil {
		logger.Fatalf("%s", err)
	} else {
		_, err = sls.WriteSlsFile(buffer, outputFilePath)
		if err != nil {
			logger.Fatalf("%s", err)
		}
	}
}

// PathAction applys an action to a YAML path
func PathAction(s *sls.Sls, path string, action string) {
	vals := s.GetValueFromPath(path)
	if vals != nil {
		processedVals, err := s.ProcessValues(vals, action)
		if err != nil {
			logger.Fatalf("path action failed: %s", err)
		}
		fmt.Printf("%s: %s\n", path, processedVals)
	} else {
		logger.Warnf("unable to find path: '%s'", path)
	}
}

// ProcessDir applies an action concurrently to a directory of files
func ProcessDir(searchDir string, fileExt string, action string, outputFilePath string, topLevelElement string, pk pki.Pki) error {
	// get a list of sls files along with the count
	files, count := FindFilesByExt(searchDir, fileExt)

	// copy files to a channel then close the
	// channel so that workers stop when done
	filesChan := make(chan string, count)
	for _, file := range files {
		filesChan <- file
	}
	close(filesChan)

	errChan := make(chan error, count)
	resChan := make(chan int, count)
	remaining := count

	// run workers
	for i := 0; i < count; i++ {
		go func() {
			for file := range filesChan {
				resChan <- applyActionAndWrite(file, action, &pk, topLevelElement, errChan)
			}
		}()
	}

	// collect results
	for i := 0; i < count; i++ {
		select {
		case byteCount := <-resChan:
			if action != sls.Validate && outputFilePath != os.Stdout.Name() {
				logger.Infof("%d bytes written", byteCount)
				logger.Infof("Finished processing %d of %d files\n", count-remaining+1, count)
			}
			remaining--
		case err := <-errChan:
			return err
		}
		if remaining == 0 {
			break
		}
	}
	return nil
}

func applyActionAndWrite(file string, action string, pk *pki.Pki, topLevelElement string, errChan chan error) int {
	s := sls.New(file, *pk, topLevelElement)
	if s.IsInclude || s.Error != nil {
		return 0
	}

	buf, err := s.PerformAction(action)
	if buf.Len() > 0 && err != nil && action != sls.Validate {
		logger.Warnf("%s", err)
	}
	if err != nil && action == sls.Validate {
		logger.Warnf("%s", err)
	}

	if action == sls.Validate {
		fmt.Printf("%s:\n%s\n", s.FilePath, buf.String())
		return 0
	}

	byteCount, err := sls.WriteSlsFile(buf, file)
	if err != nil {
		handleErr(err, errChan)
	}
	return byteCount
}

func handleErr(err error, errChan chan error) {
	if err != nil {
		select {
		case errChan <- err:
			// will break parent goroutine out of loop
		default:
			// don't care, first error wins
		}
		return
	}
}

// FindFilesByExt recurses through the given searchDir returning a list of files with a given extention and it's length
func FindFilesByExt(searchDir string, ext string) ([]string, int) {
	fileList := []string{}
	searchDir, err := filepath.Abs(searchDir)
	if err != nil {
		logger.Error(err)
		return fileList, 0
	}
	err = checkForDir(searchDir)
	if err != nil {
		logger.Error(err)
		return fileList, 0
	}

	err = filepath.Walk(searchDir, func(path string, f os.FileInfo, err error) error {
		if !f.IsDir() && filepath.Ext(f.Name()) == ext {
			fileList = append(fileList, path)
		}
		return nil
	})
	if err != nil {
		logger.Fatal("error walking file path: ", err)
	}

	return fileList, len(fileList)
}

//checkForDir does exactly what it says on the tin
func checkForDir(filePath string) error {
	fi, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("cannot stat %s: %s", filePath, err)
	}
	switch mode := fi.Mode(); {
	case mode.IsRegular():
		return fmt.Errorf("%s is a file", filePath)
	case mode.IsDir():
		return nil
	}

	return err
}
