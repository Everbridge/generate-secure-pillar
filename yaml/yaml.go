/*
  Copyright (c) 2012 José Carlos Nieto, http://xiam.menteslibres.org/

  Permission is hereby granted, free of charge, to any person obtaining
  a copy of this software and associated documentation files (the
  "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so, subject to
  the following conditions:

  The above copyright notice and this permission notice shall be
  included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

package yaml

import (
	"fmt"
	"log"
	"os"
	"reflect"
	"strings"

	yaml "gopkg.in/yaml.v1"
	"menteslibres.net/gosexy/dig"
)

// Yaml data type
type Yaml struct {
	File   string
	Values map[string]interface{}
}

/*
	true by default, for now.
*/
var Compat = false

/*
	Creates and returns a YAML struct.
*/
func New() *Yaml {
	self := &Yaml{}
	self.Values = map[string]interface{}{}
	return self
}

/*
	Creates and returns a YAML struct, from a file.
*/
func Open(file string) (*Yaml, error) {
	var err error

	self := New()

	_, err = os.Stat(file)

	if err != nil {
		return nil, err
	}

	self.File = file

	err = self.Read(self.File)

	if err != nil {
		return nil, err
	}

	return self, nil
}

/*
	Sets a YAML setting
*/
func (y *Yaml) Set(params ...interface{}) error {

	l := len(params)

	if l < 2 {
		return fmt.Errorf("missing value")
	}

	if Compat == true {
		if len(params) == 2 {
			if reflect.TypeOf(params[0]).Kind() == reflect.String {
				p := params[0].(string)

				if strings.Contains(p, "/") == true {
					p := strings.Split(p, "/")

					value := params[1]
					route := make([]interface{}, len(p))

					for i, _ := range p {
						route[i] = p[i]
					}

					log.Printf(`Using a route separated by "/" is deprecated, please use yaml.*Yaml.Get("%s") instead.`, strings.Join(p, `", "`))

					dig.Dig(&y.Values, route...)
					return dig.Set(&y.Values, value, route...)
				}
			}
		}
	}

	route := params[0 : l-1]
	value := params[l-1]

	dig.Dig(&y.Values, route...)
	return dig.Set(&y.Values, value, route...)
}

/*
	Returns a YAML setting
*/
func (y *Yaml) Get(route ...interface{}) interface{} {
	var i interface{}

	if Compat == true {
		// Compatibility should be removed soon.
		if len(route) == 1 {
			p := route[0].(string)

			if strings.Contains(p, "/") == true {
				p := strings.Split(p, "/")

				route := make([]interface{}, len(p))

				for i, _ := range p {
					route[i] = p[i]
				}

				log.Printf(`Using a route separated by "/" is deprecated, please use yaml.*Yaml.Get("%s") instead.`, strings.Join(p, `", "`))

				dig.Get(&y.Values, &i, route...)
				return i
			}
		}
	}

	dig.Get(&y.Values, &i, route...)
	return i
}

/*
	Writes changes to the currently opened YAML file.
*/
func (y *Yaml) Save() error {
	if y.File != "" {
		return y.Write(y.File)
	} else {
		return fmt.Errorf("No file specified.")
	}
	return nil
}

/*
	Writes the current YAML struct to disk.
*/
func (y *Yaml) Write(filename string) error {

	out, err := yaml.Marshal(y.Values)

	if err != nil {
		return err
	}

	fp, err := os.Create(filename)

	if err != nil {
		return err
	}

	defer fp.Close()

	_, err = fp.Write(out)

	return err
}

/*
	Loads a YAML file from disk.
*/
func (y *Yaml) Read(filename string) error {
	var err error

	fileinfo, err := os.Stat(filename)

	if err != nil {
		return err
	}

	filesize := fileinfo.Size()

	fp, err := os.Open(filename)

	if err != nil {
		return err
	}

	defer fp.Close()

	buf := make([]byte, filesize)
	fp.Read(buf)

	err = yaml.Unmarshal(buf, &y.Values)

	if err != nil {
		return err
	}

	return nil
}
