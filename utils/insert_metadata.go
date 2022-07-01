package utils

import (
	"encoding/json"
	"fmt"
	"github.com/etda-uaf/uaf-server/app"
	db "github.com/etda-uaf/uaf-server/db/model"
	"github.com/etda-uaf/uaf-server/fido/model"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

func InsertMetadata() {
	var files []string
	err := filepath.Walk("metadata", func(path string, info os.FileInfo, err error) error {
		files = append(files, path)
		return nil
	})
	if err != nil {
		panic(err)
	}
	for _, file := range files {
		log.Println(file)
		b, _ := ioutil.ReadFile(file)
		var mt model.MetadataStatement
		err = json.Unmarshal(b, &mt)
		if err != nil {
			if jsonError, ok := err.(*json.SyntaxError); ok {
				line, character, lcErr := lineAndCharacter(string(b), int(jsonError.Offset))
				fmt.Fprintf(os.Stderr, "test %d failed with error: Cannot parse JSON schema due to a syntax error at line %d, character %d: %v\n", file, line, character, jsonError.Error())
				if lcErr != nil {
					fmt.Fprintf(os.Stderr, "Couldn't find the line and character position of the error due to error %v\n", lcErr)
				}
				continue
			}
			if jsonError, ok := err.(*json.UnmarshalTypeError); ok {
				line, character, lcErr := lineAndCharacter(string(b), int(jsonError.Offset))
				fmt.Fprintf(os.Stderr, "test %d failed with error: The JSON type '%v' cannot be converted into the Go '%v' type on struct '%s', field '%v'. See input file line %d, character %d\n", file, jsonError.Value, jsonError.Type.Name(), jsonError.Struct, jsonError.Field, line, character)
				if lcErr != nil {
					fmt.Fprintf(os.Stderr, "test %d failed with error: Couldn't find the line and character position of the error due to error %v\n", file, lcErr)
				}
				continue
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "test %d failed with error: %v\n", file, err)
				continue
			}
		}
		bb, err := json.Marshal(mt)
		if err != nil {
			log.Println(err.Error())
		}
		m := db.Metadata{
			AAID:            string(mt.Aaid),
			Metadata:        string(bb),
			ConformanceOnly: true,
		}
		app.Db.Create(m)
	}
}

func lineAndCharacter(input string, offset int) (line int, character int, err error) {
	lf := rune(0x0A)

	if offset > len(input) || offset < 0 {
		return 0, 0, fmt.Errorf("Couldn't find offset %d within the input.", offset)
	}

	// Humans tend to count from 1.
	line = 1

	for i, b := range input {
		if b == lf {
			line++
			character = 0
		}
		character++
		if i == offset {
			break
		}
	}

	return line, character, nil
}
