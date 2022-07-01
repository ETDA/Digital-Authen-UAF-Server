package model

import (
	"encoding/json"
	"github.com/etda-uaf/uaf-server/app"
	"github.com/etda-uaf/uaf-server/fido/model"
)

type Metadata struct {
	AAID            string
	Metadata        string
	ConformanceOnly bool
}

func FindMetadataStatementByAAID(aaid string) *model.MetadataStatement {
	var metadata Metadata

	if res := app.Db.First(&metadata, []string{aaid}); res.Error != nil {
		return nil
	}
	var statement model.MetadataStatement

	err := json.Unmarshal([]byte(metadata.Metadata), &statement)
	if err != nil {
		return nil
	}
	return &statement
}
