package parsecomments_test

import (
	"github.com/edgexr/edge-cloud-platform/pkg/parse-comments/data"
	dashes "github.com/edgexr/edge-cloud-platform/pkg/parse-comments/pkg-with-dashes"
)

type TopObject struct {
	// StringField comment
	// read only: true
	StringField string
	// IntField comment
	IntField       int
	NoCommentField string
	// Hidden field
	// hidden: true
	HiddenField int
	// FloatField comment
	FloatField float64
	// Map[string]string comment
	StringMapField map[string]string
	// Map comment
	MapField map[int]int
	// Array comment
	Array []string
	// Arrayed object comment
	ObjectArray []dashes.Timestamp
	// SubObject comment
	SubObject1 SubObject
	// EmbeddedField comment
	SubObject
	// EmbeddedField from another package
	data.Data
}

type SubObject struct {
	// SubStringField comment
	SubStringField string
	// SubStringField2 comment
	SubStringField2 string
}

type OtherObject struct {
	// StringArrayField comment
	StringArrayField []string
	// Pointer Field comment
	StringPointer *string
	// External data
	Timestamp dashes.Timestamp
}
