package parsecomments_test

import (
	"fmt"
	"reflect"
	"testing"

	parsecomments "github.com/edgexr/edge-cloud-platform/pkg/parse-comments"
	"github.com/edgexr/edge-cloud-platform/pkg/parse-comments/data"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

func TestParseComments(t *testing.T) {
	pc := parsecomments.NewParseComments()
	err := pc.ParseFiles("./data_test.go", "./data/data.go")
	require.Nil(t, err)

	// check that overall parsed data matches
	out, err := yaml.Marshal(pc)
	require.Nil(t, err)
	if expectedData != string(out) {
		fmt.Printf("%s\n", string(out))
		require.Equal(t, expectedData, string(out))
	}

	pkgPath := "github.com/edgexr/edge-cloud-platform/pkg/parse-comments_test"
	st := "TopObject"

	// test that reflect path matches
	rPath := reflect.TypeOf(TopObject{}).PkgPath()
	require.Equal(t, pkgPath, rPath)
	rPath = reflect.TypeOf(data.Data{}).PkgPath()
	require.Equal(t, "github.com/edgexr/edge-cloud-platform/pkg/parse-comments/data", rPath)

	// check lookups
	field, ok := pc.FindField(pkgPath, st, "StringField")
	require.True(t, ok)
	require.Equal(t, "StringField comment", field.Comment)
	require.True(t, field.ReadOnly)

	field, ok = pc.FindField(pkgPath, st, "IntField")
	require.True(t, ok)
	require.Equal(t, "IntField comment", field.Comment)

	field, ok = pc.FindField(pkgPath, st, "NoCommentField")
	require.True(t, ok)
	require.Equal(t, "", field.Comment)

	field, ok = pc.FindField(pkgPath, st, "HiddenField")
	require.True(t, ok)
	require.Equal(t, "Hidden field", field.Comment)
	require.True(t, field.Hidden)

	field, ok = pc.FindField(pkgPath, st, "FloatField")
	require.True(t, ok)
	require.Equal(t, "FloatField comment", field.Comment)

	field, ok = pc.FindField(pkgPath, st, "SubObject1")
	require.True(t, ok)
	require.Equal(t, "SubObject comment", field.Comment)

	// Check that embedded fields can be found in the parent object
	field, ok = pc.FindField(pkgPath, st, "SubStringField")
	require.True(t, ok)
	require.Equal(t, "SubStringField comment", field.Comment)

	field, ok = pc.FindField(pkgPath, st, "SubStringField2")
	require.True(t, ok)
	require.Equal(t, "SubStringField2 comment", field.Comment)

	field, ok = pc.FindField(pkgPath, st, "DataName")
	require.True(t, ok)
	require.Equal(t, "Data name", field.Comment)

	field, ok = pc.FindField(pkgPath, st, "DataEditTime")
	require.True(t, ok)
	require.Equal(t, "Edit time of data", field.Comment)
}

var expectedData = `structs:
- pkg: github.com/edgexr/edge-cloud-platform/pkg/parse-comments/data
  name: Data
  fields:
  - name: DataName
    typename: string
    comment: Data name
  - name: DataEditTime
    typepkg: time
    typename: Time
    comment: Edit time of data
- pkg: github.com/edgexr/edge-cloud-platform/pkg/parse-comments_test
  name: TopObject
  fields:
  - name: StringField
    typename: string
    comment: StringField comment
    readonly: true
  - name: IntField
    typename: int
    comment: IntField comment
  - name: NoCommentField
    typename: string
  - name: HiddenField
    typename: int
    comment: Hidden field
    hidden: true
  - name: FloatField
    typename: float64
    comment: FloatField comment
  - name: StringMapField
    maptype: map[string]string
    comment: Map[string]string comment
  - name: MapField
    maptype: map
    comment: Map comment
  - name: Array
    typename: string
    comment: Array comment
    arrayedinparent: true
  - name: ObjectArray
    typepkg: github.com/edgexr/edge-cloud-platform/pkg/parse-comments/pkg-with-dashes
    typename: Timestamp
    comment: Arrayed object comment
    arrayedinparent: true
  - name: SubObject1
    typepkg: github.com/edgexr/edge-cloud-platform/pkg/parse-comments_test
    typename: SubObject
    comment: SubObject comment
  - name: SubObjectPtr
    typepkg: github.com/edgexr/edge-cloud-platform/pkg/parse-comments_test
    typename: SubObject
    comment: PointerSubObject comment
    pointertype: true
  embedded:
  - github.com/edgexr/edge-cloud-platform/pkg/parse-comments_test.SubObject
  - github.com/edgexr/edge-cloud-platform/pkg/parse-comments/data.Data
- pkg: github.com/edgexr/edge-cloud-platform/pkg/parse-comments_test
  name: SubObject
  fields:
  - name: SubStringField
    typename: string
    comment: SubStringField comment
  - name: SubStringField2
    typename: string
    comment: SubStringField2 comment
- pkg: github.com/edgexr/edge-cloud-platform/pkg/parse-comments_test
  name: OtherObject
  fields:
  - name: StringArrayField
    typename: string
    comment: StringArrayField comment
    arrayedinparent: true
  - name: StringPointer
    typename: string
    comment: Pointer Field comment
    pointertype: true
  - name: Timestamp
    typepkg: github.com/edgexr/edge-cloud-platform/pkg/parse-comments/pkg-with-dashes
    typename: Timestamp
    comment: External data
`
