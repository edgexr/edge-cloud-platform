package orm

import (
	"fmt"
	"strings"

	"github.com/jinzhu/gorm"
	"github.com/labstack/echo"
)

var NoShowFilter map[string]interface{} = nil

// For show filtering, convert the input json map to a db-name map,
// to be passed to db.Where(). This allows for searching based on
// empty values like "" or false, which would be ignored if we
// converted the json to a struct first.
func jsonToDbNames(jsonMap map[string]interface{}, refObj interface{}) (map[string]interface{}, error) {
	if len(jsonMap) == 0 {
		return jsonMap, nil
	}
	jsonToDb := make(map[string]string)

	scope := &gorm.Scope{}
	scope = scope.New(refObj)
	ms := scope.GetModelStruct()
	for _, field := range ms.StructFields {
		tag := field.Tag.Get("json")
		tagvals := strings.Split(tag, ",")
		jsonName := ""
		if len(tagvals) > 0 {
			jsonName = tagvals[0]
		}
		if jsonName == "" {
			jsonName = field.Name
		}
		jsonToDb[jsonName] = field.DBName
	}
	// gorm only allows embedded objects, so the struct depth
	// in terms of map levels will only be 1 deep, so we don't need
	// to worry about maps inside of this map.
	out := make(map[string]interface{})
	for k, v := range jsonMap {
		dbK, ok := jsonToDb[k]
		if !ok {
			return nil, fmt.Errorf("JSON field %s not found in database object %s", k, ms.ModelType.Name())
		}
		out[dbK] = v
	}
	return out, nil
}

// Get a map of filter data for Show commands, in db name format,
// to be passed to a db.Where() call, and let postgres do the filtering.
func bindDbFilter(c echo.Context, refObj interface{}) (map[string]interface{}, error) {
	filter := make(map[string]interface{})
	if c.Request().ContentLength == 0 {
		return filter, nil
	}
	// input data from client is in JSON format
	filter, err := bindMap(c)
	if err != nil {
		return nil, err
	}
	dbFilter, err := jsonToDbNames(filter, refObj)
	if err != nil {
		err = fmt.Errorf("Failed to parse input data: %s", err.Error())
		return nil, setReply(c, err, nil)
	}
	return dbFilter, nil
}

func bindMap(c echo.Context) (map[string]interface{}, error) {
	m := make(map[string]interface{})
	if c.Request().ContentLength > 0 {
		if err := c.Bind(&m); err != nil {
			return nil, bindErr(c, err)
		}
	}
	return m, nil
}

func getFilterString(filter map[string]interface{}, key string) (string, bool) {
	v, ok := filter[key]
	if !ok {
		return "", false
	}
	str, ok := v.(string)
	if !ok {
		return "", false
	}
	return str, true
}
