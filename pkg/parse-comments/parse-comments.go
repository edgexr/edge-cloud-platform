package parsecomments

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

var goPath = os.Getenv("GOPATH")

const MapTypeStringString = "map[string]string"
const MapType = "map"

type ParseComments struct {
	Structs    []*Struct          `yaml:",omitempty"`
	Embedded   []string           `yaml:",omitempty"` // pkgStruct names of embedded objects
	structsMap map[string]*Struct // key comes from getPkgStructName
	curPkg     string
	curStruct  string
	curImports map[string]string // pkg name to pkg path
}

type Struct struct {
	Pkg       string
	Name      string
	Fields    []*Field          `yaml:",omitempty"`
	Embedded  []string          `yaml:",omitempty"` // pkgStruct names
	fieldsMap map[string]*Field // key is go field name
}

type Field struct {
	Name            string
	TypePkg         string `yaml:",omitempty"` // blank for builtin types
	TypeName        string `yaml:",omitempty"`
	MapType         string `yaml:",omitempty"`
	Comment         string `yaml:",omitempty"`
	PointerType     bool   `yaml:",omitempty"`
	ArrayedInParent bool   `yaml:",omitempty"`
	Hidden          bool   `yaml:",omitempty"`
	ReadOnly        bool   `yaml:",omitempty"`
	Required        bool   `yaml:",omitempty"`
}

func NewParseComments() *ParseComments {
	pc := ParseComments{}
	pc.structsMap = make(map[string]*Struct)
	return &pc
}

func NewStruct() *Struct {
	st := Struct{}
	st.fieldsMap = make(map[string]*Field)
	return &st
}

// Parse files and directories. Passed in paths may be files or directories.
// Directory scanning is not recursive.
func (s *ParseComments) ParseFiles(paths ...string) error {
	sort.Strings(paths)
	toParse := []string{}
	for _, path := range paths {
		files, err := getFiles(path)
		if err != nil {
			return err
		}
		toParse = append(toParse, files...)
	}
	for _, file := range toParse {
		if err := s.ParseFile(file); err != nil {
			return err
		}
	}
	return nil
}

func getFiles(path string) ([]string, error) {
	files := []string{}
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return files, err
	}
	if info.IsDir() {
		dirFiles, err := ioutil.ReadDir(path)
		if err != nil {
			return files, err
		}
		for _, file := range dirFiles {
			if file.IsDir() {
				continue
			}
			name := file.Name()
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			if !strings.HasSuffix(name, ".go") {
				continue
			}
			files = append(files, path+"/"+name)
		}
	} else {
		files = append(files, path)
	}
	return files, nil
}

func (s *ParseComments) ParseFile(fileName string) error {
	// We need to compute the same package path that is
	// returned from reflect.Type.PkgPath() for this file.
	filePath, err := filepath.Abs(fileName)
	if err != nil {
		return err
	}
	// remove the filename to the get the pkg directory
	pkgPath := filepath.Dir(filePath)
	// remove leading directories to get the import path
	pkgPath = strings.TrimPrefix(pkgPath, goPath+"/src/")
	pkgPath = strings.TrimPrefix(pkgPath, goPath+"/pkg/mod/")
	if before, after, found := strings.Cut(pkgPath, "@"); found {
		// for go/pkg/mod directories, remove version tag to get path
		idx := strings.Index(after, "/")
		if idx == -1 {
			pkgPath = before
		} else {
			pkgPath = before + after[idx:]
		}
	}
	s.curPkg = pkgPath
	s.curImports = make(map[string]string)

	// parse the file
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, fileName, nil, parser.ParseComments)
	if err != nil {
		return err
	}
	// debug: print the ast
	//ast.Print(fset, f)

	// walk the AST and collect structs and field comments
	ast.Walk(s, f)
	s.curPkg = ""
	s.curStruct = ""
	return nil
}

func (s *ParseComments) Visit(node ast.Node) ast.Visitor {
	switch x := node.(type) {
	// file parsing
	case *ast.File:
		// the only case where there can be more than one
		// package name in a package directory is if it is
		// the original package name with a _test suffix.
		if strings.HasSuffix(x.Name.Name, "_test") {
			s.curPkg += "_test"
		}
		return s
	case *ast.ImportSpec:
		path, err := strconv.Unquote(x.Path.Value)
		if err != nil {
			path = x.Path.Value
		}
		name := ""
		if x.Name != nil {
			name = x.Name.Name
		} else {
			name = filepath.Base(path)
		}
		s.curImports[name] = path
		return s
	case *ast.GenDecl:
		return s
	case *ast.TypeSpec:
		s.curStruct = x.Name.Name
		return s
	// struct parsing
	case *ast.StructType:
		return s
	case *ast.FieldList:
		return s
	case *ast.Field:
		lookup := GetPkgStructName(s.curPkg, s.curStruct)
		st, ok := s.structsMap[lookup]
		if !ok {
			st = NewStruct()
			st.Pkg = s.curPkg
			st.Name = s.curStruct
			s.structsMap[lookup] = st
			s.Structs = append(s.Structs, st)
		}
		field := &Field{}
		defer func() {
			if err := recover(); err != nil {
				name := field.TypeName
				if len(x.Names) > 0 {
					name = x.Names[0].Name
				}
				fmt.Printf("Panic parsing %s.%s\n", s.curStruct, name)
				panic(err)
			}
		}()

		switch t := x.Type.(type) {
		case *ast.Ident:
			// type from same package
			s.setFieldType(field, t)
		case *ast.SelectorExpr:
			// type from different package
			s.setFieldType(field, t)
		case *ast.ArrayType:
			s.setFieldType(field, t.Elt)
			field.ArrayedInParent = true
		case *ast.MapType:
			// only support map[string]string
			keyType := ""
			if keyId, ok := t.Key.(*ast.Ident); ok && keyId.Name == "string" {
				keyType = "string"
			}
			valType := ""
			if valId, ok := t.Value.(*ast.Ident); ok && valId.Name == "string" {
				valType = "string"
			}
			if keyType == "string" && valType == "string" {
				field.MapType = MapTypeStringString
			} else {
				field.MapType = MapType
			}
		case *ast.StarExpr:
			// pointer reference
			s.setFieldType(field, t.X)
			field.PointerType = true
		}
		if len(x.Names) == 0 {
			// embedded struct
			embName := GetPkgStructName(field.TypePkg, field.TypeName)
			st.Embedded = append(st.Embedded, embName)
			return nil
		}
		if len(x.Names) != 1 {
			return nil
		}
		field.Name = x.Names[0].Name
		setFieldComments(field, x.Doc)
		st.fieldsMap[field.Name] = field
		st.Fields = append(st.Fields, field)
		return s
	}
	return nil
}

func (s *ParseComments) setFieldType(field *Field, typeExpr ast.Expr) {
	pkg, typ := s.getPkgAndType(typeExpr)
	field.TypePkg = pkg
	field.TypeName = typ
}

// This assumes a single level of indirection only, i.e.
// no maps of maps of maps, etc.
func (s *ParseComments) getPkgAndType(typ ast.Expr) (string, string) {
	switch t := typ.(type) {
	case *ast.Ident:
		// type from same package
		if t.Obj == nil {
			// builtin
			return "", t.Name
		} else {
			// struct reference
			return s.curPkg, t.Name
		}
	case *ast.SelectorExpr:
		// type from different package
		pkg := ""
		ident, ok := t.X.(*ast.Ident)
		if ok {
			pkg, ok = s.curImports[ident.Name]
			if !ok {
				fmt.Printf("import not found for %s\n", ident.Name)
			}
		}
		return pkg, t.Sel.Name
	case *ast.ArrayType:
		// nested types not handled
	case *ast.MapType:
		// nested types not handled
	case *ast.StarExpr:
		return s.getPkgAndType(t.X)
	case *ast.FuncType:
		// func types not handled
	case *ast.StructType:
		// anonymous inner structs not handled
	default:
		panic(fmt.Sprintf("getPkgAndType invalid type %v passed in\n", typ))
	}
	return "", ""
}

func setFieldComments(field *Field, doc *ast.CommentGroup) {
	strs := []string{}
	if doc == nil {
		return
	}
	for _, comment := range doc.List {
		str := comment.Text
		if strings.HasPrefix(str, "// hidden: true") {
			field.Hidden = true
			continue
		}
		if strings.HasPrefix(str, "// read only: true") {
			field.ReadOnly = true
			continue
		}
		if strings.HasPrefix(str, "// required: true") {
			field.Required = true
			continue
		}
		str = strings.TrimPrefix(str, "//")
		str = strings.TrimSpace(str)
		strs = append(strs, str)
	}
	field.Comment = strings.Join(strs, " ")
}

func GetPkgStructName(pkgPath, structName string) string {
	return pkgPath + "." + structName
}

func (s *ParseComments) FindStruct(pkgStruct string) (*Struct, bool) {
	st, ok := s.structsMap[pkgStruct]
	return st, ok
}

// Lookup field comments based on package path, go struct name,
// and go field name. For example,
// lookup("github.com/company/repo/pkg/path", "MyObject", "MyField")
func (s *ParseComments) FindField(pkgPath, structName, fieldName string) (*Field, bool) {
	return s.findField(GetPkgStructName(pkgPath, structName), fieldName)
}

func (s *ParseComments) findField(pkgStruct, fieldName string) (*Field, bool) {
	st, ok := s.structsMap[pkgStruct]
	if !ok {
		return nil, false
	}
	if field, ok := st.fieldsMap[fieldName]; ok {
		return field, true
	}
	// search embedded objects
	for _, pkgStruct := range st.Embedded {
		if field, ok := s.findField(pkgStruct, fieldName); ok {
			return field, ok
		}
	}
	return nil, false
}
