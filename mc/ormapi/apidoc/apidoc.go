package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io/ioutil"
	"log"
	"strings"
)

var apiFile = flag.String("apiFile", "", "package dir of api files to parse")

func main() {
	flag.Parse()
	if *apiFile == "" {
		log.Fatal("Must specify apiFile")
	}

	// parse the go source code file
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, *apiFile, nil, parser.ParseComments)
	if err != nil {
		log.Fatalf("Failed to parse %s: %v", *apiFile, err)
	}
	// Debug: print the ast
	//ast.Print(fset, f)

	// walk the AST and collect structs and field comments
	allStructs := AllStructs{}
	allStructs.apiStructs = make([]*ApiStruct, 0)
	allStructs.lookup = make(map[string]*ApiStruct)
	ast.Walk(&allStructs, f)

	// generate comments
	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "package %s", allStructs.pkgName)
	for _, apiSt := range allStructs.apiStructs {
		comments := []Field{}
		apiSt.genComments(&allStructs, []string{}, &comments)
		if len(comments) == 0 {
			continue
		}
		fmt.Fprintf(buf, "\nvar %sComments = map[string]string{\n", apiSt.name)
		for _, c := range comments {
			fmt.Fprintf(buf, "\"%s\": `%s`,\n", strings.ToLower(c.name), c.comment)
		}
		fmt.Fprintf(buf, "}\n")
	}
	// format the generated code
	out, err := format.Source(buf.Bytes())
	if err != nil {
		log.Fatalf("Failed to format generated code: %v\n%s", err, buf.String())
	}
	// write output file
	outFile := strings.TrimSuffix(*apiFile, ".go")
	outFile += ".comments.go"
	err = ioutil.WriteFile(outFile, out, 0644)
	if err != nil {
		log.Fatalf("Failed to write output file %s: %v", outFile, err)
	}
}

type AllStructs struct {
	pkgName    string
	apiStructs []*ApiStruct
	lookup     map[string]*ApiStruct
}

type ApiStruct struct {
	name     string
	embedded []string
	fields   []Field
}

type Field struct {
	name            string
	typeName        string
	arrayedInParent bool
	comment         string
}

func (s *AllStructs) Visit(node ast.Node) ast.Visitor {
	switch x := node.(type) {
	case *ast.File:
		s.pkgName = x.Name.Name
		return s
	case *ast.GenDecl:
		return s
	case *ast.TypeSpec:
		apiSt := ApiStruct{}
		apiSt.name = x.Name.Name
		apiSt.embedded = []string{}
		apiSt.fields = []Field{}
		s.apiStructs = append(s.apiStructs, &apiSt)
		s.lookup[apiSt.name] = &apiSt
		return &apiSt
	}
	return nil
}

const mapTypeStringString = "map[string]string"

func (s *ApiStruct) Visit(node ast.Node) ast.Visitor {
	switch x := node.(type) {
	case *ast.StructType:
		return s
	case *ast.FieldList:
		return s
	case *ast.Field:
		extraComment := ""
		// get type of field
		field := Field{}
		switch t := x.Type.(type) {
		case *ast.Ident:
			if len(x.Names) == 0 {
				// embedded struct
				s.embedded = append(s.embedded, t.Name)
				return nil
			}
			field.typeName = t.Name
		case *ast.ArrayType:
			elemId, ok := t.Elt.(*ast.Ident)
			if !ok {
				return nil
			}
			field.arrayedInParent = true
			field.typeName = elemId.Name
		case *ast.MapType:
			// only support map[string]string
			keyId, ok := t.Key.(*ast.Ident)
			if !ok || keyId.Name != "string" {
				return nil
			}
			valId, ok := t.Value.(*ast.Ident)
			if !ok || valId.Name != "string" {
				return nil
			}
			field.typeName = mapTypeStringString
			extraComment = ", value is key=value format"
		default:
			return nil
		}
		// get name of field
		if len(x.Names) != 1 {
			return nil
		}
		field.name = x.Names[0].Name
		// get comments
		comments := getComments(x.Doc)
		if comments == "" {
			return nil
		}
		field.comment = comments + extraComment
		s.fields = append(s.fields, field)
		return nil
	}
	return nil
}

func getComments(doc *ast.CommentGroup) string {
	strs := []string{}
	if doc == nil {
		return ""
	}
	for _, comment := range doc.List {
		str := comment.Text
		if strings.HasPrefix(str, "// read only: true") || strings.HasPrefix(str, "// required: true") {
			continue
		}
		str = strings.TrimPrefix(str, "//")
		str = strings.TrimSpace(str)
		strs = append(strs, str)
	}
	return strings.Join(strs, " ")
}

func (s *ApiStruct) genComments(all *AllStructs, parents []string, comments *[]Field) {
	for _, emb := range s.embedded {
		if subStruct, found := all.lookup[emb]; found {
			// sub struct
			subStruct.genComments(all, append(parents, emb), comments)
			continue
		}
	}
	for _, field := range s.fields {
		if subStruct, found := all.lookup[field.typeName]; found {
			// sub struct
			name := field.name
			if field.arrayedInParent {
				name += ":#"
			}
			subStruct.genComments(all, append(parents, name), comments)
			continue
		}
		comment := Field{
			name:    strings.Join(append(parents, field.name), "."),
			comment: field.comment,
		}
		*comments = append(*comments, comment)
	}
}
