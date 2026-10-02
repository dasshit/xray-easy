// Command check-go-docs verifies that the handwritten Go API has Godoc comments.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
)

type sourceFile struct {
	path string
	dir  string
	file *ast.File
}

func main() {
	files, err := collectFiles()
	if err != nil {
		fail(err.Error())
	}

	var problems []string
	packageDirs := make(map[string]bool)
	packageDocs := make(map[string]bool)
	fset := token.NewFileSet()
	for _, source := range files {
		packageDirs[source.dir] = true
		if hasPackageDoc(source.file) {
			packageDocs[source.dir] = true
		}
		problems = append(problems, checkFile(fset, source)...)
	}
	for dir := range packageDirs {
		if !packageDocs[dir] {
			problems = append(problems, fmt.Sprintf("%s: package is missing a Package comment", dir))
		}
	}

	sort.Strings(problems)
	if len(problems) != 0 {
		for _, problem := range problems {
			fmt.Fprintln(os.Stderr, problem)
		}
		fmt.Fprintf(os.Stderr, "FAIL Go documentation check: %d problem(s)\n", len(problems))
		os.Exit(1)
	}
	fmt.Printf("PASS Go documentation check: %d handwritten source file(s) have documented Godoc APIs\n", len(files))
}

func collectFiles() ([]sourceFile, error) {
	roots := []string{"internal", "cmd", "awg-service", "xray-runtime"}
	var files []sourceFile
	fset := token.NewFileSet()
	for _, root := range roots {
		if _, err := os.Stat(root); err != nil {
			return nil, fmt.Errorf("walk %s: %w", root, err)
		}
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !isHandwrittenGoFile(path) {
				return nil
			}
			file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
			if err != nil {
				return fmt.Errorf("parse %s: %w", path, err)
			}
			files = append(files, sourceFile{path: path, dir: filepath.Dir(path), file: file})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].path < files[j].path })
	return files, nil
}

func isHandwrittenGoFile(path string) bool {
	if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || strings.HasSuffix(path, ".pb.go") || strings.HasSuffix(path, "_grpc.pb.go") {
		return false
	}
	return true
}

func hasPackageDoc(file *ast.File) bool {
	if file.Doc == nil {
		return false
	}
	text := strings.TrimSpace(file.Doc.Text())
	return strings.HasPrefix(text, "Package "+file.Name.Name)
}

func checkFile(fset *token.FileSet, source sourceFile) []string {
	var problems []string
	for _, declaration := range source.file.Decls {
		switch declaration := declaration.(type) {
		case *ast.FuncDecl:
			if isExported(declaration.Name.Name) && declaration.Doc == nil {
				problems = append(problems, missing(fset, source.path, declaration.Pos(), "function", declaration.Name.Name))
			}
		case *ast.GenDecl:
			for _, spec := range declaration.Specs {
				switch spec := spec.(type) {
				case *ast.TypeSpec:
					if isExported(spec.Name.Name) && declaration.Doc == nil && spec.Doc == nil {
						problems = append(problems, missing(fset, source.path, spec.Pos(), "type", spec.Name.Name))
					}
					problems = append(problems, checkType(fset, source.path, spec)...)
				case *ast.ValueSpec:
					if declaration.Doc != nil || spec.Doc != nil {
						continue
					}
					for _, name := range spec.Names {
						if isExported(name.Name) {
							kind := declaration.Tok.String()
							problems = append(problems, missing(fset, source.path, name.Pos(), kind, name.Name))
						}
					}
				}
			}
		}
	}
	return problems
}

func checkType(fset *token.FileSet, path string, typeSpec *ast.TypeSpec) []string {
	var problems []string
	if !isExported(typeSpec.Name.Name) {
		return problems
	}
	switch typeValue := typeSpec.Type.(type) {
	case *ast.StructType:
		for _, field := range typeValue.Fields.List {
			if field.Doc != nil || field.Comment != nil {
				continue
			}
			for _, name := range field.Names {
				if isExported(name.Name) {
					problems = append(problems, missing(fset, path, name.Pos(), "field", name.Name))
				}
			}
		}
	case *ast.InterfaceType:
		for _, method := range typeValue.Methods.List {
			if method.Doc != nil {
				continue
			}
			for _, name := range method.Names {
				if isExported(name.Name) {
					problems = append(problems, missing(fset, path, name.Pos(), "interface method", name.Name))
				}
			}
		}
	}
	return problems
}

func isExported(name string) bool {
	runes := []rune(name)
	return len(runes) != 0 && unicode.IsUpper(runes[0])
}

func missing(fset *token.FileSet, path string, position token.Pos, kind, name string) string {
	return fmt.Sprintf("%s:%d: exported %s %s is missing a Godoc comment", path, fset.Position(position).Line, kind, name)
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
