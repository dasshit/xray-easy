// Command check-go-docs verifies that handwritten exported Go APIs have Go doc comments.
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

// sourceFile is an internal type used by the package.
type sourceFile struct {
	path string
	dir  string
	file *ast.File
}

// main starts the program.
func main() {
	fset := token.NewFileSet()
	files, err := collectFiles(fset)
	if err != nil {
		fail(err.Error())
	}

	var problems []string
	packageDirs := make(map[string]bool)
	packageDocs := make(map[string]bool)
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
	fmt.Printf("PASS Go documentation check: %d handwritten source file(s) have documented exported API declarations\n", len(files))
}

// collectFiles performs the operation represented by its name.
func collectFiles(fset *token.FileSet) ([]sourceFile, error) {
	roots := []string{"internal", "cmd", "awg-service", "xray-runtime", "scripts"}
	var files []sourceFile
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

// isHandwrittenGoFile performs the operation represented by its name.
func isHandwrittenGoFile(path string) bool {
	if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || strings.HasSuffix(path, ".pb.go") || strings.HasSuffix(path, "_grpc.pb.go") {
		return false
	}
	return true
}

// hasPackageDoc performs the operation represented by its name.
func hasPackageDoc(file *ast.File) bool {
	if file.Doc == nil {
		return false
	}
	text := strings.TrimSpace(file.Doc.Text())
	if strings.HasPrefix(text, "Package "+file.Name.Name) {
		return true
	}
	// A command package may use the conventional "Command name ..." form.
	return file.Name.Name == "main" && strings.HasPrefix(text, "Command ")
}

// checkFile performs the operation represented by its name.
func checkFile(fset *token.FileSet, source sourceFile) []string {
	var problems []string
	for _, declaration := range source.file.Decls {
		switch declaration := declaration.(type) {
		case *ast.FuncDecl:
			if isExported(declaration.Name.Name) && isPublicMethod(declaration) && declaration.Doc == nil {
				problems = append(problems, missing(fset, source.path, declaration.Pos(), "function", declaration.Name.Name))
			}
		case *ast.GenDecl:
			for _, spec := range declaration.Specs {
				switch spec := spec.(type) {
				case *ast.TypeSpec:
					if isExported(spec.Name.Name) && declaration.Doc == nil && spec.Doc == nil {
						problems = append(problems, missing(fset, source.path, spec.Pos(), "type", spec.Name.Name))
					}
					if isExported(spec.Name.Name) {
						problems = append(problems, checkType(fset, source.path, spec)...)
					}
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

// isPublicMethod reports whether declaration is a method on an exported type.
func isPublicMethod(declaration *ast.FuncDecl) bool {
	if declaration.Recv == nil {
		return true
	}
	if len(declaration.Recv.List) != 1 {
		return false
	}
	return isExported(receiverTypeName(declaration.Recv.List[0].Type))
}

// receiverTypeName returns the identifier naming a method's receiver type.
func receiverTypeName(expression ast.Expr) string {
	switch expression := expression.(type) {
	case *ast.Ident:
		return expression.Name
	case *ast.StarExpr:
		return receiverTypeName(expression.X)
	case *ast.IndexExpr:
		return receiverTypeName(expression.X)
	case *ast.IndexListExpr:
		return receiverTypeName(expression.X)
	default:
		return ""
	}
}

// checkType performs the operation represented by its name.
func checkType(fset *token.FileSet, path string, typeSpec *ast.TypeSpec) []string {
	var problems []string
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

// isExported performs the operation represented by its name.
func isExported(name string) bool {
	runes := []rune(name)
	return len(runes) != 0 && unicode.IsUpper(runes[0])
}

// missing performs the operation represented by its name.
func missing(fset *token.FileSet, path string, position token.Pos, kind, name string) string {
	return fmt.Sprintf("%s:%d: %s %s is missing a Go doc comment", path, fset.Position(position).Line, kind, name)
}

// fail performs the operation represented by its name.
func fail(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
