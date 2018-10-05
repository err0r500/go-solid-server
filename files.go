package gold

import (
	"log"
	"os"

	crdf "github.com/presbrey/goraptor"
)

type FilesHandler interface {
	WriteFile(g *Graph, file *os.File, mime string) error
	AppendFile(g *Graph, filename string, baseURI string)
	ReadFile(g *Graph, parser Parser, filename string)
}

type OrigFilesHandler struct{}

// WriteFile is used to dump RDF from a Graph into a file
func (OrigFilesHandler) WriteFile(g *Graph, file *os.File, mime string) error {
	serializerName := mimeSerializer[mime]
	if len(serializerName) == 0 {
		serializerName = "turtle"
	}
	serializer := crdf.NewSerializer(serializerName)
	defer serializer.Free()
	err := serializer.SetFile(file, g.uri)
	if err != nil {
		return err
	}
	ch := make(chan *crdf.Statement, 1024)
	go func() {
		for triple := range g.IterTriples() {
			ch <- &crdf.Statement{
				Subject:   term2C(triple.Subject),
				Predicate: term2C(triple.Predicate),
				Object:    term2C(triple.Object),
			}
		}
		close(ch)
	}()
	serializer.AddN(ch)
	return nil
}

// AppendFile is used to append RDF from a file, using a base URI
func (OrigFilesHandler) AppendFile(g *Graph, filename string, baseURI string) {
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return
	} else if err != nil {
		log.Println(err)
		return
	}
	f, err := os.OpenFile(filename, os.O_RDONLY, 0)
	defer f.Close()
	if err != nil {
		log.Println(err)
		return
	}
	g.ParseBase(f, "text/turtle", baseURI)
}

// ReadFile is used to read RDF data from a file into the graph
func (OrigFilesHandler) ReadFile(g *Graph, parser Parser, filename string) {
	stat, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return
	} else if stat.IsDir() {
		return
	} else if !stat.IsDir() && err != nil {
		log.Println(err)
		return
	}
	f, err := os.OpenFile(filename, os.O_RDONLY, 0)
	defer f.Close()
	if err != nil {
		log.Println(err)
		return
	}
	parser.Parse(g, f, "text/turtle")
}
