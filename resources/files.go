package resources

import (
	"log"
	"os"

	"github.com/err0r500/go-solid-server/constant"

	"github.com/err0r500/go-solid-server/uc"

	"github.com/err0r500/go-solid-server/domain"
)

type origFilesHandler struct {
	rdfHandler uc.Encoder
}

func New(encoder uc.Encoder) uc.FilesHandler {
	return origFilesHandler{
		rdfHandler: encoder,
	}
}

// WriteFile is used to dump RDF from a Graph into a file
func (origFilesHandler) WriteFile(g *domain.Graph, file *os.File, mime string) error {
	//serializerName := mimeSerializer[mime]
	//if len(serializerName) == 0 {
	//	serializerName = "turtle"
	//}
	//serializer := crdf.NewSerializer(serializerName)
	//defer serializer.Free()
	//err := serializer.SetFile(file, g.URI())
	//if err != nil {
	//	return err
	//}
	//ch := make(chan *crdf.Statement, 1024)
	//go func() {
	//	for triple := range g.IterTriples() {
	//		ch <- &crdf.Statement{
	//			Subject:   FromDomain(triple.Subject),
	//			Predicate: FromDomain(triple.Predicate),
	//			Object:    FromDomain(triple.Object),
	//		}
	//	}
	//	close(ch)
	//}()
	//serializer.AddN(ch)
	return nil
}

// AppendFile is used to append RDF from a file, using a base URI
func (h origFilesHandler) AppendFile(g *domain.Graph, filename string, baseURI string) {
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

	h.rdfHandler.ParseBase(g, f, constant.TextTurtle, baseURI)
}

// ReadFile is used to read RDF data from a file into the graph
func (origFilesHandler) ReadFile(g *domain.Graph, parser uc.Encoder, filename string) {
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
	parser.Parse(g, f, constant.TextTurtle)
}

func (origFilesHandler) Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
