package resources

import (
	"bufio"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"os"

	"github.com/err0r500/go-solid-server/constant"

	"github.com/err0r500/go-solid-server/uc"

	_path "path"

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

func (origFilesHandler) SaveFiles(folder string, files map[string]io.Reader) error {
	if err := createFolderIfNeeded(folder); err != nil {
		return err
	}

	for filename, reader := range files {
		if err := saveFile(filename, reader); err != nil { //todo : check if needs to add folder to filename ?
			return err
		}
	}

	return nil
}

func (origFilesHandler) GetFileContent(path string) ([]byte, error) {
	return ioutil.ReadFile(path)
}

// SaveGraph is used to dump RDF from a Graph into a file
func (origFilesHandler) SaveGraph(g *domain.Graph, path string, mime string) error {
	if err := createFolderIfNeeded(path); err != nil {
		return err
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0664)
	if err != nil {
		return err
	}
	defer f.Close()
	// fixme : actually write the file!
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
func (h origFilesHandler) Read(path string) (io.Reader, error) { return os.Open(path) }
func (h origFilesHandler) FileFirstLine(path string) (string, error) {
	fd, err := h.Read(path)
	if err != nil {
		return "", err
	}
	scanner := bufio.NewScanner(fd)

	// returns directly at the first line
	for scanner.Scan() {
		return scanner.Text(), nil
	}

	return "", errors.New("nothing to read in file : " + path)
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

func (origFilesHandler) Delete(path string) error {
	return os.Remove(path)
}

func (origFilesHandler) CreateFileOrDir(path string) error {
	err := createFolderIfNeeded(path)
	if err != nil {
		return err
	}

	if fileInfo, _ := os.Stat(path); fileInfo != nil && fileInfo.IsDir() { // if a directory was asked, stop here
		return nil
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	return nil
}

func (origFilesHandler) CreateOrUpdateFile(path string, reader io.Reader) error {
	if err := os.MkdirAll(_path.Dir(path), 0755); err != nil {
		return err
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err = io.Copy(f, reader); err != nil {
		return err
	}
	return nil
}

// UpdateGraphFromFile is used to read RDF data from a file into the graph
func (origFilesHandler) UpdateGraphFromFile(g *domain.Graph, parser uc.Encoder, filename string) {
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
	st, err := os.Stat(path)
	return st != nil && !os.IsNotExist(err)
}

func createFolderIfNeeded(path string) error {
	return os.MkdirAll(_path.Dir(path), 0755)
}

func saveFile(path string, reader io.Reader) error {
	dst, err := os.Create(path)
	defer dst.Close()

	if err != nil {
		return err
	}

	if _, err := io.Copy(dst, reader); err != nil {
		return err
	}

	return nil
}
