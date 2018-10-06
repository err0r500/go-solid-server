package gold

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/err0r500/go-solid-server/webdav"

	"github.com/err0r500/go-solid-server/tokenStorer"

	"github.com/err0r500/go-solid-server/cookies"
	"github.com/err0r500/go-solid-server/domain"
	"github.com/err0r500/go-solid-server/encoder"
	"github.com/err0r500/go-solid-server/httpCaller"
	"github.com/err0r500/go-solid-server/mail"
	"github.com/err0r500/go-solid-server/mime"
	"github.com/err0r500/go-solid-server/pathInfo"
	"github.com/err0r500/go-solid-server/resources"
)

// NewServer is used to create a new Server instance
func NewServer(config domain.ServerConfig) *Server {
	debugger := log.New(ioutil.Discard, "", 0)
	if config.Debug {
		debugger = log.New(os.Stderr, "[debug] ", log.Flags()|log.Lshortfile)
	}

	s := &Server{
		Config:        config,
		cookieManager: cookies.New(),
		debug:         debugger,
		fileHandler:   resources.New(encoder.New()),
		httpCaller:    httpCaller.New(),
		mailer:        mail.New(domain.EmailConfig{}),
		parser:        encoder.New(),
		pathInformer:  pathInfo.New(config),
		rdfHandler:    encoder.RdfEncoder{},
		tokenStorer:   tokenStorer.New(config.BoltPath),
		webdavHandler: webdav.New(config.DataRoot),
		//webdav: &webdav.Handler{
		//	FileSystem: webdav.Dir(config.DataRoot),
		//	LockSystem: webdav.NewMemLS(),
		//},
	}

	mime.AddRDFExtension(s.Config.ACLSuffix)
	mime.AddRDFExtension(s.Config.MetaSuffix)

	s.debug.Println("---- starting server ----")
	s.debug.Printf("config: %#v\n", s.Config)
	return s
}

// NewServerConfig creates a new config object
func NewServerConfig() *domain.ServerConfig {
	return &domain.ServerConfig{
		CookieAge:  8736, // hours (1 year)
		TokenAge:   5,
		HSTS:       true,
		WebIDTLS:   true,
		MetaSuffix: ".meta",
		ACLSuffix:  ".acl",
		DataApp:    "tabulator",
		DirIndex:   []string{"index.html", "index.htm"},
		DirApp:     "http://linkeddata.github.io/warp/#list/",
		SignUpApp:  "https://solid.github.io/solid-signup/?domain=",
		DiskLimit:  100000000, // 100MB
		DataRoot:   serverDefaultRoot(),
		BoltPath:   filepath.Join(os.TempDir(), "bolt.db"),
		ProxyLocal: true,
	}
}

type ConfigLoader struct{}

// LoadJSONFile loads server configuration
func (ConfigLoader) LoadJSONFile(filename string) (*domain.ServerConfig, error) {
	b, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	c := &domain.ServerConfig{}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, err
	}
	return c, nil
}

func serverDefaultRoot() string {
	serverRoot, err := os.Getwd()
	if err != nil {
		log.Fatalln(err)
	}

	if !strings.HasSuffix(serverRoot, "/") {
		serverRoot += "/"
	}
	return serverRoot
}
