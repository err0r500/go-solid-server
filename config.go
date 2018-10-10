package gold

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/err0r500/go-solid-server/authentication"
	"github.com/err0r500/go-solid-server/uuid"

	"github.com/err0r500/go-solid-server/sparql"

	"github.com/err0r500/go-solid-server/uc"

	"github.com/boltdb/bolt"

	"github.com/err0r500/go-solid-server/pages"

	"github.com/err0r500/go-solid-server/logger"

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
	debugger := logger.New(log.New(ioutil.Discard, "", 0))
	if config.Debug {
		debugger = logger.New(log.New(os.Stderr, "[debug] ", log.Flags()|log.Lshortfile))
	}

	db, err := bolt.Open(config.BoltPath, 0644, nil)
	if err != nil {
		log.Fatal("failed to start bolt db")
	}
	defer db.Close()

	s := &Server{
		Config: config,
		i: uc.NewInteractor(
			config,
			cookies.New(config.CookieAge),
			debugger,
			resources.New(encoder.New()),
			httpCaller.New(),
			mail.New(domain.EmailConfig{}),
			pathInfo.New(config),
			encoder.New(),
			sparql.New(),
			pages.New(config.DataRoot),
			tokenStorer.New(db),
			domain.URIHandler{},
			uuid.New(),
			authentication.New(httpCaller.New()),
		),

		cookieManager:  cookies.New(config.CookieAge),
		logger:         debugger,
		fileHandler:    resources.New(encoder.New()),
		httpCaller:     httpCaller.New(),
		mailer:         mail.New(domain.EmailConfig{}),
		pathInformer:   pathInfo.New(config),
		parser:         encoder.New(),
		rdfHandler:     encoder.RdfEncoder{},
		templater:      pages.New(config.DataRoot),
		tokenStorer:    tokenStorer.New(db),
		uriManipulator: domain.URIHandler{},

		//webdavHandler: webdav.New(config.DataRoot),
	}

	mime.AddRDFExtension(s.Config.ACLSuffix)
	mime.AddRDFExtension(s.Config.MetaSuffix)

	s.logger.Debug("---- starting server ----")
	s.logger.Debug("config: %#v\n", s.Config)
	return s
}

// NewServerConfig creates a new config object
func NewServerConfig() *domain.ServerConfig {
	log.Println("load config")
	return &domain.ServerConfig{
		ListenHTTP:  ":8080",
		ListenHTTPS: ":8443",
		Debug:       true,
		CookieAge:   8736, // hours (1 year)
		TokenAge:    5,
		HSTS:        false,
		WebIDTLS:    true,
		MetaSuffix:  ".meta",
		ACLSuffix:   ".acl",
		DataApp:     "tabulator",
		DirIndex:    []string{"index.html", "index.htm"},
		DirApp:      "http://linkeddata.github.io/warp/#list/",
		SignUpApp:   "https://solid.github.io/solid-signup/?domain=",
		DiskLimit:   100000000, // 100MB
		DataRoot:    serverDefaultRoot(),
		BoltPath:    filepath.Join(os.TempDir(), "bolt.db"),
		ProxyLocal:  true,
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

	// todo : hard coded for development, return just serverRoot when everything is fine
	return serverRoot + "_testRootFolder/"
}
