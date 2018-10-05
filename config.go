package gold

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/err0r500/go-solid-server/domain"
)

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
