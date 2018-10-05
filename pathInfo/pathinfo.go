package pathInfo

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	_path "path"
	"path/filepath"
	"strings"

	"github.com/err0r500/go-solid-server/domain"
	"github.com/err0r500/go-solid-server/mime"
	"github.com/err0r500/go-solid-server/uc"
)

type pathInfoGetter struct {
	serverConfig domain.ServerConfig
}

func New(srvConfig domain.ServerConfig) uc.PathInformer {
	return pathInfoGetter{
		serverConfig: srvConfig,
	}
}

func (iG pathInfoGetter) GetPathInfo(path string) (*domain.PathInfo, error) {
	if len(path) == 0 {
		return nil, errors.New("missing resource path")
	}

	// hack - if source URI contains "one%2b+%2btwo" then it is
	// normally decoded to "one+ +two", but Go parses it to
	// "one+++two", so we replace the plus with a blank space
	// strings.Replace(path, "+", "%20", -1)

	p, err := url.Parse(path)
	if err != nil {
		return nil, err
	}

	res := &domain.PathInfo{}
	res.Base = p.Scheme + "://" + p.Host
	res.Root = iG.serverConfig.DataRoot
	// include host and port if running in vhosts mode
	host, port, _ := net.SplitHostPort(p.Host)
	if len(host) == 0 {
		host = p.Host
	}
	if len(port) > 0 {
		host += ":" + port
	}
	if iG.serverConfig.Vhosts {
		res.Root = iG.serverConfig.DataRoot + host + "/"
		res.Base = p.Scheme + "://" + host
	}

	// p.Path = p.String()[len(p.Scheme+"://"+p.Host):]
	if strings.HasPrefix(p.Path, "/") && len(p.Path) > 0 {
		p.Path = strings.TrimLeft(p.Path, "/")
	}

	if len(p.Path) == 0 {
		res.URI = p.String() + "/"
	} else {
		res.URI = p.String()
	}
	res.Obj = p
	res.File = p.Path
	res.Path = p.Path

	if iG.serverConfig.Vhosts {
		res.File = res.Root + p.Path
	} else if len(iG.serverConfig.DataRoot) > 0 {
		res.File = iG.serverConfig.DataRoot + p.Path
	}

	res.Exists = true
	res.IsDir = false
	// check if file exits first
	if stat, err := os.Stat(res.File); os.IsNotExist(err) {
		res.Exists = false
	} else {
		res.ModTime = stat.ModTime()
		res.Size = stat.Size()
		// Add missing trailing slashes for dirs
		if stat.IsDir() {
			res.IsDir = true
			if !strings.HasSuffix(res.Path, "/") && len(res.Path) > 1 {
				res.Path += "/"
				res.File += "/"
				res.URI += "/"
			}
		} else {
			res.FileType, res.Extension, res.MaybeRDF = mime.MimeLookup(res.File)
			if len(res.FileType) == 0 {
				res.FileType, err = mime.GuessMimeType(res.File)
				if err != nil {
					fmt.Println(err)
					//req.Server.debug.Println(err)
				}
			}
		}
	}

	if len(res.Extension) == 0 {
		res.Extension = _path.Ext(res.File)
	}

	if strings.HasSuffix(res.Path, "/") {
		if filepath.Dir(filepath.Dir(res.Path)) == "." {
			res.ParentURI = res.Base + "/"
		} else {
			res.ParentURI = res.Base + "/" + filepath.Dir(filepath.Dir(res.Path)) + "/"
		}
	} else {
		res.ParentURI = res.Base + "/" + filepath.Dir(res.Path) + "/"
	}

	if strings.HasSuffix(res.Path, iG.serverConfig.ACLSuffix) {
		res.AclURI = res.URI
		res.AclFile = res.File
		res.MetaURI = res.URI
		res.MetaFile = res.File
	} else if strings.HasSuffix(res.Path, iG.serverConfig.MetaSuffix) {
		res.AclURI = res.URI + iG.serverConfig.ACLSuffix
		res.AclFile = res.File + iG.serverConfig.ACLSuffix
		res.MetaURI = res.URI
		res.MetaFile = res.File
	} else {
		res.AclURI = res.URI + iG.serverConfig.ACLSuffix
		res.AclFile = res.File + iG.serverConfig.ACLSuffix
		res.MetaURI = res.URI + iG.serverConfig.MetaSuffix
		res.MetaFile = res.File + iG.serverConfig.MetaSuffix
	}

	return res, nil
}
