package domain

import (
	"net/url"
	"time"
)

type PathInfo struct {
	Obj       *url.URL
	URI       string
	Base      string
	Path      string
	Root      string
	File      string
	FileType  string
	ParentURI string
	AclURI    string
	AclFile   string
	MetaURI   string
	MetaFile  string
	Extension string
	MaybeRDF  bool
	IsDir     bool
	Exists    bool
	ModTime   time.Time
	Size      int64
}

// ServerConfig holds a list of configuration parameters for the server
type ServerConfig struct {
	// PortHTTP contains the HTTPS listening port number in format ":80"
	ListenHTTP string

	// PortHTTPS contains the HTTPS listening port number in format ":443"
	ListenHTTPS string

	// WebIDTLS enables/disables client cert authentication (WebID-TLS) (on by default)
	WebIDTLS bool

	// TLSCert holds the server certificate eg. cert.pem
	TLSCert string

	// TLSKey holds the server key eg. key.pem
	TLSKey string

	// Root points to the folder that will be used as root for data
	DataRoot string

	// Vhosts enables the use of virtual hosts (i.e. user.example.org)
	Vhosts bool

	// Insecure enables insecure (HTTP) operation mode only
	Insecure bool

	// NoHTTP allows to enable or disable redirects from HTTP to HTTPS
	NoHTTP bool

	// HSTS enables or disables strict security transport
	HSTS bool

	// Debug (display or hide stdout logging)
	Debug bool

	// CookieAge contains the validity duration for cookies (in hours)
	CookieAge int64

	// TokenAge contains the validity duration for recovery tokens (in minutes)
	TokenAge int64

	// METASuffix sets the default suffix for meta files (e.g. ,meta or .meta)
	MetaSuffix string

	// ACLSuffix sets the default suffix for ACL files (e.g. ,acl or .acl)
	ACLSuffix string

	// DataApp sets the default app for viewing RDF resources
	DataApp string

	// DirApp points to the app for browsing the data space
	DirApp string

	// SignUpApp points to the app used for creating new accounts
	SignUpApp string

	// ProxyTemplate is the URL of the service that handles WebID-TLS delegation
	ProxyTemplate string

	// ProxyLocal enables/disables proxying of resources on localhost
	ProxyLocal bool

	// QueryTemplate is the URL of the service that handles query request using twinql
	QueryTemplate string

	// DirIndex contains the default index file name
	DirIndex []string

	// DiskLimit is the maximum total disk (in bytes) to be allocated to a given user
	DiskLimit int

	// Agent is the WebID of the agent used for WebID-TLS delegation (and proxy)
	Agent string

	// Salt is the value used for hashing passwords
	Salt string

	// BoltPath points to the location of the Bolt db on the filesystem
	BoltPath string

	// SMTPConfig holds the settings for the remote SMTP user/server
	SMTPConfig EmailConfig
}

// EmailConfig holds configuration values for remote SMTP servers
type EmailConfig struct {
	// Name of the remote SMTP server account, i.e. Server admin
	Name string
	// Addr is the remote SMTP server email address, i.e. admin@server.org
	Addr string
	// User is the remote SMTP server username, i.e. admin
	User string
	// Pass is the remote SMTP server password
	Pass string
	// Host is the remote SMTP server IP address or domain
	Host string
	// Port is the remote SMTP server port number
	Port int
	// ForceSSL forces SSL/TLS connection instead of StartTLS
	ForceSSL bool
	// Insecure allows connections to insecure remote SMTP servers (self-signed certs)
	Insecure bool
}
