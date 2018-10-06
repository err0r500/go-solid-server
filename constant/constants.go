package constant

const (
	// HCType is the header Content-Type
	HCType = "Content-Type"
	// SystemPrefix is the generic name for the system-reserved namespace (e.g. APIs)
	SystemPrefix = ",account"
	// LoginEndpoint is the link to the login page
	LoginEndpoint = SystemPrefix + "/login"
	// ProxyPath provides CORS proxy (empty to disable)
	ProxyPath = ",proxy"
	// QueryPath provides link-following support for twinql
	QueryPath = ",query"
	// AgentPath is the path to the agent's WebID profile
	AgentPath = ",agent"
	// RDFExtension is the default extension for RDF documents (i.e. turtle for now)
	RDFExtension = ".ttl"
)

const (
	TextPlain       = "text/plain"
	TextHtml        = "text/html"
	TextN3          = "text/n3"
	TextTurtle      = "text/turtle"
	ApplicationJSON = "application/json"

	HAuthorization = "HAuthorization"
)

func AllMethods() []string {
	return []string{
		"OPTIONS", "HEAD", "GET",
		"PATCH", "POST", "PUT", "MKCOL", "DELETE",
		"COPY", "MOVE", "LOCK", "UNLOCK",
	}
}
