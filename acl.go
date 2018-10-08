package gold

import (
	"errors"
	"log"
	"strings"

	"github.com/err0r500/go-solid-server/domain"
)

// WAC WebAccessControl object
type WAC struct {
	user string
	key  string
}

// NewWAC creates a new WAC object
func NewWAC(user string, key string) WAC {
	return WAC{user: user, key: key}
}

const (
	readAccess    = "Read"
	writeAccess   = "Write"
	appendAccess  = "Append"
	controlAccess = "Control"
)

// AllowRead checks if Read access is allowed
func (s *Server) AllowRead(acl WAC, origin, path string) (int, error) {
	return s.allow(acl, origin, readAccess, path)
}

// AllowWrite checks if Write access is allowed
func (s *Server) AllowWrite(acl WAC, origin, path string) (int, error) {
	return s.allow(acl, origin, writeAccess, path)
}

// AllowAppend checks if Append access is allowed
func (s *Server) AllowAppend(acl WAC, origin, path string) (int, error) {
	return s.allow(acl, origin, appendAccess, path)
}

// AllowControl checks if Control access is allowed
func (s *Server) AllowControl(acl WAC, origin, path string) (int, error) {
	return s.allow(acl, origin, controlAccess, path)
}

func (s *Server) VerifyDelegator(delegator string, delegatee string) bool {
	g := domain.NewGraph(delegator)

	if err := s.httpCaller.LoadURI(g, delegator); err != nil {
		log.Println("Error loading graph for " + delegator)
	}

	for _, val := range g.All(domain.NewResource(delegator), domain.NewResource("http://www.w3.org/ns/auth/acl#delegates"), nil) {
		if s.uriManipulator.Debrack(val.Object.String()) == delegatee {
			return true
		}
	}
	return false
}

// Return an HTTP code and error (200 if authd, 401 if auth required, 403 if not authorized, 500 if error)
func (s *Server) allow(acl WAC, origin string, mode string, path string) (int, error) {
	accessType := "accessTo"
	p, err := s.pathInformer.GetPathInfo(path)
	if err != nil {
		return 500, err
	}
	depth := strings.Split(p.Path, "/")

	for d := len(depth); d >= 0; d-- {
		p, err := s.pathInformer.GetPathInfo(path)
		if err != nil {
			return 500, err
		}

		s.logger.Debug("Checking " + accessType + " <" + mode + "> to " + p.URI + " for WebID: " + acl.user)
		s.logger.Debug("Looking for policies in " + p.AclFile)

		aclGraph := domain.NewGraph(p.AclURI)
		s.fileHandler.UpdateGraphFromFile(aclGraph, s.parser, p.AclFile)
		if aclGraph.NotEmpty() {
			s.logger.Debug("Found policies in " + p.AclFile)
			// TODO make it more elegant instead of duplicating code
			for _, i := range aclGraph.All(nil, domain.NewNS("acl").Get("mode"), domain.NewNS("acl").Get("Control")) {
				for range aclGraph.All(i.Subject, domain.NewNS("acl").Get(accessType), domain.NewResource(p.URI)) {
					//					@@TODO add resourceKey to ACL vocab
					if len(acl.user) > 0 {
						s.logger.Debug("Looking for policy matching user:", acl.user)
						for range aclGraph.All(i.Subject, domain.NewNS("acl").Get("owner"), domain.NewResource(acl.user)) {
							s.logger.Debug(mode + " access allowed (as owner) for: " + acl.user)
							return 200, nil
						}
						for range aclGraph.All(i.Subject, domain.NewNS("acl").Get("agent"), domain.NewResource(acl.user)) {
							s.logger.Debug(mode + " access allowed (as agent) for: " + acl.user)
							return 200, nil
						}
					}
					if len(acl.key) > 0 {
						s.logger.Debug("Looking for policy matching key:", acl.key)
						for range aclGraph.All(i.Subject, domain.NewNS("acl").Get("resourceKey"), domain.NewLiteral(acl.key)) {
							s.logger.Debug(mode + " access allowed based on matching resource key")
							return 200, nil
						}
					}
					for _, t := range aclGraph.All(i.Subject, domain.NewNS("acl").Get("agentClass"), nil) {
						// check for foaf groups
						s.logger.Debug("Found agentClass policy")
						if t.Object.Equal(domain.NewNS("foaf").Get("Agent")) {
							s.logger.Debug(mode + " access allowed as FOAF Agent")
							return 200, nil
						}

						groupURI := s.uriManipulator.Debrack(t.Object.String())
						groupGraph := domain.NewGraph(groupURI)
						s.httpCaller.LoadURI(groupGraph, groupURI)
						if groupGraph.NotEmpty() && groupGraph.One(t.Object, domain.NewNS("rdf").Get("type"), domain.NewNS("foaf").Get("Group")) != nil {
							for range groupGraph.All(t.Object, domain.NewNS("foaf").Get("member"), domain.NewResource(acl.user)) {
								s.logger.Debug(acl.user + " listed as a member of the group " + groupURI)
								return 200, nil
							}
						}
					}
				}
			}

			for _, i := range aclGraph.All(nil, domain.NewNS("acl").Get("mode"), domain.NewNS("acl").Get(mode)) {
				s.logger.Debug("Found " + accessType + " policy for <" + mode + ">")
				for range aclGraph.All(i.Subject, domain.NewNS("acl").Get(accessType), domain.NewResource(p.URI)) {
					origins := aclGraph.All(i.Subject, domain.NewNS("acl").Get("origin"), nil)
					if len(origin) > 0 && len(origins) > 0 {
						s.logger.Debug("Origin set to: " + s.uriManipulator.Brack(origin))
						for _, o := range origins {
							if s.uriManipulator.Brack(origin) == o.Object.String() {
								s.logger.Debug("Found policy for origin: " + o.Object.String())
								goto allowOrigin
							}
						}
						continue
					} else {
						s.logger.Debug("No origin found, moving on")
					}
				allowOrigin:
					if len(acl.user) > 0 {
						s.logger.Debug("Looking for policy matching user:", acl.user)
						for range aclGraph.All(i.Subject, domain.NewNS("acl").Get("owner"), domain.NewResource(acl.user)) {
							s.logger.Debug(mode + " access allowed (as owner) for: " + acl.user)
							return 200, nil
						}
						for range aclGraph.All(i.Subject, domain.NewNS("acl").Get("agent"), domain.NewResource(acl.user)) {
							s.logger.Debug(mode + " access allowed (as agent) for: " + acl.user)
							return 200, nil
						}
					}
					if len(acl.key) > 0 {
						s.logger.Debug("Looking for policy matching key:", acl.key)
						for range aclGraph.All(i.Subject, domain.NewNS("acl").Get("resourceKey"), domain.NewLiteral(acl.key)) {
							s.logger.Debug(mode + " access allowed based on matching resource key")
							return 200, nil
						}
					}
					for _, t := range aclGraph.All(i.Subject, domain.NewNS("acl").Get("agentClass"), nil) {
						// check for foaf groups
						s.logger.Debug("Found agentClass policy")
						if t.Object.Equal(domain.NewNS("foaf").Get("Agent")) {
							s.logger.Debug(mode + " access allowed as FOAF Agent")
							return 200, nil
						}
						groupURI := s.uriManipulator.Debrack(t.Object.String())
						groupGraph := domain.NewGraph(groupURI)
						s.httpCaller.LoadURI(groupGraph, groupURI)
						if groupGraph.NotEmpty() && groupGraph.One(t.Object, domain.NewNS("rdf").Get("type"), domain.NewNS("foaf").Get("Group")) != nil {
							for range groupGraph.All(t.Object, domain.NewNS("foaf").Get("member"), domain.NewResource(acl.user)) {
								s.logger.Debug(acl.user + " listed as a member of the group " + groupURI)
								return 200, nil
							}
						}
					}
				}
			}
			if len(acl.user) == 0 && len(acl.key) == 0 {
				// fixme : this code seems problematic so it's just commented out for now
				//acl.srv.debug.Println("Authentication required")
				//tokenValues := map[string]string{
				//	"secret": string(acl.srv.cookieSalt),
				//}
				//// set validity for now + 1 min
				//validity := 1 * time.Minute
				//token, err := srv.NewSecureToken("WWW-Authenticate", tokenValues, validity)
				//if err != nil {
				//	//acl.srv.debug.Println("Error generating Auth token: ", err)
				//	return 500, err
				//}
				//wwwAuth := `WebID-RSA source="` + acl.req.BaseURI() + `", nonce="` + token + `"`
				//acl.w.Header().Set("WWW-Authenticate", wwwAuth)
				return 401, errors.New("Access to " + p.URI + " requires authentication")
			}
			s.logger.Debug(mode + " access denied for: " + acl.user)
			return 403, errors.New("Access denied for: " + acl.user)
		}

		accessType = "defaultForNew"

		// cd one level: walkPath("/foo/bar/baz") => /foo/bar/
		// decrement depth
		if len(depth) > 0 {
			depth = depth[:len(depth)-1]
		} else {
			depth = depth[:1]
		}
		path = walkPath(p.Base, depth)
	}
	s.logger.Debug("No ACL policies present - access allowed")
	return 200, nil
}

func walkPath(base string, depth []string) string {
	path := base + "/"
	if len(depth) > 0 {
		path += strings.Join(depth, "/") + "/"
	}
	return path
}
