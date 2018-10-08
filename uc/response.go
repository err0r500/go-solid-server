package uc

type response struct {
	status      int
	headers     map[string][]string
	body        []byte
	redirectURL string
	argv        []interface{}
}

func NewResponse() *response {
	return &response{
		status:  500,
		headers: map[string][]string{},
	}
}

func (r *response) HeaderAdd(key, value string) {
	r.headers[key] = append(r.headers[key], value)
}

func (r *response) HeaderSet(key, value string) {
	r.headers[key] = []string{value}
}

func (r *response) HeaderDel(key string) {
	r.headers[key] = []string{}
}

func (r *response) respond(status int, a ...interface{}) *response {
	r.status = status
	r.argv = a
	return r
}

func (r *response) ShouldRedirect() (bool, string) {
	switch r.status {
	case 301, 303:
		return true, r.redirectURL
	default:
		return false, ""
	}
}
