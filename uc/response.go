package uc

type Response struct {
	Status      int
	headers     map[string][]string
	Body        []interface{}
	redirectURL string
}

func NewResponse() *Response {
	return &Response{
		Status:  500,
		headers: map[string][]string{},
	}
}

func (r *Response) Headers() map[string][]string {
	return r.headers
}

func (r *Response) HeaderAdd(key, value string) {
	r.headers[key] = append(r.headers[key], value)
}

func (r *Response) HeaderSet(key, value string) {
	r.headers[key] = []string{value}
}

func (r *Response) HeaderDel(key string) {
	r.headers[key] = []string{}
}

func (r *Response) Respond(status int, a ...interface{}) *Response {
	r.Status = status
	r.Body = a
	return r
}

func (r *Response) ShouldRedirect() (bool, string) {
	switch r.Status {
	case 301, 303:
		return true, r.redirectURL
	default:
		return false, ""
	}
}
