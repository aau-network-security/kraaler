package kraaler

import "net/url"

type FetchRequest struct {
	Url       *url.URL
	UserAgent string
}

type FetchResponse struct {
	Request    *FetchRequest
	Error      error
	Screenshot []byte
	Urls       []*url.URL
}
