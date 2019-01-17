package kraaler

import "net/url"

type Store interface {
	Push(*url.URL)
	Fetch() *FetchRequest
}
