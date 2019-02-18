package main

import (
	"regexp"
)

// Common resolutions: https://www.w3schools.com/browsers/browsers_display.asp
type Config struct {
	AllowedResolutions []Resolution
	UserAgents         []string
	UrlMatchers        []*regexp.Regexp
}

var DefaultConf = Config{
	AllowedResolutions: []Resolution{
		Resolution{1366, 768},
	},
	UserAgents: []string{},
}
