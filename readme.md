# Kraaler
[![Build Status](https://travis-ci.com/aau-network-security/kraaler.svg?token=Yc2xb5VVELJexrKxtyY8&branch=master)](https://travis-ci.com/aau-network-security/kraaler)

This is an Go implementation of the design covered in /Kraaler: A User Perspective Web Crawler/ and presented at [TMA 2019](https://tma.ifip.org/2019)

## Building
Kraaler requires `CGO_ENABLED=1` (C-support in Go), due to the use of sqlite.
In order to compile the binary a set of C libraries is needed.
The official [Golang Docker Images](https://hub.docker.com/_/golang) comes pre-bundled with these C dependencies, making them a convenient tool for compilation.

``` bash
docker run \
	--rm \
	-v $(pwd):/go/src/github.com/aau-network-security/kraaler \
	-w /go/src/github.com/aau-network-security/kraaler/app/ \
	-e GO111MODULE=on \
	-e GOOS=linux \
	-e GOARCH=amd64 \
	-e CGO_ENABLED=1 \
	-e HOST_UID=`id -u` \
	golang:1.12.6 \
	bash build.sh
```
Remember to set `GOOS` and `GOARCH` [according to your platform](https://github.com/golang/go/blob/master/src/go/build/syslist.go).

## Running

``` bash
$ krl run -n 3 \ # amount of workers
  --provider-file urls.txt \ # provider for urls
  --sampler 'uni' \ # sampler for prioritization of urls
  --filter-resp-bodies-ct '^text/' # only text bodies
```


## Contributors
- Thomas Kobber Panum ([@tpanum](https://github.com/tpanum/))
