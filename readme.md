# Kraaler
[![Build Status](https://travis-ci.com/aau-network-security/kraaler.svg?token=Yc2xb5VVELJexrKxtyY8&branch=master)](https://travis-ci.com/aau-network-security/kraaler)

This is an Go implementation of the design covered in the [Kraaler: A User Perspective Web Crawler]

## Running

``` bash
$ krl run -n 3 \ # amount of workers
  --provider-file urls.txt \ # provider for urls
  --sampler 'uni' \ # sampler for prioritization of urls
  --filter-resp-bodies-ct '^text/' # only text bodies
```


## Contributors
- Thomas Kobber Panum ([@tpanum](https://github.com/tpanum/))
