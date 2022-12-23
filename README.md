# ovt

[![Go Reference](https://pkg.go.dev/badge/github.com/cephalexin/ovt.svg)](https://pkg.go.dev/github.com/cephalexin/ovt)

A Go library for interfacing with the VirusTotal v3 API.

## Features

* typed objects and routes
* generation of an OpenAPI specification in JSON and YAML

### Generation

The [_tools/generate.py](./_tools/generate.py) script scrapes and parses the [developers.virustotal.com](https://developers.virustotal.com/reference) reference documentation and creates an OpenAPI specification from it.

### Supported objects

* URL

### Supported routes

* POST `/urls`
* GET `/urls/{id}`
* POST `/urls/{id}/analyse`

## Disclaimer

This library is in no way affiliated with nor endorsed by VirusTotal.