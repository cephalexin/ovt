package ovt

//go:generate python3 _tools/generate.py --clean
//go:generate ogen --package ovt --no-server --target . --clean data/openapi.yaml
