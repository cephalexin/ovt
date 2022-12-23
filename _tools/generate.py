from argparse import ArgumentParser
from json import load, loads, dump as json_dump, JSONDecodeError
from os import makedirs
from os.path import isfile, isdir, exists, join
from re import compile, DOTALL
from shutil import rmtree
from sys import stderr

from bs4 import BeautifulSoup
from fake_useragent import UserAgent
from requests.sessions import session
from yaml import dump as yaml_dump

try:
    from yaml import CDumper as Dumper
except ImportError:
    from yaml import Dumper

REFS = [
    "errors",
    "url-object",
    "scan-url",
    "url-info",
    "urls-analyse"
]

BLOCK_REGEX = compile("\\[block:([a-z]+)](.*?)\\[/block]", DOTALL)
ITEM_REGEX = compile("`(.*?)` ?: \\*?<\\*?([a-z _]+)\\*> (.+)$")
ENUM_ITEM_REGEX = compile("\"(.*?)\" (.+)$")


def eprint(*args, **kwargs):
    print(*args, file=stderr, **kwargs)


def dir_path(st: str) -> str:
    if isdir(st) or not exists(st):
        return st
    raise NotADirectoryError(st)


class Parser:
    def __init__(self, verbose: bool):
        self.verbose = verbose
        self.oapi = {
            "openapi": "3.1.0",
            "info": {
                "title": "VirusTotal API v3",
                "version": "3.0"
            },
            "servers": [
                {
                    "url": "https://www.virustotal.com/api/v3"
                }
            ],
            "paths": {},
            "components": {
                "securitySchemes": {
                    "sec0": {
                        "type": "apiKey",
                        "in": "header",
                        "name": "X-Apikey"
                    }
                },
                "schemas": {}
            },
            "security": [
                {
                    "sec0": []
                }
            ]
        }

    def parse_errors(self, data: dict):
        table = Table()
        for match in BLOCK_REGEX.findall(data["doc"]["body"]):
            if match[0] == "parameters":
                table.parse(loads(match[1].strip()))
                break

        error_schema = {
            "type": "object",
            "description": BLOCK_REGEX.sub("", data["doc"]["body"]).strip(),
            "required": ["code", "message"],
            "properties": {
                "code": {
                    "type": "string",
                    "enum": table.get_column_cells(1),
                    "description": "\n".join(
                        [f"* `{row[1]}` ({row[0]}) - {row[2]}" for row in table.cells.values()]
                    )
                },
                "message": {
                    "type": "string"
                }
            }
        }

        self.oapi["components"]["schemas"]["Error"] = error_schema

    def parse_url_object(self, data: dict):
        root = Node("root")
        root.add_children([Node(line) for line in data["doc"]["body"].splitlines() if line.strip().startswith("*")])

        url_object_schema = {
            "type": "object",
            "description": data["doc"]["body"].split("[block:api-header]", 1)[0].strip(),
            "required": [],
            "properties": {}
        }

        def parse_item(it: dict | str) -> tuple[str, dict]:
            if self.verbose:
                print(f"parsing item: {it}")

            if isinstance(it, dict):
                k, v = next(iter(it.items()))
                if self.verbose:
                    print(f"key: {k}, value: {v}")

                m = ITEM_REGEX.search(k)
                if not m:
                    print(f"failed to match: {k}")

                if m.group(2) == "string" and isinstance(v, list):  # enum
                    props0 = {
                        "type": "string",
                        "description": m.group(3).strip(),
                        "enum": []
                    }
                    for item0 in v:
                        ma = ENUM_ITEM_REGEX.search(item0)
                        if not ma:
                            print(f"failed to match enum: {item0}")
                        props0["enum"].append(ma.group(1))
                        props0["description"] += f"\n* `{ma.group(1)}` - {ma.group(2)}"
                    return m.group(1), props0

                props0 = {
                    "type": "object",
                    "description": m.group(3).strip(),
                    "required": [],
                    "properties": {}
                }

                for item0 in v:
                    n, p = parse_item(item0)
                    if n and p:
                        props0["required"].append(n)
                        props0["properties"][n] = p

                return m.group(1), props0
            else:  # str
                m = ITEM_REGEX.search(it)
                if m:
                    props0 = {
                        "type": m.group(2),
                        "description": m.group(3).strip()
                    }
                    if m.group(2) == "dictionary":
                        props0["type"] = "object"
                        props0["additionalProperties"] = True
                    elif m.group(2) == "list of strings":
                        props0["type"] = "array"
                        props0["items"] = {"type": "string"}

                    return m.group(1), props0
                return "", {}

        for item in root.as_dict()["root"]:
            name, props = parse_item(item)
            url_object_schema["required"].append(name)
            url_object_schema["properties"][name] = props

        self.oapi["components"]["schemas"]["URLObject"] = url_object_schema

    def parse_route(self, data: dict, result_name: str):
        oas_def = data["oasDefinition"]
        path_def = next(iter(oas_def["paths"][data["doc"]["api"]["url"]].values()))
        if self.verbose:
            print(f"parsing oasDefinition: {path_def}")

        # don't use the default meta description
        if not path_def["description"] and "developers hub" not in data["meta"]["description"]:
            path_def["description"] = data["meta"]["description"]
        del path_def["x-readme"]

        for k, v in path_def["responses"].items():
            content = v["content"]["application/json"]
            del content["examples"]

            property_key = "data" if k.startswith('2') else "error"
            content["schema"] = {
                "type": "object",
                "required": [property_key],
                "properties": {
                    property_key: {
                        "$ref": f"#/components/schemas/{result_name if k.startswith('2') else 'Error'}"
                    }
                }
            }

        self.oapi["paths"].update(oas_def["paths"])

    def parse_scan_url(self, data: dict):
        self.parse_route(data, "URLObject")

    def parse_url_info(self, data: dict):
        self.parse_route(data, "URLObject")

    def parse_urls_analyse(self, data: dict):
        self.parse_route(data, "URLObject")


class Table:
    def __init__(self):
        self.headers = {}
        self.cells = {}

    def parse(self, data: dict):
        for k, v in data["data"].items():
            row, column = k.split("-", 1)
            if row == "h":  # row with headers
                self.set_column(int(column), v)
            else:
                self.set_cell(int(column), int(row), v)

    def set_column(self, index: int, name: str):
        self.headers[index] = name

    def set_cell(self, column_index: int, row_index: int, val: str):
        self.cells.setdefault(row_index, {})[column_index] = val

    def get_column_cells(self, column_index: int) -> list[str]:
        return [row[column_index] for row in self.cells.values()]


# https://stackoverflow.com/questions/17858404/creating-a-tree-deeply-nested-dict-from-an-indented-text-file-in-python
class Node:
    def __init__(self, indented_line: str):
        self.children = []
        self.level = len(indented_line) - len(indented_line.lstrip())
        self.text = indented_line.strip()

    def add_children(self, nodes: list):
        childlevel = nodes[0].level
        while nodes:
            node = nodes.pop(0)
            if node.level == childlevel:  # add node as a child
                self.children.append(node)
            elif node.level > childlevel:  # add nodes as grandchildren of the last child
                nodes.insert(0, node)
                self.children[-1].add_children(nodes)
            elif node.level <= self.level:  # this node is a sibling, no more children
                nodes.insert(0, node)
                return

    def as_dict(self) -> dict | str:
        if len(self.children) > 1:
            return {self.text: [node.as_dict() for node in self.children]}
        elif len(self.children) == 1:
            return {self.text: self.children[0].as_dict()}
        else:
            return self.text


if __name__ == "__main__":
    parser = ArgumentParser(
        description="Generates an OpenAPI specification from data scraped from developers.virustotal.com.")
    parser.add_argument("--data-folder", "-d", type=dir_path, help="the directory where results are stored",
                        default="./data")
    parser.add_argument("--verbose", "-v", help="should additional debugging output be printed?", action="store_true",
                        default=False)
    parser.add_argument("--clean", "-c", help="should the scraping data be cleared and re-scraped?",
                        action="store_true", default=False)

    p_args = parser.parse_args()

    if exists(p_args.data_folder) and p_args.clean:
        rmtree(p_args.data_folder)

    if not exists(p_args.data_folder):
        makedirs(p_args.data_folder)

    s = session()
    s.headers["User-Agent"] = UserAgent().chrome

    resolved_refs = {}
    for i in REFS:
        path = join(p_args.data_folder, f"{i}.json")
        if isfile(path):
            with open(path, "r") as f:
                try:
                    resolved_refs[i] = load(f)
                except JSONDecodeError as e:
                    eprint(f"could not parse JSON of {path}: {e}")
                    exit(1)
        else:
            r = s.get(f"https://developers.virustotal.com/reference/{i}")
            try:
                soup = BeautifulSoup(r.text, "html.parser")
                script = soup.find("div", attrs={"class": "ng-non-bindable"}).find("script")

                r_json = loads(script["data-initial-props"])

                # let's actually remove their API key from the JSON
                del r_json["search"]["appId"]
                del r_json["search"]["searchApiKey"]

                resolved_refs[i] = r_json
                with open(path, "w") as f:
                    json_dump(r_json, f, indent=2)
            except JSONDecodeError as e:
                eprint(f"could not parse div.ng-non-bindable[data-initial-props] of "
                       f"https://developers.virustotal.com/reference/{i}: {e}")
                if p_args.verbose:
                    eprint(r.text)
                exit(1)

    r_parser = Parser(p_args.verbose)

    for key, value in resolved_refs.items():
        getattr(r_parser, f"parse_{key.replace('-', '_')}")(value)

    with open(join(p_args.data_folder, "openapi.json"), "w") as f:
        json_dump(r_parser.oapi, f, indent=2)
    with open(join(p_args.data_folder, "openapi.yaml"), "w") as f:
        yaml_dump(r_parser.oapi, f, indent=2)
