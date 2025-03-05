import json
import os
import sys

from mitmproxy import flowfilter, http
from mitmproxy.tools import cmdline, dump
from mitmproxy.tools.main import run  # pyright: ignore[reportUnknownVariableType]


class Filter:
    def response(self, flow: http.HTTPFlow) -> None:
        filter_exp = "~d google.com"

        if flowfilter.match(filter_exp, flow) and (response := flow.response):
            try:
                data = response.json()
                _ = sys.stdout.writelines(json.dumps(data) + "\n")

            except json.decoder.JSONDecodeError as e:
                _ = sys.stderr.writelines(f"Error decoding JSON: {e}" + "\n")

            sys.stdout.flush()


class Dumper(dump.DumpMaster):
    def __init__(self, *args, **kwargs) -> None:  # pyright: ignore[reportMissingParameterType,reportUnknownParameterType]
        super().__init__(*args, **kwargs)  # pyright: ignore[reportUnknownMemberType]

        self.addons.add(Filter())  # pyright: ignore[reportUnknownMemberType]


def main():
    args = ("--quiet",)
    if upstream := os.getenv("http_proxy"):
        args += ("--mode", f"upstream:{upstream}")

    run(Dumper, cmdline.mitmdump, args)  # pyright: ignore[reportUnknownMemberType]


if __name__ == "__main__":
    main()
