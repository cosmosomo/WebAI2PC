# Third-Party Notices

Cosmos MCP (`cosmos-mcp`) is licensed under the MIT License (see [`LICENSE`](LICENSE)).

The lightweight source distribution (`Cosmos-MCP-v<version>.zip`) contains only first-party Cosmos MCP source code and documentation. The standalone Windows 64-bit portable bundle (`Cosmos-MCP-v<version>-win64-full.zip`) additionally redistributes the official CPython Windows Embeddable Package, OpenSSL shared libraries, and pre-installed open-source Python runtime packages listed below.

## 1. Bundled Runtime & Native Libraries (`win64-full.zip` only)

| Component | License | Upstream Project |
| :--- | :--- | :--- |
| Python (CPython 3.12 Windows Embeddable Package) | Python Software Foundation License v2 (`PSF-2.0`) | https://www.python.org/ |
| OpenSSL (`libcrypto-3.dll`, `libssl-3.dll`) | Apache License 2.0 (`Apache-2.0`) | https://www.openssl.org/ |
| `libffi` / `sqlite3` / `zlib` / `bzip2` / `xz` (bundled with CPython) | MIT / Public Domain / zlib / BSD-style (per `python-embed/LICENSE.txt`) | https://docs.python.org/3/license.html |

Full CPython and bundled C library license texts are included inside `python-embed/LICENSE.txt` in the `win64-full.zip` archive.

## 2. Core & Document Python Dependencies

| Package | License | Upstream Project |
| :--- | :--- | :--- |
| `mcp` | MIT | https://github.com/modelcontextprotocol/python-sdk |
| `starlette` | BSD-3-Clause | https://github.com/encode/starlette |
| `uvicorn` | BSD-3-Clause | https://github.com/encode/uvicorn |
| `websockets` | BSD-3-Clause | https://github.com/python-websockets/websockets |
| `cryptography` | Apache-2.0 OR BSD-3-Clause | https://github.com/pyca/cryptography |
| `pydantic` / `pydantic-core` / `pydantic-settings` | MIT | https://github.com/pydantic/pydantic |
| `python-multipart` | Apache-2.0 | https://github.com/Kludex/python-multipart |
| `Pillow` | MIT-CMU (HPND) | https://github.com/python-pillow/Pillow |
| `pypdf` | BSD-3-Clause | https://github.com/py-pdf/pypdf |
| `openpyxl` / `et_xmlfile` | MIT | https://foss.heptapod.net/openpyxl/openpyxl |
| `python-docx` | MIT | https://github.com/python-openxml/python-docx |
| `python-pptx` | MIT | https://github.com/scanny/python-pptx |
| `lxml` | BSD-3-Clause | https://github.com/lxml/lxml |
| `XlsxWriter` | BSD-2-Clause | https://github.com/jmcnamara/XlsxWriter |
| `anyio` | MIT | https://github.com/agronholm/anyio |
| `httpx` / `httpcore` | BSD-3-Clause | https://github.com/encode/httpx |
| `httpx-sse` | MIT | https://github.com/florimondmanca/httpx-sse |
| `sse-starlette` | BSD-3-Clause | https://github.com/sysid/sse-starlette |
| `PyJWT` | MIT | https://github.com/jpadilla/pyjwt |
| `jsonschema` / `jsonschema-specifications` / `referencing` / `rpds-py` / `attrs` | MIT | https://github.com/python-jsonschema/jsonschema |
| `cffi` | MIT-0 / MIT | https://github.com/python-cffi/cffi |
| `pycparser` | BSD-3-Clause | https://github.com/eliben/pycparser |
| `click` | BSD-3-Clause | https://github.com/pallets/click |
| `h11` | MIT | https://github.com/python-hyper/h11 |
| `python-dotenv` | BSD-3-Clause | https://github.com/theskumar/python-dotenv |
| `idna` | BSD-3-Clause | https://github.com/kjd/idna |
| `typing_extensions` | PSF-2.0 | https://github.com/python/typing_extensions |
| `typing-inspection` / `annotated-types` | MIT | https://github.com/pydantic/typing-inspection |
| `certifi` | Mozilla Public License 2.0 (`MPL-2.0`) | https://github.com/certifi/python-certifi |

Individual package `LICENSE` and `METADATA` files are preserved unmodified inside each `python-embed/Lib/site-packages/*.dist-info/` directory in `win64-full.zip`. Under `MPL-2.0`, unmodified `certifi` CA bundle files remain governed by `MPL-2.0` with source code available at https://github.com/certifi/python-certifi.
