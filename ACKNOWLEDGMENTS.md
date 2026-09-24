# Acknowledgments

Thanks to everyone who has contributed code, reviews, bug reports and design feedback to the Wazuh MCP Server. Pull request numbers refer to this repository.

## Code and pull requests

- **[@alokemajumder](https://github.com/alokemajumder)** — maintainer; architecture, MCP transport, security hardening, releases.
- **[@gensecai-dev](https://github.com/gensecai-dev)** — the 19 active-response, verification and rollback tools, fixes for broken Manager API endpoints, production hardening.
- **[@andrzej-piotrowski-pl](https://github.com/andrzej-piotrowski-pl)** — ISO 27001:2022 compliance tooling: per-control Annex A mapping to live Wazuh data, weighted domain scoring, gap analysis and the guided `iso27001_assessment` prompt (#74).
- **[@blackwell-systems](https://github.com/blackwell-systems)** — opt-in GCF response encoding for record tools (#102, #104).
- **[@lucascruzb](https://github.com/lucascruzb)** — period-wide alert aggregation (summarizing a whole time range without a per-document limit), which shaped the `get_alerts_aggregated` tool (#79, implemented in #81).
- **[@kanylbullen](https://github.com/kanylbullen)** — compact output mode for token-efficient responses (#65).
- **[@mouse-value-add](https://github.com/mouse-value-add)** — optional You.com web-search context, `search_external_context` (#85).
- **[@DrRSatzteil](https://github.com/DrRSatzteil)** — `tools/list` pagination fix (#70).
- **[@SiM22](https://github.com/SiM22)** — MCP 2025-06-18 support for Windsurf compatibility (#66).
- **[@aiunmukto](https://github.com/aiunmukto)** — `.env.example`, an early CI workflow and the Glama registry listing (#12).
- **[@Karibusan](https://github.com/Karibusan)** — dependency fixes (#38).
- **[@lwsinclair](https://github.com/lwsinclair)** — MseeP.ai listing (#9).
- **[@markeclaudio](https://github.com/markeclaudio)** — OIDC login, active-response guard-rails, session bounds and TLS-by-default hardening (#123–#127, in review).
- **[@MilkyWay88](https://github.com/MilkyWay88)** and **[@taylorwalton](https://github.com/taylorwalton)** — early pull requests on configuration, logging and packaging.

## Bug reports and discussions

[@cbassonbgroup](https://github.com/cbassonbgroup), [@cybersentinel-06](https://github.com/cybersentinel-06), [@daod-arshad](https://github.com/daod-arshad), [@mamema](https://github.com/mamema), [@marcolinux46](https://github.com/marcolinux46), [@matveevandrey](https://github.com/matveevandrey), [@punkpeye](https://github.com/punkpeye), [@tonyliu9189](https://github.com/tonyliu9189), [@Uberkarhu](https://github.com/Uberkarhu), [@bl4ck5w4n07](https://github.com/bl4ck5w4n07), [@gnix45](https://github.com/gnix45), [@hackdefendr](https://github.com/hackdefendr), [@melmasry1987](https://github.com/melmasry1987), [@Vasanth120v](https://github.com/Vasanth120v), [@wqfh](https://github.com/wqfh)

## Built on and works with

- [Wazuh](https://wazuh.com/) — open source security platform
- [Model Context Protocol](https://modelcontextprotocol.io/) — the protocol this server implements
- [vLLM](https://github.com/vllm-project/vllm), [Ollama](https://ollama.com/) and [Open WebUI](https://github.com/open-webui/open-webui) — local model serving and chat, used in the local LLM stack

The full contributor list, updated automatically, is in the [README](README.md#acknowledgments). Contributions of any size are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md).
