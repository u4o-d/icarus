# ICARUS — MCP Threat Lab

> A research-grade lab for studying MCP-specific attacks and the layered runtime defenses needed to stop them.

**Status:** under construction. Full README, attack catalog, and detection matrix coming after the first eval run.

## Planned scope

- 6 attacks from 2025–2026 MCP security research
- 5 defense layers (static scan → regex → LLM judge → tool-arg auth → drift detection → output DLP)
- 1 evaluation harness producing a detection matrix

## Quickstart (preview)

```bash
git clone https://github.com/u4o-d/icarus
cd icarus
python -m venv .venv && source .venv/bin/activate
cp .env.example .env  # fill in OPENAI_API_KEY
pip install -e ".[dev,eval]"
```

Full instructions, attack catalog, defense layers, and detection matrix coming soon.

## Documentation

- [Architecture](docs/architecture.md)
- [Attacks](docs/attacks.md)
- [Defenses](docs/defenses.md)
- [Threat Model](docs/threat_model.md)
- [Detection Results](docs/results.md)

## Disclaimer

This repository contains intentionally vulnerable code for educational and defensive security research purposes. The vulnerable MCP server, attack payloads, and C2 simulator exist solely to demonstrate detection by the Sentinel guardrails layer. Do not deploy any component in production environments.

## License

MIT — see [LICENSE](LICENSE).
