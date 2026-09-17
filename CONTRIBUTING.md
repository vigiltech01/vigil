# Contributing to Vigil

Thanks for helping! Bug reports, FortiOS log samples (anonymised), documentation and code are all welcome.

## Development setup

```bash
git clone https://github.com/MrkktestHari/vigil.git && cd vigil
python3.12 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
pytest                                   # unit + end-to-end tests, about 20 seconds
docker build -t vigil:dev .
docker run --rm -p 8080:8080 -e VIGIL_DEMO=1 vigil:dev   # full app with demo data
```

The front end is plain JavaScript and CSS in `web/static/` - no build step. Rebuild the image (a few seconds, cached) and
reload the page after editing. To run from a checkout without Docker, download the libraries listed in the `Dockerfile` into
`web/static/vendor/` first.

## Guidelines

- Keep changes focused; include a test for parser, import or API changes (`tests/`).
- **Never commit real log lines, configurations or IP addresses.** Use the RFC 5737 documentation ranges
  (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and invented names in tests, docs and screenshots.
- Regenerate screenshots only from demo mode: `scripts/screenshots.py` refuses to run against a non-demo instance.
- UI text should be plain English that a non-specialist can act on.
- Charts use the validated palette in `web/static/app.js` (`C`) in fixed order; status colours are reserved for status.

## Pull requests

1. Fork and create a branch.
2. `pytest` passes and `docker build` succeeds.
3. Describe what changed and why; add screenshots for UI changes.

By contributing you agree that your contributions are licensed under the Apache License 2.0.
