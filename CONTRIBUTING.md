# Contributing to aiscan

Thanks for your interest! Contributions are welcome — here's how to get started.

## Getting set up

```bash
git clone https://github.com/samsepassi1/aiscan
cd aiscan
pip install -e ".[dev]"
```

## Adding a new rule

Rules live in `src/aiscan/rules/python/` or `src/aiscan/rules/javascript/`. Each rule extends `BaseRule`. Add a matching fixture in `tests/fixtures/vulnerable/` and `tests/fixtures/safe/`, then add a test in `tests/test_rule_engine.py`.

## Submitting a PR

- Run `pytest tests/ -v` before submitting
- Run `ruff check src/ tests/` to lint
- Keep PRs focused — one rule or fix per PR
- Include a vulnerable fixture that reproduces the issue

## Reporting a vulnerability

Open a GitHub Issue with the label `security`. Do not include live API keys or credentials in bug reports.
