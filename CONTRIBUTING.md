# Contributing

```bash
pip install -e . pytest pytest-cov ruff
ruff check . && ruff format --check .
pytest --cov=sweepsafe
node --test tests/js/
```

Rules live in `src/sweepsafe/data/rules.json`; `docs/rules.json` must be an identical copy
(CI checks it). Any change to scoring needs a case in `tests/fixtures/parity_cases.json`,
computed by hand, so Python and JavaScript are checked against the same answer.

## Good first issues

- Add another chain (add it to `config/chains.py` and `CHAINS` in `docs/sweepsafe.js`; the parity test will tell you if they differ).
- Add a risk rule (needs a Python rule, a JS rule, a rules.json weight and a fixture).
- Better address-list sources for the blocklist.
- Translate the explanation templates.
