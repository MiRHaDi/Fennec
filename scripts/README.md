# scripts/

Manual, developer-run checks. These are **not** part of the automated `pytest`
suite — they make real (paid) LLM calls and require API keys, so they live here
rather than under `tests/`.

- `manual_recon_fallback_check.py` — exercises the recon large-context fallback path.
- `manual_structured_extraction_check.py` — exercises structured-output extraction live.

Run them directly, e.g.:

```bash
python scripts/manual_recon_fallback_check.py
```
