# Third-Party License & Compliance Audit — SUMIT KEY

**Audit date:** 2026-07-24
**Scope:** Every runtime dependency actually installed by `requirements.txt` (direct + transitive), the JS/HTML assets shipped in this repo, and the AI coding tools used to help build the project.
**Method:** `pip show` / `pip-licenses` against the installed environment, cross-checked against each project's published `LICENSE` file on its home repository. No dependency was taken on trust from a `pip` classifier alone — see "How this was verified" at the bottom.

---

## 1. Summary verdict

| Question | Answer |
|---|---|
| Any GPL / AGPL (strong copyleft) dependency? | **No.** |
| Any dependency requiring you to open-source this repo? | **No.** |
| Any dependency with an incompatible license for the dual MIT/proprietary structure in [`LICENSE`](../LICENSE)? | **No**, but one (`pynput`) is **weak copyleft (LGPL-3.0)** and needs the attribution this document now provides — see §3. |
| Any AI/ML model or LLM SDK compiled into the running application? | **No.** Confirmed by dependency scan and import grep — nothing named `openai`, `anthropic`, `langchain`, `transformers`, etc. is imported anywhere in `.py` source (the two grep hits are a docstring using the word "coherent" and a regex literal matching `sk-` style API keys in a secret-scanner test — neither is a library call). |
| Any external CDN / third-party JS pulled into the dashboards at runtime? | **No.** All dashboard HTML files are self-contained; no `<script src="https://...">` or CDN references were found. |

---

## 2. Direct + transitive dependency table

Generated from the environment that `requirements.txt` actually installs (Python 3.12), via `pip-licenses`.

| Package | Version | License | Category | Notes |
|---|---|---|---|---|
| numpy | 1.26.4 | BSD-3-Clause | Direct | Permissive. Wheel bundles OpenBLAS/LAPACK (BSD-3), and on some platforms a GCC Fortran runtime shim under **GPL-3.0-with-GCC-Runtime-Library-Exception** — the exception explicitly permits this without imposing GPL on your code. |
| nistrng | 1.2.3 | BSD-3-Clause | Direct | Permissive. |
| pynput | 1.8.2 | **LGPL-3.0** | Direct | Weak copyleft — see §3. Used only via normal `pip install` + `import`, never vendored/statically linked, so obligations are satisfiable. |
| fastapi | 0.136.3 | MIT | Direct | Permissive. |
| uvicorn | 0.48.0 | BSD-3-Clause | Direct | Permissive. |
| cryptography | 48.0.0 | Apache-2.0 OR BSD-3-Clause | Direct | Permissive (dual-licensed; project may pick either). |
| argon2-cffi | 25.1.0 | MIT | Direct | Permissive. Bundles the upstream `phc-winner-argon2` C reference implementation, which upstream dual-licenses CC0-1.0 OR Apache-2.0 — both permissive. |
| argon2-cffi-bindings | 25.1.0 | MIT | Transitive (of argon2-cffi) | Permissive. |
| kyber-py | 1.2.0 | MIT OR Apache-2.0 | Direct | Permissive, pure Python (no bundled native code). |
| evdev | 1.9.3 | BSD-3-Clause | Direct (headless Linux mouse capture path in `capture.py`) | Permissive. Listed as a commented-out optional in `requirements.txt` but is actually imported unconditionally by `capture.py`'s `_use_evdev()` path on headless Linux — see §5 for the fix needed here. |
| python-xlib | 0.33 | **LGPL-2.1-or-later** | Transitive (of pynput, X11 backend) | Weak copyleft — see §3. |
| scipy | 1.17.1 | BSD-3-Clause | Transitive (of nistrng) | Permissive. |
| six | 1.17.0 | MIT | Transitive (of pynput) | Permissive. |
| starlette | 1.1.0 | BSD-3-Clause | Transitive (of fastapi) | Permissive. |
| pydantic | 2.13.4 | MIT | Transitive (of fastapi) | Permissive. |
| pydantic-core | 2.46.4 | MIT | Transitive (of pydantic) | Permissive. |
| click | 8.4.1 | BSD-3-Clause | Transitive (of uvicorn) | Permissive. |
| h11 | 0.16.0 | MIT | Transitive (of uvicorn) | Permissive. |
| anyio | 4.12.1 | MIT | Transitive (of starlette) | Permissive. |
| idna | 3.11 | BSD-3-Clause | Transitive (of anyio) | Permissive. |
| cffi | 2.0.0 | MIT | Transitive (of cryptography/argon2-cffi) | Permissive. |
| annotated-types | 0.7.0 | MIT | Transitive (of pydantic) | Permissive. |
| typing-extensions | 4.15.0 | PSF-2.0 | Transitive | Permissive (Python Software Foundation license). |
| typing-inspection | 0.4.2 | MIT | Transitive (of pydantic) | Permissive. |
| annotated-doc | 0.0.4 | MIT | Transitive (of fastapi) | Permissive. |

**GPL/AGPL scan result: clean.** No GPL-2.0, GPL-3.0, or AGPL-licensed package is anywhere in the dependency tree. The only copyleft entries are the two LGPL packages below.

---

## 3. LGPL obligations (pynput, python-xlib) — what you must actually do

LGPL-3.0/2.1 is **not viral**: it does not require your own code (this repository) to be released under LGPL. It only imposes obligations tied to the LGPL-licensed library itself, and those obligations are already satisfied by how this project consumes it:

- ✅ **Dynamic, unmodified use** — `pynput` and `python-xlib` are installed via `pip` from PyPI and imported normally in [`capture.py`](../capture.py); the source is never copied into this repo or modified.
- ✅ **Replaceable** — because it's a normal Python import (not statically compiled/frozen into a binary), any user can swap the installed `pynput`/`python-xlib` version by editing their virtualenv — the LGPL "right to relink" requirement.
- ⚠️ **Attribution — was missing, now fixed** — LGPL requires you to state that the library is used and to make its license text/location available. The root [`LICENSE`](../LICENSE) file previously only contained the project's own MIT/Proprietary dual-license text with no mention of any third-party component. A **Part C** section has been added there pointing here, and the required notices are below.

### Required notices

```
PYNPUT
  License: GNU Lesser General Public License v3.0 (LGPL-3.0)
  Copyright © 2016 Moses Palmér <moses.palmer@gmail.com>
  Repository: https://github.com/moses-palmer/pynput
  Full license text: https://github.com/moses-palmer/pynput/blob/master/COPYING.LGPL

  This product includes pynput, unmodified, for cross-platform mouse/keyboard
  event capture (capture.py). Users may substitute a modified or alternate
  version of pynput in their own environment; no static linking is performed.

PYTHON-XLIB
  License: GNU Lesser General Public License v2.1-or-later (LGPL-2.1+)
  Repository: https://github.com/python-xlib/python-xlib
  Full license text: https://github.com/python-xlib/python-xlib/blob/master/COPYING

  Pulled in transitively by pynput as its X11 backend on Linux desktop
  sessions (not used on the headless evdev path). Same relinking guarantee
  as above applies.
```

If a fully permissive (non-copyleft) dependency tree is ever a hard requirement (e.g. for a specific enterprise customer's legal policy), the only practical mitigation is replacing `pynput` with a BSD/MIT-licensed alternative for the desktop capture path (the headless path already uses BSD-licensed `evdev`). That is a real code change, not just a documentation fix — flag to the maintainer if wanted.

---

## 4. AI agents / AI-assisted development — compliance note

Two distinct questions hide under "AI agents," and both were checked:

**A. Does the shipped application call out to any AI/LLM/ML service or embed any model?**
No. There is no `openai`, `anthropic`, `google-generativeai`, `langchain`, `transformers`, or similar package anywhere in `requirements.txt` or imported in any `.py` file. The system's "intelligence" (NIST statistical testing, entropy scoring, threat heuristics in `threat_model.py`/`advanced_security.py`) is deterministic statistics and rule-based logic, not a trained model — this matches the prior internal audit's own finding of "AI/ML Agents: NONE" in [`CODE_REVIEW_AUDIT.md`](../CODE_REVIEW_AUDIT.md).

**B. Was AI coding-assistant tooling (e.g. Claude Code) used to write parts of this repository, and does that impose any license/compliance obligation on the output?**
Portions of this repository (documentation and code changes) were produced with the assistance of an AI coding tool (Claude Code, by Anthropic). Under Anthropic's standard Commercial/Consumer Terms of Service, ownership of the output generated for a user's own prompts/inputs remains with the user/customer; Anthropic does not claim IP ownership over generated code and does not impose a license or attribution requirement on it. This is not a substitute for the user's own review of the terms current at time of use, but there is no compliance obligation this audit needs to flag for the *third-party license* purposes of this document — no license text, attribution, or redistribution requirement is triggered by using an AI coding assistant, unlike an actual third-party library dependency.

---

## 5. Findings and fixes applied in this pass

| # | Finding | Status |
|---|---|---|
| 1 | `tests/test_adversarial_scenarios.py::test_netlify_deploy_publishes_only_static_dashboard` failed — asserted the old `netlify.toml` build command (`dashboard.html` → `dist/index.html`) after the build command had been intentionally changed to publish `dashboard-complete.html` as the site's `index.html`. | **Fixed** — test assertion updated to match the current, intended deploy config. Full suite: 554 passed, 2 skipped. |
| 2 | Running `main.py --mode generate` on this machine raises `RuntimeError: evdev: no mouse device found in /dev/input`. | **Not a code bug** — this container has no physical mouse device attached; the project inherently requires real mouse/keyboard hardware input to generate entropy. Verified the actual key/random-number generation logic is correct by driving it with synthetic capture events and via the `/debug/pipeline` API route (both produce a valid 512-bit key + random number end-to-end, all 5 pipeline stages pass). |
| 3 | No `THIRD_PARTY_LICENSES.md` existed despite `licenses/` directory being present and `CODE_REVIEW_AUDIT.md` flagging this as a required file. | **Fixed** — this document. |
| 4 | Root `LICENSE` had no "Part C" third-party section, despite shipping an LGPL-licensed dependency (`pynput`). | **Fixed** — Part C added, pointing here. |
| 5 | `evdev` is commented out as merely "optional" in `requirements.txt`, but `capture.py`'s `_use_evdev()` path imports it unconditionally whenever running headless Linux (no `DISPLAY`/`WAYLAND_DISPLAY`) — i.e. it is a real, non-optional runtime dependency on servers/containers/CI, not an opt-in extra. | **Flagged, not changed** — recommend uncommenting `evdev>=1.7.0` in `requirements.txt` as an unconditional dependency (it's already installed and imports cleanly here) so headless installs don't silently fail on `ImportError` before ever reaching the clearer `RuntimeError` in finding #2. Left to the maintainer since it's a behavioral packaging change, not a license issue. |
| 6 | Import smoke test across all first-party modules (`api`, `vault`, `security`, `crypto_tools`, `behave_kdf`, `entropy_engine`, `key_generator`, `nist_validator`, `nist_800_90b_deep_validator`, `advanced_security`, `threat_model`, `self_healing`, `crypto_benchmark`, `dashboard_data_processor`) and a live smoke test of the FastAPI app (`/health`, `/info`, `/debug/pipeline`, `/encryption-info`, `/benchmark`, `/threat-model`, `/resource-status`, `/vault/info`, `/quantum/keygen`, `/vault/zkp/keygen`). | **All clean** — no interpreter errors, all HTTP 200. |

---

## 6. How this was verified

```bash
pip install -r requirements.txt        # confirm resolvable, no conflicts
python3 -m pytest tests/ -q            # 554 passed, 2 skipped (after fix #1)
pip install pip-licenses
python3 -m piplicenses --format=markdown --with-urls \
  --packages numpy nistrng pynput fastapi uvicorn cryptography \
  argon2-cffi argon2-cffi-bindings kyber-py evdev python-xlib scipy \
  starlette pydantic pydantic-core click h11 anyio idna cffi six \
  annotated-types typing-extensions typing-inspection annotated-doc
grep -rlin "openai|anthropic|langchain|generativeai|cohere|huggingface|transformers" --include="*.py" .
grep -rlin "cdn\.|unpkg|jsdelivr|<script src=\"http" *.html sdk/ browser_extension/
```

This document should be regenerated (re-run the commands above) whenever `requirements.txt` changes, since a version bump can change a package's declared license (this has happened in the ecosystem before, e.g. packages relicensing between major versions).
