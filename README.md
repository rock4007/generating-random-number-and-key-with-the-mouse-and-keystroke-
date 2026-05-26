# SUMIT KEY

SUMIT KEY is a behavioural entropy research project that derives cryptographic material from mouse motion and keystroke timing. It combines movement jitter, micro-vibration, and typing rhythm into a deterministic key generation pipeline with support for a quantum-hardened output profile.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Modes](#modes)
- [Testing](#testing)
- [Outputs](#outputs)
- [Project Layout](#project-layout)
- [Notes](#notes)
- [License](#license)

## Overview

SUMIT KEY captures user behaviour and derives:

- a 64-bit random number
- deterministic cryptographic key material
- per-mouse-move binary outputs for movement-driven randomness

The project is designed for experimentation and validation, not production deployment.

## Features

- mouse and keyboard behavioural entropy capture
- SHA3-based entropy extraction and pooling
- standard and quantum-hardened HKDF key derivation
- fresh key generation that mixes behavioural entropy with OS CSPRNG bytes
- basic SP 800-90B-inspired entropy health checks for broken input detection
- per-move generation with one binary output per movement
- batch experiment mode with NIST SP 800-22 validation

## Requirements

- Python 3.11 or newer
- `pip`
- desktop environment for `pynput` capture on Windows/macOS/Linux

Optional for Linux headless use:

- `evdev`
- membership in the `input` group

## Quick Start

1. Clone the repository:

```bash
git clone https://github.com/rock4007/generating-random-number-and-key-with-the-mouse-and-keystroke-.git
cd generating-random-number-and-key-with-the-mouse-and-keystroke-
```

2. Create and activate a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
```

3. Install dependencies:

```bash
pip install -r requirements.txt
```

## Modes

### Single generation

Run one behavioural capture and derive a key:

```bash
python main.py
```

### Per-mouse-move generation

Generate one key and one binary string for each captured mouse movement:

```bash
python main.py --mode per-move
```

This mode writes detailed records to `results/per_move_generation.json`.

### Static mouse-turn encryption chain

Generate a repeatable static key from a few mouse turns plus micro-vibration, then encrypt a message with AES-256-GCM:

```bash
python debug_pipeline.py --static-chain
```

For live capture:

```bash
python debug_pipeline.py --static-chain-live 5
```

### Game fallback authentication scenarios

Test chess/game-like mouse movement quality first, then fall back to phone/email OTP, then phone NFC:

```bash
python crypto_benchmark.py --quick
```

The benchmark includes four sandbox scenarios:

- good chess movement passes directly
- weak movement passes with OTP backup
- bad movement and bad OTP pass with NFC backup
- bad movement, bad OTP, and bad NFC deny access

### NIST experiment mode

Generate a batch of keys and run statistical validation:

```bash
python main.py --mode experiments --num-keys 1000
```

The batch output is summarized in `results/combined_experiment_report.txt`.

### Live demo

Run a short interactive capture demo:

```bash
python demo.py
```

### Digital dashboard

Open the local dashboard for live mouse-key generation, message encryption, one-minute file encryption scheduling, random numbers, and key-stream monitoring:

```bash
python -m http.server 8080
```

Then open `http://127.0.0.1:8080/dashboard.html`.

## Testing

Validate the entropy pipeline with synthetic data:

```bash
python test_sandbox.py
```

This test harness checks mouse entropy extraction, keystroke entropy extraction, entropy pooling, key derivation, and deterministic output behavior without requiring GUI input.

Run black-box security checks:

```bash
python test_blackbox_security.py
```

This validates fresh-key uniqueness, deterministic test injection, avalanche behavior, health-check rejection, quantum output length, and AES-GCM authentication when `cryptography` is installed.

## Outputs

- `results/latest_generation.json` — single-run output metadata
- `results/per_move_generation.json` — per-movement generation records
- `results/combined_experiment_report.txt` — NIST experiment summary
- `results/nist_report.txt` — raw NIST validation output

## Project Layout

- `main.py` — generation and experiment runner
- `dashboard.html` — browser dashboard for message/file encryption and live key stream
- `demo.py` — interactive behavioural capture demo
- `capture.py` — mouse and keyboard capture logic
- `entropy_engine.py` — entropy feature extraction and pooling
- `key_generator.py` — deterministic key derivation
- `nist_validator.py` — NIST SP 800-22 wrapper
- `security.py` — security profile helpers
- `test_sandbox.py` — synthetic pipeline validation tests

## Notes

- This repository is for research and proof-of-concept usage.
- Behavioural entropy is non-deterministic and depends on live input.
- Production-facing key generation mixes mouse/keystroke entropy with fresh operating-system CSPRNG bytes. Behavioural entropy is treated as additional input, not the sole root of trust.
- Static-chain mode is repeatable by design: the same captured movement features can reproduce the same key. Use it for demos, local encryption workflows, or research; use fresh mode when replay resistance matters.
- Phone/email OTP and NFC fallback code is sandbox simulation. Production OTP needs provider integration, replay prevention, rate limits, and short expiry. Production NFC should use phishing-resistant FIDO2/WebAuthn or smart-card semantics.
- NIST SP 800-22 tests assess statistical characteristics; they do not guarantee cryptographic certification.
- The health checks are inspired by NIST SP 800-90B concepts, but this project is not a formal NIST entropy-source validation or a FIPS 140 validated cryptographic module.

## License

See `LICENSE` for licensing details.
