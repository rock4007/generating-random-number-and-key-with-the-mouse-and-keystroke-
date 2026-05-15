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

## Testing

Validate the entropy pipeline with synthetic data:

```bash
python test_sandbox.py
```

This test harness checks mouse entropy extraction, keystroke entropy extraction, entropy pooling, key derivation, and deterministic output behavior without requiring GUI input.

## Outputs

- `results/latest_generation.json` — single-run output metadata
- `results/per_move_generation.json` — per-movement generation records
- `results/combined_experiment_report.txt` — NIST experiment summary
- `results/nist_report.txt` — raw NIST validation output

## Project Layout

- `main.py` — generation and experiment runner
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
- NIST tests assess randomness characteristics; they do not guarantee cryptographic certification.

## License

See `LICENSE` for licensing details.
