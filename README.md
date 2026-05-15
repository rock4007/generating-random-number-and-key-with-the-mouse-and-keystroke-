# SUMIT KEY

SUMIT KEY is a dissertation-grade research project that derives cryptographic keys from behavioural entropy. It combines mouse movement and keystroke timing data to generate entropy, validates output using NIST SP 800-22, and produces deterministic key material for post-quantum-resistant usage.

## Table of Contents

- [Project Overview](#project-overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Security Profiles](#security-profiles)
- [Output Files](#output-files)
- [Project Structure](#project-structure)
- [Notes](#notes)
- [License](#license)

## Project Overview

This repository captures user behaviour through mouse movements and keyboard timing, then derives:

- a 64-bit pseudorandom number
- a cryptographic key derived from entropy pooled across behavioural sources

The project supports:

- single-shot generation
- per-mouse-movement output
- full batch experiments with NIST SP 800-22 validation

## Features

- behavioural entropy capture from mouse movement and keystrokes
- entropy extraction and pooling using SHA3-based processing
- deterministic key derivation with standard and quantum-hardened profiles
- configurable experiment mode for statistical validation
- recorded outputs in `results/`

## Requirements

- Python 3.11 or newer
- Windows, Linux or macOS desktop environment for `pynput` capture
- `pip` package manager

Optional for Linux headless usage:

- `evdev` and membership in the `input` group

## Installation

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

## Usage

### Generate a single random number and key

```bash
python main.py
```

This runs a live behavioural capture using the default 10-second duration and outputs:

- 64-bit random number
- cryptographic key hex string
- generation metadata saved to `results/latest_generation.json`

### Run per-mouse-move generation

```bash
python main.py --mode per-move
```

This mode generates one key per captured mouse movement and saves the results to `results/per_move_generation.json`.

### Run full NIST experiment suite

```bash
python main.py --mode experiments --num-keys 1000
```

This executes three experiment streams:

- Experiment A: mouse entropy only
- Experiment B: keystroke entropy only
- Experiment C: combined mouse + keystroke entropy

Each experiment outputs validated results and a combined report in `results/combined_experiment_report.txt`.

### Live demo

```bash
python demo.py
```

The demo performs a short live capture and displays generated outputs interactively.

### Testing

Run the test sandbox to validate the entropy and key generation pipeline:

```bash
python test_sandbox.py
```

This executes synthetic tests that validate:

- mouse entropy extraction from movement data
- keystroke entropy extraction from timing data
- entropy pooling and SHA3-256 hashing
- deterministic key derivation for both standard and quantum-hardened profiles
- pipeline determinism (same inputs produce same outputs)

All tests run without GUI dependencies and are suitable for headless environments.

## Security Profiles

The generator supports two security levels:

- `quantum`: default mode producing a post-quantum-hardened key profile
- `standard`: legacy profile for a standard 256-bit key output

Example:

```bash
python main.py --security-level standard
```

## Output Files

- `results/latest_generation.json` — single-run generation metadata and outputs
- `results/per_move_generation.json` — per-mouse-move generation records
- `results/combined_experiment_report.txt` — consolidated NIST experiment summary
- `results/nist_report.txt` — raw NIST SP 800-22 validation report

## Project Structure

- `main.py` — main runner for generation and experiments
- `demo.py` — interactive capture/demo script
- `capture.py` — behavioural capture implementation
- `entropy_engine.py` — entropy extraction from mouse and keyboard data
- `key_generator.py` — deterministic key derivation logic
- `nist_validator.py` — NIST SP 800-22 validation wrapper
- `security.py` — security profile helpers
- `test_sandbox.py` — unit tests for entropy and key generation pipeline

## Notes

- The repository is intended for research and proof-of-concept usage.
- Behavioural entropy sources are non-deterministic and require user activity during capture.
- NIST tests are statistical and are used to assess randomness characteristics, not to certify security.

## License

See `LICENSE` for licensing details.
