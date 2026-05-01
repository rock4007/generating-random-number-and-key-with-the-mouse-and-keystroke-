# SUMIT KEY

SUMIT KEY is an MSc Cybersecurity dissertation project that derives a 256-bit cryptographic key from behavioural entropy.

## What It Uses

- Mouse movement features: position, velocity, direction, and micro-tremor
- Keystroke timing features: dwell time, flight time, and bigram timing
- SHA3-256 for entropy pooling
- HKDF-SHA3-256 for key derivation
- NIST SP 800-22 tests via `nistrng`

## Windows Setup

1. Install Python 3.11 or newer.
2. Open the project folder in VS Code.
3. Create and activate a virtual environment:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

4. Install dependencies:

```powershell
pip install -r requirements.txt
```

## Run A Live Demo

```powershell
python demo.py
```

This performs one 10-second live capture and prints a generated 256-bit key.

## Generate Random Number + Crypto Key

```powershell
python main.py
```

This is now the default mode. It performs one live capture and outputs:

- A generated random number (64-bit)
- A generated cryptographic key (256-bit hex)

Saved output:

- `results/latest_generation.json`

## Run Full Experiments

```powershell
python main.py --mode experiments --num-keys 1000
```

This runs:

- Experiment A: Mouse entropy only
- Experiment B: Keystroke entropy only
- Experiment C: Mouse + keystroke entropy combined

Outputs are written to the `results` folder.

## Output Files

- `results/nist_report.txt`: latest per-run NIST table
- `results/combined_experiment_report.txt`: summary across experiments