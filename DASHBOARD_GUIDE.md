# 🎯 SUMIT KEY Dashboard Guide

## Overview

The SUMIT KEY project includes a comprehensive web-based dashboard system for visualizing test results, security findings, and system health across all components.

## Dashboard Components

### 1. **Main Dashboard** (`dashboard-complete.html`)
The central hub showing all test suites at a glance.

**Features:**
- 📊 Overall system status and health indicators
- 🔄 Quick links to all specialized dashboards
- 📈 Real-time test metrics summary
- 🛡️ Security findings and fixes status
- 📋 Comprehensive test suite overview

**Access:** `/` or `/index.html` on Netlify

### 2. **NIST 800-90B Dashboard** (`dashboard-nist.html`)
Detailed NIST 800-90B compliance testing results.

**Features:**
- 🧪 Health Tests (Continuous Online) — RCT, APT
- 📊 IID Tests (Statistical Validation) — Chi-squared, Excursion, Runs
- 📈 Per-entropy-source analysis
- 📋 Detailed test results table
- ✅ Pass/fail indicators with thresholds

**Covers:**
- OS CSPRNG Baseline
- Weak LCG PRNG (negative control)
- SUMIT KEY Behavioral Entropy
- SUMIT KEY HKDF Output

### 3. **Entropy Tests Dashboard** (`dashboard-entropy.html`)
Entropy quality metrics and behavioral KDF validation.

**Features:**
- 📈 Entropy metrics (min, max, mean bits/byte)
- 🔬 BEHAVE-KDF experiment results
- 🎯 Research claims verification
- 🚀 Platform compatibility tests
- 📊 Per-scenario entropy distribution

### 4. **Mouse & Volunteer Tests Dashboard** (`dashboard-mouse.html`)
Behavioral capture and volunteer validation tests.

**Features:**
- 🐭 Mouse movement capture quality tests
- 👥 Ghost handoff (one-time package) validation
- ⌨️ Keystroke dynamics biometric seal tests
- 📋 MOAT test results summary
- 🔐 Biometric profile enrollment validation

### 5. **Legacy Dashboard** (`dashboard.html`)
Original dashboard (maintained for compatibility).

---

## Data Flow

```
Test Results JSON Files
    ↓
dashboard_data_processor.py
    ↓
dashboard_data.json
    ↓
HTML Dashboards (fetch & render)
    ↓
Browser Visualization
```

### Data Sources

| Source | File | Updates |
|--------|------|---------|
| NIST Tests | `results/nist_800_90b_deep_report.json` | After NIST validation |
| Entropy Tests | `results/per_move_generation.json` | Per test run |
| Research Evidence | `results/research_evidence.json` | After research validation |
| MOAT Tests | `results/moat_report.json` | After MOAT run |
| Tier 1 Features | `results/tier1_validation_report.json` | After feature tests |

---

## Running Tests & Generating Dashboards

### Quick Start

```bash
# Generate dashboards from existing test results
python3 test_runner.py --dashboard

# Run all tests and generate dashboards
python3 test_runner.py

# Run with verbose output
python3 test_runner.py --verbose
```

### Manual Data Generation

```bash
# Just process test results into dashboard data
python3 dashboard_data_processor.py

# Output: dashboard_data.json
```

### Test Result Files

After running tests, JSON results are saved to `results/`:

```bash
cd results/

# View test results
ls -la *.json

# Check specific test results
cat nist_800_90b_deep_report.json | jq '.' | head -50
cat research_evidence.json | jq '.claim_matrix' 
```

---

## Local Development

### View Dashboards Locally

```bash
# Start a simple HTTP server
cd /path/to/project
python3 -m http.server 8000

# Open browser
open http://localhost:8000/dashboard-complete.html
```

Or use VS Code's Live Server extension:
1. Right-click on `dashboard-complete.html`
2. Select "Open with Live Server"

### Update Dashboard After Test Run

```bash
# Run tests
python3 -m pytest tests/ -v

# Generate dashboard data
python3 dashboard_data_processor.py

# View in browser (will auto-refresh if using Live Server)
```

---

## Netlify Deployment

### Build Configuration

The `netlify.toml` automatically:

1. **Runs** `dashboard_data_processor.py` during build
2. **Copies** all dashboard HTML files to `dist/`
3. **Includes** `dashboard_data.json` in output
4. **Sets** `dashboard-complete.html` as home page

### Environment Setup

```toml
[build]
  command = "python3 dashboard_data_processor.py && cp dashboard*.html dist/ && cp dashboard_data.json dist/ && cp 404.html dist/"
  publish = "dist"
```

### Deploy Manually

```bash
# Build locally
mkdir -p dist
python3 dashboard_data_processor.py
cp dashboard-complete.html dist/index.html
cp dashboard*.html dist/
cp dashboard_data.json dist/
cp 404.html dist/

# Deploy to Netlify
netlify deploy --prod --dir=dist
```

---

## Dashboard Metrics

### NIST 800-90B

| Metric | Threshold | Current |
|--------|-----------|---------|
| Health Tests Pass Rate | > 95% | 100% |
| IID Tests Pass Rate | > 90% | 100% |
| Entropy Sources | ≥ 3 | 4 |
| Overall Status | PASS | ✓ PASS |

### Entropy Quality

| Metric | Target | Current |
|--------|--------|---------|
| Min Entropy (bits/byte) | > 6.0 | 6.7+ |
| Mean Entropy (bits/byte) | > 7.0 | 7.88+ |
| Max Entropy (bits/byte) | = 8.0 | 8.0 |
| Sample Count | > 1000 | 10000+ |

### Volunteer Tests

| Test | Status | Details |
|------|--------|---------|
| Ghost Package Opens | ✓ PASS | 100% successful |
| Key Zeroization | ✓ PASS | All keys destroyed |
| Cross-Platform | ✓ PASS | 5+ device types |
| Mouse Capture | ✓ PASS | All axes working |

---

## Security Findings Status

| Finding | Issue | Status | Evidence |
|---------|-------|--------|----------|
| eval() Usage | Code injection risk | ✓ FIXED | [sdk/biometric_seal.py](../sdk/biometric_seal.py#L247) |
| Exception Handling | Overly broad catches | ✓ FIXED | [capture.py](../capture.py#L58) |
| CORS Validation | Missing input validation | ✓ FIXED | [api.py](../api.py#L240) |
| Evdev Errors | Silent failures | ✓ FIXED | Proper logging added |

---

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: Generate Dashboards

on: [push, pull_request]

jobs:
  dashboards:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Generate Dashboard Data
        run: python3 dashboard_data_processor.py
      
      - name: Deploy to Netlify
        env:
          NETLIFY_SITE_ID: ${{ secrets.NETLIFY_SITE_ID }}
          NETLIFY_AUTH_TOKEN: ${{ secrets.NETLIFY_AUTH_TOKEN }}
        run: |
          npm install -g netlify-cli
          netlify deploy --prod
```

---

## Customization

### Adding New Dashboards

1. Create new HTML file: `dashboard-feature.html`
2. Use existing dashboard as template
3. Add data loading function:
   ```javascript
   async function loadDashboard() {
     const response = await fetch('dashboard_data.json');
     const data = await response.json();
     // Process data and update UI
   }
   ```
4. Update `dashboard_data_processor.py` to include new data
5. Update navigation links in all dashboards

### Updating Data Processor

Edit `dashboard_data_processor.py` to:
- Add new test result files
- Parse additional metrics
- Generate computed statistics

---

## Troubleshooting

### Dashboard Shows No Data

**Problem:** Dashboards display "—" or "NOT_FOUND"

**Solutions:**
1. Run tests to generate result files:
   ```bash
   python3 test_runner.py
   ```
2. Generate dashboard data:
   ```bash
   python3 dashboard_data_processor.py
   ```
3. Refresh browser and check browser console for errors

### Data Not Updating

**Problem:** Dashboard shows stale data

**Solutions:**
1. Hard refresh browser (Ctrl+F5 / Cmd+Shift+R)
2. Clear browser cache
3. Regenerate dashboard_data.json:
   ```bash
   rm dashboard_data.json
   python3 dashboard_data_processor.py
   ```

### Netlify Build Fails

**Problem:** Build fails during dashboard generation

**Check:**
1. Python version (requires 3.10+):
   ```bash
   python3 --version
   ```
2. JSON files exist in `results/`:
   ```bash
   ls -la results/*.json
   ```
3. Check build log in Netlify dashboard

---

## Files Reference

### Dashboard Files

```
dashboard-complete.html    ← Main comprehensive dashboard
dashboard-nist.html        ← NIST 800-90B tests
dashboard-entropy.html     ← Entropy quality metrics
dashboard-mouse.html       ← Mouse & volunteer tests
dashboard.html             ← Legacy dashboard (compatibility)
dashboard_data.json        ← Generated data file
```

### Processing Files

```
dashboard_data_processor.py ← Converts JSON results to dashboard format
test_runner.py             ← Runs all tests and generates dashboards
netlify.toml               ← Build configuration for deployment
```

### Result Files

```
results/
  ├── nist_800_90b_deep_report.json      ← NIST test results
  ├── research_evidence.json              ← Research claims validation
  ├── per_move_generation.json            ← Entropy per-movement data
  ├── moat_report.json                    ← MOAT test results
  ├── tier1_validation_report.json        ← Tier 1 feature tests
  └── combined_experiment_report.txt      ← Text summary
```

---

## Support & Issues

For dashboard-related issues:
1. Check browser console (F12) for JavaScript errors
2. Review `dashboard_data_processor.py` output
3. Verify test result files exist in `results/`
4. Check Netlify build logs for deployment issues

---

**Last Updated:** 2026-07-23  
**Dashboard Version:** 1.0  
**SUMIT KEY Version:** 1.0-stable
