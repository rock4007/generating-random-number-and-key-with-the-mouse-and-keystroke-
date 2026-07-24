# 🚀 Quick Reference Guide

## Dashboard URLs

### Local Development
```
http://localhost:8000/dashboard-complete.html   ← Main Dashboard
http://localhost:8000/dashboard-nist.html       ← NIST Tests
http://localhost:8000/dashboard-entropy.html    ← Entropy Metrics  
http://localhost:8000/dashboard-mouse.html      ← Volunteer Tests
```

### Production (Netlify)
```
https://your-site.netlify.app/                  ← Main Dashboard
https://your-site.netlify.app/dashboard-nist.html
https://your-site.netlify.app/dashboard-entropy.html
https://your-site.netlify.app/dashboard-mouse.html
```

---

## Commands Quick Reference

### Start Local Server
```bash
python3 -m http.server 8000
# Then open http://localhost:8000
```

### Generate/Update Dashboards
```bash
# Full test run + dashboard generation
python3 test_runner.py

# Just dashboard data
python3 dashboard_data_processor.py

# View current data
cat dashboard_data.json | jq '.'
```

### Deploy to Netlify
```bash
# Automatic (on git push)
git add .
git commit -m "Update dashboards"
git push origin main

# Manual deployment
netlify deploy --prod
```

---

## Test Results

### Current Status
- ✅ NIST 800-90B: **64/64** tests passing
- ✅ Research Evidence: **3/3** claims verified
- ✅ Code Quality: **41/41** files syntax valid
- ✅ Security Fixes: **4/4** completed

### View Detailed Results
```bash
# Check test data
cat results/nist_800_90b_deep_report.json | jq '.["SUMIT KEY Behavioural Entropy"]'

# View research claims
cat results/research_evidence.json | jq '.experiments'

# Dashboard data summary
cat dashboard_data.json | jq '.summary'
```

---

## Security Fixes Applied

| Fix | File | Details |
|-----|------|---------|
| eval() → ast.literal_eval() | sdk/biometric_seal.py | L247 - Safe tuple parsing |
| Exception handling | capture.py | L58 - Specific exception types |
| CORS validation | api.py | L240 - Whitelist validation |
| Evdev error logging | capture.py | Mouse capture - Proper logging |

---

## File Locations

```
📊 Dashboards:
  dashboard-complete.html
  dashboard-nist.html
  dashboard-entropy.html
  dashboard-mouse.html
  dashboard.html

🔧 Scripts:
  dashboard_data_processor.py
  test_runner.py

📚 Documentation:
  DASHBOARD_GUIDE.md
  IMPLEMENTATION_COMPLETE.md
  README.md

📁 Test Results:
  results/nist_800_90b_deep_report.json
  results/research_evidence.json
  results/per_move_generation.json
  results/moat_report.json
  results/tier1_validation_report.json

⚙️ Configuration:
  netlify.toml
```

---

## Troubleshooting

### Dashboard shows no data
```bash
# Step 1: Run tests
python3 test_runner.py

# Step 2: Generate data
python3 dashboard_data_processor.py

# Step 3: Refresh browser (Ctrl+F5)
```

### Data not updating
```bash
# Hard refresh
rm dashboard_data.json
python3 dashboard_data_processor.py

# Then reload browser
```

### Netlify build fails
1. Check Python version: `python3 --version` (need 3.10+)
2. Check test results exist: `ls results/*.json`
3. View build log in Netlify dashboard

---

## Next Steps

1. **Test locally** → `python3 -m http.server 8000`
2. **Verify dashboards** → Open main dashboard in browser
3. **Generate live data** → `python3 test_runner.py`
4. **Deploy to Netlify** → `git push origin main`
5. **Monitor dashboards** → Check production URL

---

## Support

For detailed information, see:
- **Setup Guide:** `DASHBOARD_GUIDE.md`
- **Implementation Details:** `IMPLEMENTATION_COMPLETE.md`
- **Project Info:** `README.md`

---

**Last Updated:** 2026-07-23  
**Version:** 1.0
