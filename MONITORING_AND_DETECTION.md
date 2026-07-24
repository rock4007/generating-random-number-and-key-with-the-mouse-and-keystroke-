# 🔍 SECURITY MONITORING & THREAT DETECTION
## Production-Grade Security Operations Center (SOC) Guide

**Date:** July 24, 2026  
**Project:** SUMIT KEY  
**Purpose:** Real-time detection and response to security threats

---

## 🎯 DETECTION STRATEGY

### Three-Layer Detection Model

```
┌─────────────────────────────────────────────────────────────┐
│  LAYER 1: Real-Time Detection (Milliseconds)                │
├─────────────────────────────────────────────────────────────┤
│  • Rate limiting violations (HTTP 429)                      │
│  • Invalid input validation (HTTP 400)                      │
│  • TLS handshake failures                                   │
│  • API endpoint errors (HTTP 5xx)                           │
│                                                             │
│  Implementation: security.py middleware                     │
│  Detection Time: < 100ms                                    │
│  Action: Block IP, log event                               │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  LAYER 2: Behavioral Detection (Seconds to Minutes)        │
├─────────────────────────────────────────────────────────────┤
│  • Entropy anomalies (< 3.0 bits/byte)                     │
│  • Device capture failures                                  │
│  • Nonce collision detection                                │
│  • Keystroke biometric anomalies                            │
│  • Timing pattern deviations                                │
│                                                             │
│  Implementation: vault.py threat_detector()                │
│  Detection Time: 1-10 seconds                              │
│  Action: Alert, throttle, investigate                      │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  LAYER 3: Statistical Detection (Hours to Days)            │
├─────────────────────────────────────────────────────────────┤
│  • Abnormal access patterns                                 │
│  • Cross-session entropy correlation                        │
│  • Device failure trends                                    │
│  • Repeated threat detections from same IP                 │
│  • Certificate expiry approaching                           │
│                                                             │
│  Implementation: Prometheus + Grafana alerting             │
│  Detection Time: 1-24 hours                                │
│  Action: Alert, trend analysis, preventive maintenance    │
└─────────────────────────────────────────────────────────────┘
```

---

## 📊 METRICS TO MONITOR

### 1. **API Performance Metrics**

```python
# Prometheus metrics definition
from prometheus_client import Counter, Histogram, Gauge

# Counters (cumulative)
http_requests_total = Counter(
    'http_requests_total',
    'Total HTTP requests',
    ['method', 'endpoint', 'status']
)
http_errors_total = Counter(
    'http_errors_total',
    'Total HTTP errors',
    ['status', 'endpoint']
)

# Histograms (latency distribution)
request_latency_seconds = Histogram(
    'request_latency_seconds',
    'Request latency in seconds',
    ['endpoint'],
    buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
)

# Gauges (current state)
active_connections = Gauge(
    'active_connections',
    'Active connections'
)

rate_limit_violations = Counter(
    'rate_limit_violations',
    'Rate limit violations',
    ['ip_address']
)
```

**Alert Rules:**
```yaml
# Prometheus alert rules
groups:
- name: api_alerts
  rules:
  
  - alert: HighErrorRate
    expr: rate(http_errors_total[5m]) > 0.05
    for: 5m
    annotations:
      severity: CRITICAL
      summary: "API error rate > 5% for 5 minutes"
      dashboard: "https://grafana.example.com/api-health"
  
  - alert: SlowRequests
    expr: histogram_quantile(0.95, request_latency_seconds) > 1
    for: 10m
    annotations:
      severity: HIGH
      summary: "95th percentile latency > 1s"
      runbook: "https://wiki.example.com/slow-requests"
  
  - alert: DeviceCaptureFailing
    expr: rate(http_errors_total{status="503"}[5m]) > 0.01
    annotations:
      severity: HIGH
      summary: "Device capture failures > 1%"
      action: "Check physical device, restart container"
```

### 2. **Entropy Quality Metrics**

```python
# vault.py: Entropy measurement
entropy_metrics = {
    "bits_per_byte": 7.89,           # Target: 7.0-8.0
    "min_bits_observed": 6.78,       # Trend indicator
    "max_bits_observed": 8.00,
    "events_captured": 245,          # Target: > 30
    "nonce_collision_prob": 1.2e-48, # Target: < 1e-40
}

# Alert thresholds
ENTROPY_CRITICAL = 3.0   # < 3.0 → CRITICAL
ENTROPY_HIGH = 5.0       # 3.0-5.0 → HIGH alert
ENTROPY_MEDIUM = 6.0     # 5.0-6.0 → MEDIUM alert
ENTROPY_OK = 7.0         # > 7.0 → OK

# Example monitoring query (Prometheus PromQL)
entropy_bits_per_byte < 3.0    # Alert CRITICAL
entropy_bits_per_byte < 5.0    # Alert HIGH
entropy_bits_per_byte < 6.0    # Alert MEDIUM
```

### 3. **Threat Detection Metrics**

```python
# vault.py: Threat scoring
threat_score_total = Counter(
    'threat_score_total',
    'Cumulative threat detection score',
    ['threat_type', 'severity']
)

threat_events = [
    {
        "type": "entropy_anomaly",
        "timestamp": "2026-07-24T10:30:45Z",
        "value": 2.15,
        "threshold": 3.0,
        "severity": "LOW",        # 2.15 < 3.0 slightly
        "action": "log_only"
    },
    {
        "type": "entropy_anomaly",
        "timestamp": "2026-07-24T10:31:15Z",
        "value": 1.50,
        "threshold": 3.0,
        "severity": "CRITICAL",   # 1.50 << 3.0 significantly
        "action": "alert_and_block"
    },
    {
        "type": "timing_burst",
        "timestamp": "2026-07-24T10:32:00Z",
        "deviation": 450,         # milliseconds
        "threshold": 500,
        "severity": "LOW",        # 450 < 500
        "action": "log_only"
    },
    {
        "type": "replay_attempt",
        "timestamp": "2026-07-24T10:33:00Z",
        "pattern_similarity": 0.85,  # 0-1 scale
        "threshold": 0.95,
        "severity": "LOW",        # 0.85 < 0.95
        "action": "log_and_monitor"
    }
]
```

**Alert Rules for Threat Detection:**
```yaml
- alert: CriticalEntropyAnomaly
  expr: entropy_bits_per_byte < 3.0
  annotations:
    severity: CRITICAL
    action: "Invalidate key, warn user, investigate device"
    
- alert: MultipleEntropyAnomalies
  expr: count(increase(threat_score_total{threat_type="entropy_anomaly"}[1h])) > 5
  annotations:
    severity: HIGH
    action: "Pattern of weak entropy, check for systematic issue"
    
- alert: ReplayPattern
  expr: count(increase(threat_score_total{threat_type="replay_attempt"}[1h])) > 3
  annotations:
    severity: MEDIUM
    action: "Possible replay attack, review logs"
```

### 4. **Rate Limiting Metrics**

```python
# security.py: Rate limit tracking
rate_limit_metrics = {
    "requests_per_ip_per_minute": {
        "192.168.1.100": 12,      # > 10 limit
        "192.168.1.101": 8,       # OK
        "192.168.1.102": 3,       # OK
    },
    "blocked_ips": {
        "192.168.1.100": {
            "violations": 7,
            "blocked_until": "2026-07-24T10:45:00Z",  # 15 min block
            "reason": "Rate limit exceeded"
        }
    },
    "repeated_violators": {
        "203.0.113.50": {
            "violations_today": 15,
            "first_violation": "2026-07-24T08:00:00Z",
            "severity": "CRITICAL"
        }
    }
}

# Alert rule
- alert: SuspiciousRateLimitPattern
  expr: |
    count(
      rate_limit_violations > 5 
      AND 
      increase(rate_limit_violations[1h]) > 0.1
    ) > 0
  annotations:
    severity: HIGH
    action: "Possible brute-force or DoS attack from {{ $labels.ip }}"
    firewall_action: "Consider adding IP to firewall blocklist"
```

### 5. **Cryptographic Metrics**

```python
# crypto_tools.py: Encryption metrics
crypto_metrics = {
    "aes_encryptions_total": 10234,
    "aes_decryptions_total": 9876,
    "nonce_generation_total": 10234,
    "nonce_collisions": 0,                # Target: always 0
    "authentication_failures": 0,         # Target: always 0
    "messages_per_key": 5000,             # Alert if > 2^32
}

# Alert rules
- alert: KeyRotationNeeded
  expr: messages_per_key > 4294967295  # 2^32
  annotations:
    severity: CRITICAL
    action: "Rotate all keys immediately (nonce collision risk)"
    
- alert: AuthenticationFailure
  expr: authentication_failures > 0
  annotations:
    severity: CRITICAL
    action: "Possible ciphertext tampering or corruption"
```

### 6. **Biometric Metrics**

```python
# biometric_seal.py: Keystroke biometric monitoring
biometric_metrics = {
    "enrollments_total": 42,
    "verification_attempts": 1234,
    "verification_success_rate": 0.98,   # Target: > 0.95
    "anomalies_detected": 12,            # Z-score > 3
    "anomaly_false_positive_rate": 0.02, # Target: < 0.05
}

# Alert rules
- alert: BiometricAnomalyStrike
  expr: |
    increase(anomalies_detected[1h]) > 10
  annotations:
    severity: MEDIUM
    action: "High biometric anomaly rate, possible impersonation attempt"
    investigate: "Review keystroke logs for patterns"
```

---

## 🚨 ALERT SEVERITY LEVELS

### CRITICAL (Immediate Action Required)
```
Examples:
  • Entropy < 3.0 bits/byte (key is weak)
  • Nonce collision detected (key compromised)
  • Authentication failure (ciphertext tampered)
  • API completely down (HTTP 5xx > 50%)
  • Certificate expiry < 7 days
  • TLS handshake failures > 10/minute

Response Time: < 5 minutes
Escalation: Page on-call engineer
Action: Immediate investigation and remediation
```

### HIGH (Urgent Investigation)
```
Examples:
  • Entropy 3.0-5.0 bits/byte (degraded, use Argon2id)
  • Rate limit violations > 100/hour (possible attack)
  • Device capture failures > 5% (hardware issue)
  • Error rate > 5% (service degradation)
  • Repeated threat detections (pattern detected)

Response Time: < 15 minutes
Escalation: Alert team lead
Action: Investigate root cause, implement workaround
```

### MEDIUM (Important Investigation)
```
Examples:
  • Entropy 5.0-6.0 bits/byte (marginal quality)
  • Repeated anomalies (3+ in 1 hour)
  • Device capture failures 1-5% (intermittent issue)
  • Error rate 1-5% (normal operational limits)
  • Slow response times (95th percentile > 500ms)

Response Time: < 1 hour
Escalation: Alert team via Slack/email
Action: Schedule investigation, log ticket
```

### LOW (Informational)
```
Examples:
  • Entropy trend downward (monitor only)
  • API request latency slightly elevated
  • Single anomaly detected (could be user variation)
  • Rate limit warnings (approaching threshold)

Response Time: Next business day
Escalation: Email team for awareness
Action: Monitor trend, add to weekly report
```

---

## 🔐 DETECTION PLAYBOOKS

### Playbook 1: Weak Entropy Detected

**Alert Triggered:** `entropy_bits_per_byte < 3.0`

**Immediate Actions (0-5 min):**
```
1. Log event:
   - Timestamp
   - Entropy value
   - User ID (if available)
   - Device type
   
2. Notify user:
   - HTTP 400 response: "Entropy too weak, please re-capture"
   - Suggest: More mouse movement, longer capture duration
   - Alternative: Use Argon2id hardening (POST /generate?hardening=true)
   
3. Invalidate key:
   - Mark key as compromised (do not use)
   - Recommend re-generation
   - Do NOT return key to user
```

**Investigation (5-30 min):**
```
1. Check event patterns:
   - How many mouse events? (target: >= 30)
   - How many keystroke events? (target: >= 20)
   - Event distribution (any clustering?)
   
2. Check device:
   - Is mouse/keyboard responding?
   - Latency of captures (should be real-time)
   - Repeated failures on same device?
   
3. Check user:
   - First-time user? (may need training)
   - Repeated weak captures? (possible device issue)
   - Accessibility needs? (tremor, disability requiring adaptation)
```

**Response (30+ min):**
```
1. If device issue:
   - Recommend user test on different device
   - Document device model and OS
   - Add to compatibility matrix
   
2. If user issue:
   - Send guide: "How to Capture Strong Entropy"
   - Offer support/training
   - Recommend multiple sessions (average entropy)
   
3. If systematic issue:
   - Check for OS updates affecting capture
   - Check for pynput library issues
   - Consider fallback capture method
```

---

### Playbook 2: Rate Limit Violations (Possible Attack)

**Alert Triggered:** `rate_limit_violations > 5 per minute from same IP`

**Immediate Actions (0-5 min):**
```
1. Block IP address:
   - 15-minute automatic block (security.py RateLimitMiddleware)
   - Log IP address and timestamp
   
2. Escalate alert:
   - Severity: HIGH
   - Send alert to SOC dashboard
   - Page on-call engineer if > 10 violations
   
3. Check attack pattern:
   - Single IP or distributed (botnet)?
   - Pattern: Rapid /generate requests?
   - User-Agent: Same or varied?
```

**Investigation (5-30 min):**
```
1. Check logs:
   tail -f /var/log/sumitkey/security.log | grep 429
   
2. Get attacker profile:
   - IP geolocation
   - ASN/ISP
   - Known attack group?
   - Residential or datacenter IP?
   
3. Assess intent:
   - Brute-force attack? (trying to guess entropy patterns)
   - API enumeration? (scanning endpoints)
   - DoS attack? (just overwhelming API)
   - Legitimate? (misconfigured client, bug)
```

**Response (30+ min):**
```
1. If brute-force:
   - IP is already blocked (15 min automatic)
   - Add to permanent firewall blacklist if repeated
   - No keys were exposed (rate limit stopped attempt)
   
2. If DoS:
   - Activate DDoS protection (if available)
   - Scale up API instances (Kubernetes HPA)
   - Notify hosting provider
   
3. If legitimate (misconfigured client):
   - Contact user/organization
   - Help fix configuration
   - Increase their rate limit if needed
   - Monitor for future patterns
```

---

### Playbook 3: Device Capture Failures

**Alert Triggered:** `HTTP 503 (Device Not Found) > 1% of requests`

**Immediate Actions (0-5 min):**
```
1. Check API status:
   curl https://api.example.com/health
   → Should show device availability status
   
2. Verify device is connected:
   On production server:
   python3 -c "import capture; print(capture.check_device_available())"
   
3. Alert users:
   - Return HTTP 503: "Device capture temporarily unavailable"
   - Suggest: Retry in 5 minutes
   - Alternative: Use existing key or generate on different device
```

**Investigation (5-30 min):**
```
1. Check device logs:
   cat /var/log/sumitkey/capture.log | tail -100
   → Look for pynput errors, device disconnections
   
2. Check system logs:
   dmesg | tail -50
   → Look for USB device errors, kernel messages
   
3. Test device manually:
   python3 -c "
   from pynput import mouse, keyboard
   try:
       listener = mouse.Listener()
       listener.start()
       print('Mouse detected')
       listener.stop()
   except Exception as e:
       print(f'Error: {e}')
   "
```

**Response (30+ min):**
```
1. If device is detected:
   - Issue may be transient
   - Restart API service
   - Monitor for recurrence
   
2. If device is not detected:
   - Check USB connections (if using USB mouse)
   - Restart container/VM
   - Check device permissions (Linux: /dev/input access)
   - Replace device if broken
   
3. If in Docker/Kubernetes:
   - Check volume mounts (if using /dev/input)
   - Verify device is available in container
   - Update Dockerfile if needed
```

---

### Playbook 4: Keystroke Biometric Anomaly

**Alert Triggered:** `anomaly_score > 3.0 (3-sigma deviation)`

**Immediate Actions (0-5 min):**
```
1. Log anomaly:
   - User ID
   - Anomaly score (Z-score)
   - Keystroke features (timing, flight times)
   - Comparison to enrolled profile
   
2. Take action (per security policy):
   - Option A: Reject authentication (conservative)
   - Option B: Challenge user with additional verification
   - Option C: Log and monitor (permissive)
   
3. Notify:
   - Security team (for monitoring)
   - User (if rejected): "Signature mismatch, please re-enroll"
```

**Investigation (5-30 min):**
```
1. Is this legitimate user variation?
   - Check if 3-sigma threshold appropriate
   - Welford's algorithm updating profile
   - Check user's historical anomaly rate
   
2. Possible explanations:
   - User is injured (arm in cast, tremor today)
   - User is tired (slower reactions)
   - User on different device (keyboard tactile feedback)
   - Different typing position (desk height, angle)
   - Attacker mimicking user
   
3. Check context:
   - Time of day (fatigue?)
   - Device type (laptop vs. external keyboard?)
   - Location (VPN, traveling?)
   - Recent pattern changes
```

**Response (30+ min):**
```
1. If legitimate user:
   - Update enrolled profile with new biometric data
   - Reduce sensitivity of 3-sigma threshold if needed
   - Monitor for stabilization
   - Consider Argon2id hardening as backup
   
2. If suspected impersonation:
   - Force re-authentication with knowledge factor
   - Security questions: "What was your first pet's name?"
   - One-time password via email/SMS
   - Require in-person re-enrollment
   
3. Ongoing monitoring:
   - Track anomaly frequency per user
   - Alert if repeated anomalies (possible attack)
   - Alert if profile drift (user changing style)
```

---

## 📊 DASHBOARD DESIGN

### Main Security Dashboard (Real-Time View)

```
┌─────────────────────────────────────────────────────────────┐
│  SUMIT KEY SECURITY OPERATIONS CENTER                       │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Status: ✅ OPERATIONAL (All Systems Green)                │
│  Last Check: 2026-07-24 10:35:00 UTC (2 seconds ago)      │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ CRITICAL ALERTS                                      │  │
│  ├──────────────────────────────────────────────────────┤  │
│  │ ✅ None currently active                             │  │
│  │                                                      │  │
│  │ Most Recent:                                         │  │
│  │   • 2026-07-24 08:15 - Entropy anomaly (resolved)   │  │
│  │   • 2026-07-23 22:30 - Rate limit violation (IP     │  │
│  │     blocked for 15 min)                              │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ API HEALTH                          │ HIGH ALERTS    │  │
│  ├──────────────────────────────────────┼────────────────┤  │
│  │ Status:        ✅ UP                 │ None           │  │
│  │ Requests/min:  1,234 (avg 1,100)    │                │  │
│  │ Error Rate:    0.03% (< 1%)          │                │  │
│  │ Latency (p95): 128ms (< 500ms)       │                │  │
│  │ Uptime:        99.98% (30 days)      │                │  │
│  └──────────────────────────────────────┴────────────────┘  │
│                                                             │
│  ┌──────────────────────────────────────┬────────────────┐  │
│  │ ENTROPY QUALITY                      │ RATE LIMITING  │  │
│  ├──────────────────────────────────────┼────────────────┤  │
│  │ Mean: 7.89 bits/byte ✅              │ Violations/hr: │  │
│  │ Min:  6.78 bits/byte ✅              │ 3 (low)        │  │
│  │ Max:  8.00 bits/byte ✅              │                │  │
│  │ Quality: EXCELLENT                   │ Top IPs:       │  │
│  │ NIST: 64/64 PASS ✅                  │ 192.168.1.100  │  │
│  └──────────────────────────────────────┴────────────────┘  │
│                                                             │
│  ┌──────────────────────────────────────┬────────────────┐  │
│  │ THREAT DETECTION (Last 24h)          │ CRYPTO METRICS │  │
│  ├──────────────────────────────────────┼────────────────┤  │
│  │ Anomalies: 2 (low)                   │ Keys generated:│  │
│  │ ├─ Entropy anomaly: 1                │ 1,234          │  │
│  │ ├─ Replay detection: 0               │ Messages:      │  │
│  │ ├─ Device failure: 1                 │ 5,678          │  │
│  │ └─ Replay attempt: 0                 │ Nonce collision│  │
│  │ Severity: LOW                        │ risk: None ✅  │  │
│  │ Confidence: 98%                      │ Key rotation:  │  │
│  │                                      │ 0.002% of 2^32 │  │
│  └──────────────────────────────────────┴────────────────┘  │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │ INFRASTRUCTURE                                      │  │
│  ├──────────────────────────────────────────────────────┤  │
│  │ CPU:           22% (3 instances)                     │  │
│  │ Memory:        45% of 1.5GB                          │  │
│  │ Disk:          38% of 50GB                           │  │
│  │ TLS:           Valid until 2026-09-22 (60 days) ✅   │  │
│  │ Database:      N/A (stateless)                       │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔄 INCIDENT ESCALATION PROCEDURES

### Escalation Path

```
Level 1: Automated Monitoring (Prometheus/Grafana)
  ↓
  Alert triggered (severity: CRITICAL/HIGH/MEDIUM/LOW)
  → Logs to console + Slack webhook
  
Level 2: On-Call Engineer (Paged if CRITICAL)
  ↓
  30-second acknowledgment required (auto-page again after 5 min)
  → Investigate using runbooks
  → Determine if false positive or real incident
  
Level 3: Incident Commander (If escalation needed)
  ↓
  Multiple instances of same alert
  → Page incident commander
  → Coordinate cross-team response
  → Update status page
  
Level 4: Management (If critical service impact)
  ↓
  >15 minutes of service degradation
  → Notify engineering manager
  → Customer communication (if external service)
  → Post-mortem scheduling
```

---

## 📋 INCIDENT RESPONSE CHECKLIST

### For Each Incident

```
□ Identify & Triage
  □ What is the problem? (service down, data leak, performance, etc.)
  □ What is the impact? (who is affected, how many users)
  □ What is the severity? (CRITICAL/HIGH/MEDIUM/LOW)
  □ Is the service degraded or unavailable?

□ Notify Stakeholders
  □ Page on-call engineer
  □ Notify management (if CRITICAL)
  □ Update status page (if customer-facing)
  □ Prepare customer communication

□ Investigate & Diagnose
  □ Check recent code deployments
  □ Check infrastructure metrics (CPU, memory, disk)
  □ Check application logs for errors
  □ Check security logs for intrusions
  □ Identify root cause

□ Implement Fix
  □ Develop fix (code, configuration, etc.)
  □ Test in staging
  □ Deploy to production (with rollback plan)
  □ Verify fix resolves issue

□ Restore & Recover
  □ Bring system back to normal operations
  □ Clear any manual blocks/throttles
  □ Verify all metrics return to normal
  □ Confirm customers/users report system working

□ Communicate
  □ Update incident status page
  □ Send all-clear message to stakeholders
  □ Provide estimated time to post-mortem (24-48 hours)

□ Post-Mortem
  □ Document root cause analysis
  □ Identify preventive measures
  □ Create tickets for improvements
  □ Share lessons learned with team
  □ Schedule follow-up in 2 weeks
```

---

## 🎓 TEAM TRAINING

### Required Skills for Operations Team

1. **Prometheus/Grafana**
   - Reading time-series metrics
   - Writing PromQL queries
   - Setting up alerts
   - Creating dashboards

2. **Kubernetes (if deployed on K8s)**
   - Viewing logs: `kubectl logs deployment/sumitkey`
   - Scaling: `kubectl scale deployment sumitkey --replicas=5`
   - Rolling restart: `kubectl rollout restart deployment/sumitkey`
   - Debugging: `kubectl describe pod <pod-name>`

3. **SUMIT KEY Specifics**
   - Understanding entropy quality metrics
   - Threat detection thresholds
   - Rate limiting behavior
   - Cryptographic validation

4. **Incident Response**
   - Recognizing alert severity levels
   - Following playbooks
   - Communication during incidents
   - Post-mortem participation

---

**Status:** ✅ Production-Ready  
**Last Updated:** July 24, 2026  
**Alert Coverage:** Comprehensive
