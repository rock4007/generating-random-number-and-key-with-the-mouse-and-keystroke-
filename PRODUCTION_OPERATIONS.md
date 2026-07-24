# 🚀 PRODUCTION OPERATIONS GUIDE
## Deployment, Monitoring, and Maintenance

**Date:** July 24, 2026  
**Project:** SUMIT KEY  
**Audience:** DevOps, SRE, Security Operations

---

## 📋 PRE-DEPLOYMENT CHECKLIST

### Security Hardening
- [ ] **TLS Certificate**
  - Obtain valid SSL/TLS certificate for domain
  - Test with `curl -I https://your-domain.com`
  - Verify certificate chain (root, intermediate, leaf)
  - Set certificate expiration alert (90+ days before expiry)

- [ ] **Environment Configuration**
  ```bash
  # .env (secure, not in git)
  export API_HOST=0.0.0.0
  export API_PORT=443  # HTTPS port
  export TLS_CERT_PATH=/etc/ssl/certs/your-cert.pem
  export TLS_KEY_PATH=/etc/ssl/private/your-key.pem
  export ORIGIN_WHITELIST="https://yourdomain.com,https://app.yourdomain.com"
  export LOG_LEVEL=INFO  # Not DEBUG in production
  ```

- [ ] **CORS Configuration**
  - Verify ORIGIN_WHITELIST is set to HTTPS only
  - Test: `curl -H "Origin: http://evil.com" https://your-api/generate` → 403 FORBIDDEN

- [ ] **Rate Limiting Tuning**
  - Default: 10 requests/minute per IP
  - Adjust if needed: `RATE_LIMIT_REQUESTS=10 RATE_LIMIT_PERIOD=60`
  - Test: Send 11 requests in 60 seconds → 11th should get 429 Too Many Requests

- [ ] **Logging Configuration**
  ```python
  # In api.py before deployment
  logging.basicConfig(
      level=logging.INFO,  # Production: INFO only (not DEBUG)
      format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
      handlers=[
          logging.FileHandler('/var/log/sumitkey/api.log'),
          logging.StreamHandler(),  # Also stdout for container logs
      ]
  )
  ```

### Code Validation
- [ ] **Python Syntax Check**
  ```bash
  python3 -m py_compile *.py sdk/*.py tests/*.py
  # Should complete without errors
  ```

- [ ] **NIST Validation (64/64 tests must pass)**
  ```bash
  python3 nist_validator.py --deep
  # Should report: 64/64 TESTS PASSED (100%)
  ```

- [ ] **Import Chain Check**
  ```bash
  python3 -c "import api"  # Should complete without errors
  # If circular import exists, this will fail
  ```

- [ ] **Type Hint Validation**
  ```bash
  # Optional: use mypy for static type checking
  pip3 install mypy
  mypy *.py --ignore-missing-imports
  ```

### Dependency Verification
- [ ] **All dependencies in requirements.txt**
  ```bash
  pip3 install -r requirements.txt
  pip3 freeze > deployed_requirements.txt  # Document exact versions
  ```

- [ ] **License compliance**
  - [ ] Verify LICENSE file includes pynput LGPL-3.0 text
  - [ ] Verify THIRD_PARTY_LICENSES.txt exists
  - [ ] Check: `grep -r "GNU LESSER GENERAL PUBLIC LICENSE" LICENSE`

### Performance Baseline
- [ ] **Benchmark encryption speed**
  ```bash
  time python3 -c "
  import crypto_tools
  key = b'x' * 32
  plaintext = b'Hello World' * 100
  for _ in range(100):
      crypto_tools.encrypt_message(key, plaintext)
  print('100 encryptions complete')
  "
  # Should complete in < 1 second (AES-NI hardware accelerated)
  ```

- [ ] **Benchmark HKDF derivation**
  ```bash
  time python3 -c "
  import key_generator
  entropy = b'x' * 32
  for _ in range(1000):
      key_generator.derive_key(entropy)
  print('1000 HKDF derivations complete')
  "
  # Should complete in < 5 seconds
  ```

---

## 🚀 DEPLOYMENT

### Option 1: Docker Deployment (Recommended)

**Dockerfile (provided)**
```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f https://localhost/health || exit 1

EXPOSE 443
CMD ["python3", "-m", "uvicorn", "api:app", "--host", "0.0.0.0", "--port", "443", "--ssl-certfile", "/etc/ssl/certs/cert.pem", "--ssl-keyfile", "/etc/ssl/private/key.pem"]
```

**Build & Deploy:**
```bash
# Build
docker build -t sumitkey:latest .

# Run with TLS
docker run -d \
  --name sumitkey \
  -p 443:443 \
  -v /etc/ssl/certs/cert.pem:/etc/ssl/certs/cert.pem:ro \
  -v /etc/ssl/private/key.pem:/etc/ssl/private/key.pem:ro \
  -v /var/log/sumitkey:/app/logs \
  -e ORIGIN_WHITELIST="https://yourdomain.com" \
  sumitkey:latest

# Verify
docker logs sumitkey
curl -k https://localhost/health
```

### Option 2: Kubernetes Deployment

**k8s/deployment.yaml (provided)**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sumitkey
spec:
  replicas: 3  # High availability
  selector:
    matchLabels:
      app: sumitkey
  template:
    metadata:
      labels:
        app: sumitkey
    spec:
      containers:
      - name: api
        image: sumitkey:latest
        ports:
        - containerPort: 443
        env:
        - name: ORIGIN_WHITELIST
          value: "https://yourdomain.com"
        livenessProbe:
          httpGet:
            path: /health
            port: 443
            scheme: HTTPS
          initialDelaySeconds: 10
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /health
            port: 443
          initialDelaySeconds: 5
          periodSeconds: 10
        volumeMounts:
        - name: tls-certs
          mountPath: /etc/ssl/certs
          readOnly: true
      volumes:
      - name: tls-certs
        secret:
          secretName: sumitkey-tls
```

**Deploy:**
```bash
# Create TLS secret
kubectl create secret tls sumitkey-tls \
  --cert=cert.pem \
  --key=key.pem

# Deploy
kubectl apply -f k8s/deployment.yaml

# Verify
kubectl logs deployment/sumitkey
kubectl port-forward service/sumitkey 443:443
curl -k https://localhost/health
```

### Option 3: Netlify Deployment

**netlify.toml (provided)**
```toml
[build]
command = "python3 dashboard_data_processor.py && npm run build"
functions = "netlify/functions"

[functions]
directory = "netlify/functions"

[[redirects]]
from = "/api/*"
to = "/.netlify/functions/api/:splat"
status = 200

[[headers]]
for = "/*"
[headers.values]
Strict-Transport-Security = "max-age=31536000; includeSubDomains"
X-Content-Type-Options = "nosniff"
X-Frame-Options = "DENY"
```

**Deploy:**
```bash
npm install -g netlify-cli
netlify login
netlify deploy --prod
```

---

## 📊 MONITORING & ALERTING

### Key Metrics to Monitor

#### 1. **API Endpoint Health**
```python
# Prometheus metrics (example)
GET /metrics
│
├─ http_requests_total{endpoint="/generate", status="200"} 1234
├─ http_requests_total{endpoint="/generate", status="429"} 45  # Rate limited
├─ http_requests_total{endpoint="/generate", status="503"} 2   # Device failed
│
├─ request_latency_seconds{endpoint="/generate"} 0.125  # avg
├─ request_latency_seconds{endpoint="/generate"} [0.010, 2.500]  # min, max
│
└─ tls_certificate_expiry_seconds 2592000  # 30 days
```

**Alert Rules:**
```
- alert: HighErrorRate
  expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.05
  annotations:
    summary: "{{ $labels.endpoint }} error rate > 5%"

- alert: RateLimitViolations
  expr: rate(http_requests_total{status="429"}[5m]) > 0.1
  annotations:
    summary: "High rate limit violations (possible attack)"

- alert: DeviceNotFound
  expr: rate(http_requests_total{status="503"}[5m]) > 0.01
  annotations:
    summary: "Device capture failures ({{ $value }}%)"

- alert: CertificateExpiringSoon
  expr: tls_certificate_expiry_seconds < 7776000  # 90 days
  annotations:
    summary: "TLS certificate expires in 90 days"
```

#### 2. **Entropy Quality Metrics**
```python
# In vault.py:threat_detector()
metrics = {
    "entropy_bits_per_byte": 7.89,  # Target: > 7.0
    "event_count": 245,             # Target: > 30
    "feature_variance": 12.5,       # Health indicator
    "nonce_collision_prob": 1e-48,  # Always << 1
}

# Alert if entropy_bits_per_byte < 3.0 (CRITICAL)
# Alert if event_count < 10 (HIGH)
```

#### 3. **Threat Detection Alerts**
```python
# Log all threat detections
threat_events = [
    {"type": "entropy_anomaly", "score": 2.15, "threshold": 3.0, "status": "OK"},
    {"type": "timing_burst", "deviation": 450ms, "threshold": 500ms, "status": "OK"},
    {"type": "replay_attempt", "pattern_similarity": 0.45, "threshold": 0.95, "status": "OK"},
]

# Alert if any threat_score > 1.0 (escalate based on score)
```

#### 4. **Key Rotation Monitoring**
```
# Alert: Key reuse after 2^32 messages
# Monitor: Total messages encrypted with current key
# Rotate: When total messages >= 2^32
```

### Logging Strategy

**Structured Logging (JSON format for aggregation):**
```python
import json
import logging

class JSONFormatter(logging.Formatter):
    def format(self, record):
        log_obj = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "module": record.module,
            "message": record.getMessage(),
            "function": record.funcName,
            "line": record.lineno,
        }
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_obj)

# Usage
handler = logging.StreamHandler()
handler.setFormatter(JSONFormatter())
logger.addHandler(handler)
```

**Log Locations:**
- `/var/log/sumitkey/api.log` — API requests/responses
- `/var/log/sumitkey/security.log` — Rate limiting, anomalies
- `/var/log/sumitkey/crypto.log` — Encryption operations (fingerprints only)
- `/var/log/sumitkey/errors.log` — Errors and exceptions

**Log Retention:**
```bash
# Rotate logs daily
/var/log/sumitkey/*.log {
    daily
    rotate 90       # Keep 90 days of logs
    compress        # gzip compress
    delaycompress   # Delay compression by 1 day
    missingok       # Don't error if missing
}
```

---

## 🔒 SECURITY HARDENING IN PRODUCTION

### 1. TLS Configuration
```python
# api.py deployment config
# Minimum TLS 1.2 (TLS 1.3 preferred)
# Strongest ciphers only

import ssl
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.load_cert_chain("cert.pem", "key.pem")
ssl_context.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!eNULL")
ssl_context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # Disable weak protocols
```

### 2. Rate Limiting Enforcement
```python
# security.py: Dynamic IP blocking
RATE_LIMIT_REQUESTS = 10      # per IP
RATE_LIMIT_PERIOD = 60        # seconds
VIOLATION_THRESHOLD = 5       # violations before block
BLOCK_DURATION = 900          # 15 minutes

# After 5 violations in 1 minute → block IP for 15 minutes
# This prevents:
#   • Brute-force key discovery
#   • API endpoint enumeration
#   • DoS attacks
```

### 3. Security Headers
```python
# security.py: All mandatory headers
response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
response.headers["X-Content-Type-Options"] = "nosniff"
response.headers["X-Frame-Options"] = "DENY"
response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'none'"
response.headers["X-XSS-Protection"] = "1; mode=block"

# Test headers:
curl -I https://your-api.com/health
# Should show all security headers
```

### 4. Input Validation
```python
# api.py: All inputs validated
class GenerateAndEncryptBody(BaseModel):
    duration_seconds: float = Query(10.0, ge=1, le=60)  # 1-60 seconds only
    include_key: bool = False
    security_level: Literal["quantum", "standard"] = "standard"

# Pydantic automatically validates and rejects invalid input
# Test: curl -X POST https://your-api/generate -d '{"duration_seconds": 999}' → 422
```

### 5. Output Sanitization
```python
# crypto_tools.py: No key material in response
def message_to_dict(self) -> dict:
    """Convert to JSON-safe dict, removing secrets."""
    return {
        "ciphertext": self.ciphertext.hex(),
        "nonce": self.nonce.hex(),
        "tag": self.tag.hex(),
        "algorithm": self.algorithm,
        # ❌ NOT included:
        # "key": self.key.hex(),  # Never expose key
    }

# Verify: Check response logs never contain key material (fingerprints only)
```

---

## 🏥 INCIDENT RESPONSE

### Critical: API Unavailable (5xx errors)
```
1. Check: Application logs
   tail -f /var/log/sumitkey/api.log
   
2. Restart: Container/service
   docker restart sumitkey
   kubectl rollout restart deployment/sumitkey
   
3. Scale: Add more replicas if CPU/memory high
   kubectl scale deployment sumitkey --replicas=5
   
4. Investigate: Root cause in logs
   grep ERROR /var/log/sumitkey/api.log
   grep Exception /var/log/sumitkey/api.log
```

### High: Rate Limiting Triggered (429 Too Many Requests)
```
1. Alert: Possible attack or legitimate traffic spike
   
2. Check: Request pattern
   grep "429" /var/log/sumitkey/security.log | tail -100
   
3. If attack:
   - Get attacker IP
   - Add to firewall blocklist
   - Monitor for DDoS patterns
   
4. If legitimate spike:
   - Increase RATE_LIMIT_REQUESTS temporarily
   - Or distribute load across more API instances
```

### Medium: Entropy Quality Low (< 3.0 bits/byte)
```
1. Alert: Weak entropy detected, key may be vulnerable
   
2. Notify: User to re-capture with more mouse movement
   
3. Investigate: Check if device is functioning
   - Test mouse capture: python3 debug_pipeline.py --mouse-test
   - Test keyboard capture: python3 debug_pipeline.py --keyboard-test
   
4. If device issue:
   - Replace/repair device
   - Consider alternative capture method
```

### Medium: Certificate Expiry Warning
```
1. Alert: Certificate expires in 30 days
   
2. Obtain: New certificate before expiry
   - Contact CA: Let's Encrypt, DigiCert, etc.
   
3. Test: New certificate in staging environment
   
4. Deploy: To production (zero-downtime if using Kubernetes)
   - Update Kubernetes secret: kubectl create secret tls sumitkey-tls --cert=new.pem --key=new.key --dry-run=client -o yaml | kubectl apply -f -
   - Restart pods: kubectl rollout restart deployment/sumitkey
```

---

## 📈 SCALING STRATEGY

### Horizontal Scaling (Multiple Instances)
```yaml
# k8s/deployment.yaml
replicas: 3          # Start with 3 instances
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: sumitkey-autoscale
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: sumitkey
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

### Vertical Scaling (Larger Instances)
```yaml
# k8s/deployment.yaml
resources:
  requests:
    memory: "256Mi"
    cpu: "250m"
  limits:
    memory: "512Mi"
    cpu: "500m"

# Increase if: CPU > 80% consistently, Memory > 90% consistently
```

### Database Scaling (Future)
```
If future implementation adds persistent storage:
  • Use managed database (RDS, Cloud SQL, etc.)
  • Enable read replicas for scaling reads
  • Use connection pooling (pgbouncer, pgpool)
  • Monitor: Query latency, connection pool utilization
```

---

## 🔄 MAINTENANCE & UPDATES

### Weekly Maintenance
- [ ] Review security logs
- [ ] Check TLS certificate expiry date
- [ ] Monitor entropy quality metrics
- [ ] Verify rate limiting is working
- [ ] Backup configuration and logs

### Monthly Maintenance
- [ ] Run NIST 800-90B validation
- [ ] Update threat model documentation
- [ ] Review and rotate access credentials
- [ ] Test disaster recovery procedures
- [ ] Update dependency audit (security patches)

### Quarterly Maintenance
- [ ] Full security audit
- [ ] Penetration testing
- [ ] Load testing
- [ ] Disaster recovery drill
- [ ] Team training on incident response

### Annual Maintenance
- [ ] Complete security review
- [ ] Update TLS certificates
- [ ] Update all dependencies
- [ ] Review threat model assumptions
- [ ] Compliance audit (GDPR, etc.)

---

## 📊 PERFORMANCE TARGETS

| Metric | Target | Acceptable | Alert |
|--------|--------|-----------|-------|
| API Response Time | < 150ms | < 500ms | > 1s |
| NIST Test Pass Rate | 100% (64/64) | 100% | < 100% |
| Entropy Quality | 7.89 bits/byte | > 7.0 | < 3.0 |
| Error Rate | < 0.1% | < 1% | > 5% |
| CPU Utilization | < 30% | < 70% | > 80% |
| Memory Utilization | < 40% | < 70% | > 85% |
| TLS Handshake | < 100ms | < 500ms | > 1s |
| Rate Limit Violations | 0/day | < 10/day | > 50/day |

---

## 🎯 PRODUCTION READINESS CHECKLIST

Before going live:
- [ ] TLS certificate installed and tested
- [ ] NIST 64/64 tests passing
- [ ] Rate limiting active (10 req/min per IP)
- [ ] Logging configured and monitored
- [ ] Alerting configured for critical metrics
- [ ] Disaster recovery plan documented
- [ ] Incident response playbooks written
- [ ] Team trained on operations
- [ ] Backup procedures tested
- [ ] Compliance requirements met (GDPR, etc.)

---

**Status:** ✅ Production-Ready  
**Last Updated:** July 24, 2026  
**Audience:** DevOps/SRE Teams
