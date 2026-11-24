# BankDesk Security Assessment (SAST + DAST)

A security review of **[BankDesk](https://github.com/yusufseroor-24/bank-ticketing-desk)**, my Spring Boot microservices banking ticket system, using static analysis (SAST), dynamic analysis (DAST) and manual code review. I triaged each finding, fixed the real issues, and re-scanned to confirm the fixes.

| Area | Details |
|---|---|
| **Target** | 6 Spring Boot services behind an API gateway, deployed on AWS EC2 with Docker and a Jenkins CI/CD pipeline |
| **SAST** | SonarQube Cloud, Semgrep (run in GitHub Actions) |
| **DAST** | OWASP ZAP 2.17 (automated scan: spider, AJAX spider and active scan) |
| **Manual review** | Source code, Dockerfiles, configuration |
| **Scope** | Unauthenticated DAST scan of the deployed app and full source for SAST |

## Results summary

| Tool | Before | After |
|---|---|---|
| **Semgrep** | 9 findings | **0** |
| **SonarQube**: Security | 0 (A) | 0 (A) |
| **SonarQube**: Reliability | 35 (E) | 32 (C), all remaining are frontend accessibility issues |
| **SonarQube**: Dependency risks | 1 (C) | **0 (A)** |
| **ZAP** | 16 alerts (0 High, 6 Medium, 3 Low, 7 Info) | 9 alerts (0 High, 4 Medium, 0 Low, 5 Info) |
| **Manual review** | 2 findings | **Fixed** |

## Findings

| # | Finding | Severity | Found by | Status |
|---|---|---|---|---|
| 1 | Demo-account login buttons with a hard-coded admin password on the public site | **Critical** | Manual review, confirmed by ZAP | Fixed |
| 2 | Admin, agent and customer credentials pre-filled in public `simulation.html` (CWE-798) | **High** | Manual review | Fixed |
| 3 | 6 service containers run as root | High | Semgrep | Fixed |
| 4 | Missing security headers: CSP, X-Frame-Options, X-Content-Type-Options | Medium | ZAP | Fixed |
| 5 | Stack traces enabled in the production profile (CWE-209) | Medium | Manual review | Fixed |
| 6 | Non-numeric query parameter caused a 500 instead of a 400 | Medium | ZAP | Fixed |
| 7 | Vulnerable dependency jjwt 0.11.5 (CVE-2024-31033, disputed) | Medium | SonarQube | Fixed (upgraded to 0.12.6) |
| 8 | GitHub Actions pinned to mutable tags (supply-chain risk) | Medium | Semgrep | Fixed |
| 9 | Site served over plain HTTP on the server IP | Medium | ZAP | Fixed (port 80 closed; HTTPS only via ngrok) |
| 10 | CSP allows `'unsafe-inline'` | Medium | ZAP | Accepted, future work |
| 11 | `Thread.sleep()` inside `synchronized` (rate limiter) | Low (tool said Blocker) | SonarQube | Fixed |
| 12 | Time-zone-unaware SLA duration calculation | Low | SonarQube | Fixed |
| 13 | Jenkins container runs as root | Low | Semgrep | Accepted risk |
| 14 | No Subresource Integrity on Google Fonts | Low | ZAP | Accepted risk |

### False positives

| Alert | Tool | Why it's a false positive |
|---|---|---|
| Buffer Overflow | ZAP | Java is memory-safe. The alert was triggered by a 500 error on a very long input. That 500 was a real input-handling bug, fixed as finding #6. |
| Cross-Domain Misconfiguration, 1× X-Content-Type-Options | ZAP | The URL was `firefox-settings-attachments.cdn.mozilla.net`: background traffic from the headless browser ZAP uses, not my server. Excluded in the second scan. |
| Timestamp Disclosure | ZAP | Normal numbers in responses, not sensitive timestamps. |

## Details of key findings

### 1. One-click admin login on the public site (Critical)
**Issue:** the login page had "Demo accounts" buttons. Their JavaScript filled in a hard-coded password (`Password123!`) and logged in, including as **admin**.
**Proof:** during the DAST scan, ZAP's AJAX spider clicked the button and received a valid admin token. An automated crawler became admin without any credentials.
**Fix:** removed the demo-login buttons from the deployed frontend, changed all demo account passwords, and moved the seed password into an environment variable.
**Lesson:** none of the tools reported this as a vulnerability. I found it by reviewing the code and reading the ZAP traffic.

### 3. Containers running as root (Semgrep)
**Issue:** no `USER` in the Dockerfiles, so each Java process ran as root inside its container.
**Fix:** created a non-root `app` user (UID 10001), gave it only `/app/logs` and `/app/uploads`, and switched to it before `ENTRYPOINT` (principle of least privilege). Existing upload volumes on EC2 were handed over to UID 10001 with `chown`.

### 4. Missing security headers (ZAP)
**Fix:** added a `SecurityHeadersFilter` to the API gateway. It sets `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, and HSTS when the request came over HTTPS. The filter skips `/api/**`, because the backend services already set these headers there and would otherwise send them twice.

### 10. CSP `'unsafe-inline'` (accepted, future work)
The frontend uses inline `<script>` and about 100 inline `onclick` handlers, so the CSP has to allow `'unsafe-inline'`. That weakens its protection against XSS. The CSP still blocks third-party scripts, framing (clickjacking), plugins and form posts to other sites. **Future work:** move the JavaScript into external files and replace the `onclick` handlers with `addEventListener`, then remove `'unsafe-inline'`.

### 11. SonarQube "Blocker": `Thread.sleep()` inside `synchronized`
SonarQube suggested replacing `sleep()` with `wait()`, but that doesn't fit a rate limiter. Impact was also **low in practice**: the VirusTotal executor has a single worker, so nothing ever competed for the lock. I fixed it defensively anyway: a thread now books its time slot while holding the lock and sleeps after releasing it. The 16-second spacing is unchanged.
**Lesson:** a tool's severity label and suggested fix need to be checked against how the system actually works.

### 7. jjwt CVE-2024-31033 (disputed)
The CVE says a user "might falsely conclude they have a strong key". The maintainers dispute it. My signing keys are 66+ random characters loaded from environment variables, so the real risk was low. I upgraded to 0.12.6 anyway, which meant migrating to the new parser API (`parser().verifyWith().parseSignedClaims()`) in 4 services.

## Screenshots

### Semgrep
| Before | After |
|---|---|
| ![](screenshots/SAST/semgrep/before.png) | ![](screenshots/SAST/semgrep/after.png) |

### SonarQube
| Before | After |
|---|---|
| ![](screenshots/SAST/sonarcloud/sonar-before-summary.png) | ![](screenshots/SAST/sonarcloud/sonar-after-summary.png) |
| ![](screenshots/SAST/sonarcloud/sonar-dependency-cve-alert.png) | ![](screenshots/SAST/sonarcloud/no-CVE-(after).png) |

### OWASP ZAP
| Before | After |
|---|---|
| ![](screenshots/DAST(ZAP)/Bankdesk-ZAPAlerts-Before.png) | ![](screenshots/DAST(ZAP)/Bankdesk-ZAPAlerts-After.png) |

New security headers on the gateway response:

![](screenshots/zap/detailed-ZAP-Alert-After.png)

## Known limitations and future work
- **Unauthenticated DAST only.** Next step: an authenticated ZAP scan with a test user, to cover the logged-in API endpoints and access control (e.g. IDOR between customers).
- **CSP `'unsafe-inline'`:** see finding #10.
- **Quality gate fails on duplication (9.8% of new code),** because each microservice keeps its own `JwtUtils`. Future: a shared JWT library module.
- **32 SonarQube reliability issues** in the frontend are accessibility (WCAG) issues, outside the scope of this security review.

## Reports
- [`Reports/semgrep-reports/semgrep-results(before).txt`](Reports/semgrep-reports/semgrep-results(before).txt) · [`Reports/semgrep-reports/semgrep-results(after).txt`](Reports/semgrep-reports/semgrep-results(after).txt)
- [`Reports/Zap-reports/Bankdesk-zap-report-before.html`](Reports/Zap-reports/Bankdesk-zap-report-before.html) · [`Reports/Zap-reports/Bankdesk-zap-report-after.html`](Reports/Zap-reports/Bankdesk-zap-report-after.html)

*Note: the frontend of BankDesk was AI-generated (out of scope); the backend, infrastructure and this security review are my own work.*
