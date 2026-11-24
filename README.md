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

**13 findings: 8 fixed, 5 accepted with a written reason.**

| # | Finding | Severity | Found by | Status |
|---|---|---|---|---|
| 1 | 6 service containers run as root | High | Semgrep | Fixed |
| 2 | Missing security headers: CSP, X-Frame-Options, X-Content-Type-Options | Medium | ZAP | Fixed |
| 3 | Stack traces enabled in the production profile (CWE-209) | Medium | Manual review | Fixed |
| 4 | Non-numeric query parameter caused a 500 instead of a 400 | Medium | ZAP | Fixed |
| 5 | Vulnerable dependency jjwt 0.11.5 (CVE-2024-31033, disputed) | Medium | SonarQube | Fixed (upgraded to 0.12.6) |
| 6 | GitHub Actions pinned to mutable tags (supply-chain risk) | Medium | Semgrep | Fixed |
| 7 | `Thread.sleep()` inside `synchronized` (rate limiter) | Low (tool said Blocker) | SonarQube | Fixed |
| 8 | Time-zone-unaware SLA duration calculation | Low | SonarQube | Fixed |
| 9 | Demo quick-login buttons with a shared password | High | Manual review, confirmed by ZAP | Accepted: demo-only feature, would be removed in production |
| 10 | Site served over plain HTTP on the server IP | Medium | ZAP | Accepted: demo deployment being removed; HTTPS available via ngrok |
| 11 | CSP allows `'unsafe-inline'` | Medium | ZAP | Accepted, future work |
| 12 | Jenkins container runs as root | Low | Semgrep | Accepted: local CI only |
| 13 | No Subresource Integrity on Google Fonts | Low | ZAP | Accepted: trusted provider |

### False positives

| Alert | Tool | Why it's a false positive |
|---|---|---|
| Buffer Overflow | ZAP | Java is memory-safe. The alert was triggered by a 500 error on a very long input. That 500 was a real input-handling bug, fixed as finding #4. |
| Cross-Domain Misconfiguration, 1× X-Content-Type-Options | ZAP | The URL was `firefox-settings-attachments.cdn.mozilla.net`: background traffic from the headless browser ZAP uses, not my server. Excluded in the second scan. |
| Timestamp Disclosure | ZAP | Normal numbers in responses, not sensitive timestamps. |

## Details of key findings

### 1. Containers running as root (Semgrep)
**Issue:** no `USER` in the Dockerfiles, so each Java process ran as root inside its container.
**Fix:** created a non-root `app` user (UID 10001), gave it only `/app/logs` and `/app/uploads`, and switched to it before `ENTRYPOINT` (principle of least privilege). Existing upload volumes on EC2 were handed over to UID 10001 with `chown`.

### 2. Missing security headers (ZAP)
**Fix:** added a `SecurityHeadersFilter` to the API gateway. It sets `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, and HSTS when the request came over HTTPS. The filter skips `/api/**`, because the backend services already set these headers there and would otherwise send them twice.

### 5. jjwt CVE-2024-31033 (disputed)
The CVE says a user might wrongly believe their key is strong. The maintainers dispute it. My signing keys are 66+ random characters loaded from environment variables, so the real risk was low. I upgraded to 0.12.6 anyway, which meant migrating to the new parser API (`parser().verifyWith().parseSignedClaims()`) in 4 services.

### 7. SonarQube "Blocker": `Thread.sleep()` inside `synchronized`
SonarQube suggested replacing `sleep()` with `wait()`, but that doesn't fit a rate limiter. Impact was also **low in practice**: the VirusTotal executor has a single worker, so nothing ever competed for the lock. I fixed it defensively anyway: a thread now books its time slot while holding the lock and sleeps after releasing it. The 16-second spacing is unchanged.
**Lesson:** a tool's severity label and suggested fix need to be checked against how the system actually works.

### 9. Demo quick-login buttons (accepted for a demo, not for production)
**Issue:** the login page has "Demo accounts" buttons that fill in a shared password (`Password123!`) and log in, including as **admin**, so anyone can use them.
**Proof:** during the DAST scan, ZAP's AJAX spider clicked the button and received a valid admin token. An automated crawler became admin without knowing any credentials. None of the tools reported this as a vulnerability; I found it by reviewing the code and reading the ZAP traffic.
**Decision:** accepted, because BankDesk is a demo project built to be shown to reviewers, and the deployment is being removed. **In production I would:** remove the buttons, use a unique password per account loaded from environment variables, and show demo logins only on `localhost`.

### 11. CSP `'unsafe-inline'` (accepted, future work)
The frontend uses inline `<script>` and about 100 inline `onclick` handlers, so the CSP has to allow `'unsafe-inline'`. That weakens its protection against XSS. The CSP still blocks third-party scripts, framing (clickjacking), plugins and form posts to other sites. **Future work:** move the JavaScript into external files, replace the `onclick` handlers with `addEventListener`, then remove `'unsafe-inline'`..

## Screenshots

### Semgrep
| Before | After |
|---|---|
| ![](<screenshots/SAST/Semgrep/before.png>) | ![](<screenshots/SAST/Semgrep/after.png>) |

### SonarQube
| Before | After |
|---|---|
| ![](<screenshots/SAST/sonarcloud/before/sonar-before-summary.png>) | ![](<screenshots/SAST/sonarcloud/after/sonar-after-summary.png>) |
| ![](<screenshots/SAST/sonarcloud/before/sonar-dependency-cve-alert.png>) | ![](<screenshots/SAST/sonarcloud/after/no-CVE-(after).png>) |

### OWASP ZAP
| Before | After |
|---|---|
| ![](<screenshots/DAST(ZAP)/Before/Bankdesk-ZAPAlerts-Before.png>) | ![](<screenshots/DAST(ZAP)/After/Bankdesk-ZAPAlerts-After.png>) |

New security headers on the gateway response:

![](<screenshots/DAST(ZAP)/After/detailed-ZAP-Alert After.png>)

## Known limitations and future work
- **Unauthenticated DAST only.** Next step: an authenticated ZAP scan with a test user, to cover the logged-in API endpoints and access control (e.g. IDOR between customers).
- **CSP `'unsafe-inline'`:** see finding #11.
- **Quality gate fails on duplication (9.8% of new code),** because each microservice keeps its own `JwtUtils`. Future: a shared JWT library module.
- **32 SonarQube reliability issues** in the frontend are accessibility (WCAG) issues, outside the scope of this security review.

## Reports
Download the HTML reports and open them in a browser (GitHub shows them as source code).

- Semgrep: [before](<Reports/semgrep-reports/semgrep-results(before).txt>) · [after](<Reports/semgrep-reports/semgrep-results(after).txt>)
- OWASP ZAP: [before](<Reports/Zap-reports/Bankdesk-zap-report-before.html>) · [after](<Reports/Zap-reports/Bankdesk-zap-report-after.html>)

*Note: the frontend of BankDesk was AI-generated (out of scope); the backend, infrastructure and this security review are my own work.*
