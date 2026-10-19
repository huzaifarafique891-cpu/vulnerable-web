gfiy# CloudSentinel — Vulnerable Demo Application (Project B)

> ⚠️ **ACADEMIC DEVSECOPS SECURITY TESTING NOTICE**  
> **This repository intentionally contains an insecure coding pattern designed for controlled SAST verification.**  
> It is strictly designated for local academic testing within the CloudSentinel DevSecOps evaluation framework.  
> **Under active security-gate policy, deployment to production or staging Kubernetes clusters MUST BE BLOCKED.**

---

## 1. Project Purpose

`cloudsentinel-vulnerable-demo` is a lightweight, standalone Node.js/Express demonstration web application created to validate the enforcement mechanisms of **CloudSentinel's automated DevSecOps Security Gate**.

In modern CI/CD pipelines, automated testing frequently focuses solely on functional correctness (e.g., whether endpoints respond with HTTP 200). This demonstration proves that functional success alone is insufficient: **code containing identifiable security violations must trigger security-gate failure and prevent automated container deployment.**

---

## 2. Architecture & Design

The application is structured into isolated, testable tiers without any dependency on external databases, cloud services, or credentials:

```
cloudsentinel-vulnerable-demo/
├── src/
│   ├── app.js               # Express application server and routing logic
│   └── insecure-demo.js     # Isolated intentional cryptographic rule violation
├── public/
│   ├── index.html           # DevSecOps status dashboard UI (Dark Glassmorphic UI)
│   └── styles.css           # Visual styling system with interactive pipeline stages
├── tests/
│   └── app.test.js          # 10-point automated operational & security specification test suite
├── k8s/
│   ├── namespace.yaml       # Namespace definition: cloudsentinel-vulnerable-demo
│   ├── deployment.yaml      # Hardened non-root Kubernetes Deployment manifest
│   └── service.yaml         # ClusterIP Service manifest (port 80 -> 3000)
├── Dockerfile               # Production hardened Node.js 22 LTS Alpine Dockerfile (non-root)
├── .dockerignore            # Build context filter
├── .gitignore               # SCM exclusion filter
├── package.json             # Manifest with Express and dev dependencies
├── package-lock.json        # Reproducible dependency lockfile
└── README.md                # Comprehensive documentation
```

### Endpoints Specification

| Method | Path | Status | Purpose |
| :--- | :--- | :--- | :--- |
| `GET` | `/` | `200 OK` | Serves interactive UI displaying mandatory status and warnings |
| `GET` | `/health` | `200 OK` | Health probe returning service uptime and operational status |
| `GET` | `/api/info` | `200 OK` | Metadata descriptor detailing the gate status and rule violation |
| `GET` | `/api/demo/violation` | `200 OK` | Controlled execution showing the MD5 digest of the demo constant |

---

## 3. Intentional Security-Rule Violation

To provide a safe, harmless, and reliably scanner-recognizable finding, this repository introduces exactly **ONE** isolated cryptographic defect.

### Technical Specification

- **Target Source File:** [`src/insecure-demo.js`](file:///src/insecure-demo.js#L39)
- **Exact Line of Defect:** Line 39 (`const hash = crypto.createHash('md5');`)
- **Vulnerability Category:** Weak Cryptographic Hash Algorithm
- **Target Scanner Rule:** SonarQube `javascript:S4790` (*"Weak hashing algorithms should not be used"*)
- **Industry Classifications:**
  - **CWE-327:** Use of a Broken or Risky Cryptographic Algorithm
  - **CWE-328:** Use of Weak Hash
  - **OWASP Top 10:** A02:2021 — Cryptographic Failures

### Controlled Safety Scope

1. **Fixed Public Input:** The hash is computed strictly on a static constant string (`"CloudSentinel-Academic-Demo-String-V1"`).
2. **Zero Sensitive Data:** No user credentials, passwords, tokens, API keys, or personally identifiable information (PII) are processed.
3. **No Dangerous Sinks:** The application contains **NO** SQL queries, command execution (`exec`/`spawn`), eval, file upload parsers, or untrusted network callers.
4. **Isolated Runtime:** The defect is purely static-source detectable and poses zero runtime threat to the executing host.

---

## 4. Functional Testing vs. Security Testing

A core tenet of DevSecOps is understanding the divergence between functional testing and security gate policy:

```
+-------------------------------------------------------------------------+
|                  CODE COMMIT: git push origin main                     |
+-------------------------------------------------------------------------+
                                    |
          +-------------------------+-------------------------+
          |                                                   |
          v                                                   v
+-------------------------+                       +-----------------------+
|  Functional Test Suite  |                       |  CloudSentinel Gate   |
|     (npm run test)      |                       |    (SAST Analysis)    |
+-------------------------+                       +-----------------------+
          |                                                   |
          | Runs 10/10 assertions                             | Scans AST for CWE-327
          | - Routes respond 200                              | - Identifies S4790 (MD5)
          | - Health checks pass                              | - Threshold breached
          v                                                   v
+-------------------------+                       +-----------------------+
|       RESULT: PASS      |                       |    RESULT: BLOCKED    |
+-------------------------+                       +-----------------------+
          |                                                   |
          +-------------------------+-------------------------+
                                    |
                                    v
                     +-----------------------------+
                     |   PIPELINE PROMOTION RULE   |
                     | Both Must Pass to Deploy    |
                     +-----------------------------+
                                    |
                                    v
                     +=============================+
                     |    DEPLOYMENT DENIED        |
                     |    Artifacts Discarded      |
                     +=============================+
```

Even though all 10 automated test suites pass with zero errors, CloudSentinel's SAST gate intercepts the code before container creation or Kubernetes deployment can take place.

---

## 5. CloudSentinel Onboarding & Webhook Integration

### Project Onboarding Configuration

1. **Repository Target:** `cloudsentinel-vulnerable-demo`
2. **Webhook Event:** GitHub `push` / `pull_request`
3. **Pipeline Stages:**
   - Source Code Checkout
   - Dependency Validation (`npm ci --ignore-scripts`)
   - SAST Analysis (SonarQube Scanner / ESLint Security)
   - Quality Gate Evaluation
   - *Conditional Action:* Build Docker image and apply Kubernetes manifests **ONLY** if gate status is `PASSED`.

### Expected Security Gate Evaluation

- **SAST Rule Triggered:** `javascript:S4790`
- **Issue Severity:** `CRITICAL` / `BLOCKER` (in default SonarQube Way quality profile)
- **Quality Gate Condition:** *"New Security Vulnerabilities > 0"* or *"Security Rating worse than A"*
- **Evaluated Gate Result:** **`BLOCKED`**
- **Pipeline Reaction:** The webhook callback terminates the build with an error code, notifying the repository owner that deployment has been withheld.

---

## 6. Why Deployment Must Be Denied When Gate is BLOCKED

Allowing applications with unresolved SAST findings into production exposes cloud infrastructure to:
- Supply-chain poisoning and reliance on obsolete algorithms.
- Non-compliance with PCI-DSS (Requirement 3.4), NIST SP 800-131A, and ISO/IEC 27001.
- Inability to enforce preventative shift-left controls across engineering squads.

By arresting the pipeline at the SAST gate, CloudSentinel guarantees that unvetted workloads never reach container registries or cluster runtimes.

---

## 7. Comparison: Project A (Secure Demo) vs. Project B (Vulnerable Demo)

| Evaluation Metric | Project A (`cloudsentinel-secure-demo`) | Project B (`cloudsentinel-vulnerable-demo`) |
| :--- | :--- | :--- |
| **Cryptographic Primitives** | Secure SHA-256 (`crypto.createHash('sha256')`) | Obsolete MD5 (`crypto.createHash('md5')`) |
| **SonarQube S4790 Trigger** | None (0 issues found) | **1 Blocker Issue Found** |
| **Functional Tests** | 100% Passed | 100% Passed |
| **Security Gate Outcome** | **PASSED** | **BLOCKED** |
| **Docker Build Status** | Permitted & Tagged | **Aborted** |
| **Kubernetes Promotion** | Deployed to Cluster | **Halted (Zero pods scheduled)** |

---

## 8. Local Verification & Execution

### Prerequisites
- Node.js >= 20.0.0 LTS
- npm >= 10.0.0

### Install Dependencies
```bash
npm install
```

### Run Automated 10-Point Test Suite
```bash
npm test
```

### Start Application Locally
```bash
npm start
```
Open [http://localhost:3000](http://localhost:3000) to view the interactive DevSecOps inspection interface.

---

## 9. Container & Kubernetes Manifests (Auditing Only)

Although deployment is blocked under gate policy, manifests are provided for comparative static analysis and security scanning:

- **Dockerfile:** Hardened Alpine Node.js 22 LTS with unprivileged execution (`USER node`).
- **Kubernetes Manifests:**
  - `k8s/namespace.yaml`
  - `k8s/deployment.yaml` (`runAsNonRoot: true`, `allowPrivilegeEscalation: false`, all capabilities dropped)
  - `k8s/service.yaml` (Internal `ClusterIP` only)
