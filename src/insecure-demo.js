/**
 * ============================================================================
 * CLOUDSENTINEL CONTROLLED SECURITY TEST COMPONENT
 * ============================================================================
 * 
 * INTENTIONAL SECURITY-RULE VIOLATION FOR CONTROLLED SAST TESTING
 * 
 * Target Scanner Rule:
 *   - SonarQube: javascript:S4790 ("Weak hashing algorithms should not be used")
 *   - CWE Identifier: CWE-327 (Use of a Broken or Risky Cryptographic Algorithm), CWE-328 (Use of Weak Hash)
 *   - OWASP Top 10: A02:2021 - Cryptographic Failures
 * 
 * Safety & Compliance Boundaries:
 *   - Uses ONLY a fixed public demo string ("CloudSentinel-Academic-Demo-String-V1").
 *   - NO passwords, tokens, session IDs, or sensitive data are hashed.
 *   - NO database queries, file system writes, or network calls.
 *   - NO arbitrary input acceptance; this is strictly an internal demo computation.
 *   - Completely harmless in execution, yet reliably flagged by SAST scanners (SonarQube, Semgrep, ESLint Security).
 * 
 * Security Gate Expectation:
 *   When CloudSentinel triggers a SAST scan on push, this file triggers rule javascript:S4790,
 *   causing the Security Gate to evaluate as BLOCKED, denying Docker build and Kubernetes deployment.
 * ============================================================================
 */

const crypto = require('crypto');

// Fixed, non-sensitive, public demonstration constant
const FIXED_PUBLIC_DEMO_STRING = 'CloudSentinel-Academic-Demo-String-V1';

/**
 * Computes an MD5 hash over a fixed public demonstration string.
 * MD5 is cryptographically broken and prone to collision attacks.
 * 
 * Insecure Pattern (Line below triggers SonarQube javascript:S4790):
 */
function computeInsecureDemoHash() {
  // INTENTIONAL SAST VIOLATION: Insecure hash algorithm (MD5)
  // Rule: javascript:S4790 - Weak hashing algorithms should not be used
  const hash = crypto.createHash('md5');
  hash.update(FIXED_PUBLIC_DEMO_STRING);
  return hash.digest('hex');
}

/**
 * Metadata descriptor for CloudSentinel SAST verification and reporting.
 */
function getViolationMetadata() {
  return {
    demonstrationMode: true,
    ruleId: 'javascript:S4790',
    ruleName: 'Weak hashing algorithms should not be used',
    severityExpected: 'CRITICAL',
    cwe: ['CWE-327', 'CWE-328'],
    owasp: 'A02:2021 - Cryptographic Failures',
    algorithmUsed: 'MD5',
    targetData: FIXED_PUBLIC_DEMO_STRING,
    isSensitiveData: false,
    file: 'src/insecure-demo.js',
    line: 39,
    expectedGateAction: 'BLOCK_DEPLOYMENT'
  };
}

module.exports = {
  FIXED_PUBLIC_DEMO_STRING,
  computeInsecureDemoHash,
  getViolationMetadata
};
