/**
 * ==============================================================================
 * CloudSentinel Vulnerable Demo - Automated Test Suite
 * Validates the 10 Required Operational and Architectural Assertions
 * 
 * IMPORTANT DEVSECOPS NOTICE:
 * Passing these 10 functional and configuration tests verifies operational
 * readiness, but must NEVER be conflated with security clearance.
 * The intentional SAST rule violation (javascript:S4790) is designed to trigger
 * CloudSentinel's SAST gate to BLOCK deployment despite test suite success.
 * ==============================================================================
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const request = require('supertest');
const app = require('../src/app');
const { FIXED_PUBLIC_DEMO_STRING, computeInsecureDemoHash, getViolationMetadata } = require('../src/insecure-demo');

describe('CloudSentinel Vulnerable Demo - Test Suite', () => {

  // Test 1: Homepage responds with HTTP 200
  it('1. Homepage responds with HTTP 200', async () => {
    const res = await request(app).get('/');
    assert.equal(res.status, 200);
    assert.match(res.headers['content-type'], /html/);
  });

  // Test 2: Warning message and exact titles are visible in homepage
  it('2. Warning message and exact titles are visible', async () => {
    const res = await request(app).get('/');
    const html = res.text;

    // Check exact required strings
    assert.ok(
      html.includes('CloudSentinel — Vulnerable Demo Application'),
      'Homepage must contain exact header: CloudSentinel — Vulnerable Demo Application'
    );
    assert.ok(
      html.includes('Security Gate Demonstration — Deployment Must Be Blocked'),
      'Homepage must contain exact message: Security Gate Demonstration — Deployment Must Be Blocked'
    );
    assert.ok(
      html.includes('This application intentionally contains a security-rule violation for controlled SAST testing.'),
      'Homepage must contain exact warning: This application intentionally contains a security-rule violation for controlled SAST testing.'
    );
  });

  // Test 3: /health returns HTTP 200
  it('3. /health returns HTTP 200 and UP status', async () => {
    const res = await request(app).get('/health');
    assert.equal(res.status, 200);
    assert.equal(res.body.status, 'UP');
    assert.equal(res.body.service, 'cloudsentinel-vulnerable-demo');
    assert.ok(res.body.timestamp);
  });

  // Test 4: /api/info responds correctly
  it('4. /api/info responds correctly with metadata and endpoints', async () => {
    const res = await request(app).get('/api/info');
    assert.equal(res.status, 200);
    assert.equal(res.body.name, 'cloudsentinel-vulnerable-demo');
    assert.equal(res.body.securityGateStatus, 'BLOCKED');
    assert.equal(res.body.deploymentPolicy.action, 'DENIED');
    assert.equal(res.body.intentionalSecurityViolation.ruleId, 'javascript:S4790');
    assert.ok(res.body.endpoints.health);
    assert.ok(res.body.endpoints.info);
  });

  // Test 5: The intentional security-rule test file exists
  it('5. The intentional security-rule test file exists', () => {
    const insecureFilePath = path.join(__dirname, '../src/insecure-demo.js');
    assert.ok(fs.existsSync(insecureFilePath), 'src/insecure-demo.js must exist in source tree');
  });

  // Test 6: Only the documented intentional vulnerability is introduced
  it('6. Only the documented intentional vulnerability is introduced', () => {
    const insecureContent = fs.readFileSync(path.join(__dirname, '../src/insecure-demo.js'), 'utf8');
    const appContent = fs.readFileSync(path.join(__dirname, '../src/app.js'), 'utf8');

    // Confirm presence of documented MD5 hash violation
    assert.ok(
      insecureContent.includes("crypto.createHash('md5')") || insecureContent.includes('crypto.createHash("md5")'),
      'Intentional MD5 hashing violation must be present in insecure-demo.js'
    );
    assert.ok(
      insecureContent.includes('FIXED_PUBLIC_DEMO_STRING'),
      'Hashing must be performed strictly against fixed public demonstration string'
    );

    // Negative tests: Confirm absence of dangerous sinks
    const bannedPatterns = [
      /require\(['"]child_process['"]\)/,
      /\bexec\s*\(/,
      /\bexecSync\s*\(/,
      /\bspawn\s*\(/,
      /\beval\s*\(/,
      /SELECT\s+.*\s+FROM/i,
      /INSERT\s+INTO/i,
      /DROP\s+TABLE/i,
      /multipart\/form-data/i,
      /multer/i
    ];

    for (const pattern of bannedPatterns) {
      assert.ok(
        !pattern.test(insecureContent) && !pattern.test(appContent),
        `Prohibited dangerous sink pattern ${pattern} found in codebase`
      );
    }
  });

  // Test 7: No external credentials are required
  it('7. No external credentials are required', () => {
    // Assert app operates in standalone mode without any required environment secrets
    const sensitiveEnvKeys = ['AWS_SECRET_ACCESS_KEY', 'DATABASE_URL', 'DB_PASSWORD', 'API_KEY', 'JWT_SECRET'];
    for (const key of sensitiveEnvKeys) {
      assert.equal(
        process.env[key],
        undefined,
        `Application should not expect or require external credential ${key}`
      );
    }
  });

  // Test 8: Dockerfile runs as a non-root user
  it('8. Dockerfile runs as a non-root user', () => {
    const dockerfilePath = path.join(__dirname, '../Dockerfile');
    assert.ok(fs.existsSync(dockerfilePath), 'Dockerfile must exist');

    const dockerfileContent = fs.readFileSync(dockerfilePath, 'utf8');
    assert.ok(
      dockerfileContent.includes('USER node'),
      'Dockerfile must switch execution to non-root user (USER node)'
    );
    assert.ok(
      dockerfileContent.includes('EXPOSE 3000'),
      'Dockerfile must expose port 3000'
    );
  });

  // Test 9: Kubernetes manifests avoid privileged settings
  it('9. Kubernetes manifests avoid privileged settings', () => {
    const deploymentPath = path.join(__dirname, '../k8s/deployment.yaml');
    const servicePath = path.join(__dirname, '../k8s/service.yaml');
    const namespacePath = path.join(__dirname, '../k8s/namespace.yaml');

    assert.ok(fs.existsSync(deploymentPath), 'k8s/deployment.yaml must exist');
    assert.ok(fs.existsSync(servicePath), 'k8s/service.yaml must exist');
    assert.ok(fs.existsSync(namespacePath), 'k8s/namespace.yaml must exist');

    const deploymentContent = fs.readFileSync(deploymentPath, 'utf8');
    const serviceContent = fs.readFileSync(servicePath, 'utf8');

    // Pod & Container security assertions
    assert.ok(
      deploymentContent.includes('runAsNonRoot: true'),
      'k8s deployment must specify runAsNonRoot: true'
    );
    assert.ok(
      deploymentContent.includes('allowPrivilegeEscalation: false'),
      'k8s deployment must disable privilege escalation'
    );
    assert.ok(
      !deploymentContent.includes('privileged: true'),
      'k8s deployment must NOT permit privileged mode'
    );

    // Network isolation assertion
    assert.ok(
      serviceContent.includes('type: ClusterIP'),
      'k8s service must be ClusterIP without public ingress'
    );
  });

  // Test 10: Application is functionally operational
  it('10. Application is functionally operational and hashes match expected digest', async () => {
    // Check computed hash validity
    const hash = computeInsecureDemoHash();
    assert.equal(typeof hash, 'string');
    assert.equal(hash.length, 32, 'MD5 hex digest must be 32 characters long');

    // Verify violation endpoint responds accurately
    const res = await request(app).get('/api/demo/violation');
    assert.equal(res.status, 200);
    assert.equal(res.body.violationDetails.ruleId, 'javascript:S4790');
    assert.equal(res.body.sampleExecution.outputHash, hash);
  });
});
