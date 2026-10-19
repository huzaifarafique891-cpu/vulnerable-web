/**
 * CloudSentinel Vulnerable Demo Application
 * Express.js Server
 */

const express = require('express');
const path = require('path');
const { computeInsecureDemoHash, getViolationMetadata } = require('./insecure-demo');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware for parsing JSON & serving static files
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

// Explicit route for homepage
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// Required health probe endpoint - Returns HTTP 200
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'UP',
    service: 'cloudsentinel-vulnerable-demo',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Required /api/info endpoint
app.get('/api/info', (req, res) => {
  const metadata = getViolationMetadata();
  const demoHash = computeInsecureDemoHash();

  res.status(200).json({
    name: 'cloudsentinel-vulnerable-demo',
    version: '1.0.0',
    description: 'CloudSentinel Vulnerable Demo Application for controlled SAST security gate testing',
    exactHeader: 'CloudSentinel — Vulnerable Demo Application',
    exactGateMessage: 'Security Gate Demonstration — Deployment Must Be Blocked',
    exactWarningMessage: 'This application intentionally contains a security-rule violation for controlled SAST testing.',
    environment: process.env.NODE_ENV || 'production',
    securityGateStatus: 'BLOCKED',
    pipelineStage: 'SAST Scan Gate',
    intentionalSecurityViolation: {
      ...metadata,
      computedDemoHash: demoHash
    },
    deploymentPolicy: {
      action: 'DENIED',
      reason: 'SAST rule violation detected: javascript:S4790 (Weak Cryptographic Hash Algorithm)',
      allowedToDeploy: false
    },
    endpoints: {
      home: '/',
      health: '/health',
      info: '/api/info',
      violationDemo: '/api/demo/violation'
    }
  });
});

// Dedicated violation endpoint for verification & demonstration inspection
app.get('/api/demo/violation', (req, res) => {
  const metadata = getViolationMetadata();
  const computedHash = computeInsecureDemoHash();

  res.status(200).json({
    warning: 'This application intentionally contains a security-rule violation for controlled SAST testing.',
    violationDetails: metadata,
    sampleExecution: {
      input: metadata.targetData,
      algorithm: metadata.algorithmUsed,
      outputHash: computedHash
    }
  });
});

// Start server if executed directly
if (require.main === module) {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[CloudSentinel Vulnerable Demo] Running on http://0.0.0.0:${PORT}`);
    console.log(`[Security Note] Intentional SAST rule violation active in src/insecure-demo.js (javascript:S4790)`);
    console.log(`[Gate Policy] Expected gate outcome: BLOCKED`);
  });
}

module.exports = app;
