# AI Security Audit Agent

A comprehensive, deployable AI agent for infrastructure security auditing. Built on the Agent Squad framework, this agent provides continuous security monitoring with a privacy-first hybrid AI approach.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Configuration](#configuration)
- [Usage](#usage)
  - [Programmatic API](#programmatic-api)
  - [CLI Interface](#cli-interface)
- [Scanners](#scanners)
- [Hybrid AI Processing](#hybrid-ai-processing)
- [Continuous Monitoring](#continuous-monitoring)
- [Data Sanitization](#data-sanitization)
- [API Reference](#api-reference)
- [Examples](#examples)

## Features

| Feature | Description |
|---------|-------------|
| **Config Audit** | Scans for default credentials, exposed ports, weak authentication |
| **Network Mapping** | Documents network topology, identifies unnecessary exposure |
| **Container Security** | Checks Docker configs, privileged containers, volume mounts |
| **Auth Review** | Analyzes shared credentials vs proper isolation |
| **Log Analysis** | Pattern detection for brute force, data exfil, IMSI concerns |
| **Hybrid AI** | Local model for scanning, Vertex AI for pattern analysis |
| **Privacy-First** | Sensitive data stays local; only sanitized patterns sent to cloud |
| **Continuous Monitoring** | Real-time change validation and dependency tracking |
| **CLI Interface** | Standalone usage or CI/CD pipeline integration |

## Installation

```bash
# Install the agent-squad package
npm install agent-squad

# For CLI usage, you can also install globally
npm install -g agent-squad
```

### Requirements

- Node.js 18+
- TypeScript 5.0+ (for development)
- Docker (optional, for container scanning)
- Kubernetes CLI (optional, for K8s service discovery)
- Google Cloud SDK (optional, for Vertex AI integration)
- Ollama (optional, for local AI processing)

## Quick Start

### Basic Usage

```typescript
import { SecurityAuditAgent } from 'agent-squad';

// Create the agent
const agent = new SecurityAuditAgent({
  name: 'MySecurityAgent',
  description: 'Security auditor for my infrastructure'
});

// Run a full security audit
const response = await agent.processRequest(
  'full audit',
  'user-id',
  'session-id',
  []
);

console.log(response.content[0].text);
```

### CLI Quick Start

```bash
# Run a full security audit
npx security-audit full-audit

# Interactive mode
npx security-audit -i

# Scan specific components
npx security-audit container-scan
npx security-audit config-audit
npx security-audit network-map
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    SecurityAuditAgent                           │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    Orchestrator                          │   │
│  └─────────────────────────────────────────────────────────┘   │
│           │                    │                    │           │
│  ┌────────▼────────┐  ┌───────▼───────┐  ┌────────▼────────┐  │
│  │    Scanners     │  │   Analyzers   │  │    Monitors     │  │
│  │  ─────────────  │  │  ───────────  │  │  ────────────   │  │
│  │  ConfigScanner  │  │  HybridAI     │  │  Continuous     │  │
│  │  NetworkMapper  │  │  Processor    │  │  Monitor        │  │
│  │  ContainerScan  │  │               │  │                 │  │
│  │  AuthScanner    │  │  ┌─────────┐  │  │  ┌───────────┐  │  │
│  │  LogAnalyzer    │  │  │ Local   │  │  │  │ Change    │  │  │
│  └─────────────────┘  │  │ Model   │  │  │  │ Validator │  │  │
│                       │  └────┬────┘  │  │  └───────────┘  │  │
│  ┌─────────────────┐  │       │       │  │                 │  │
│  │   Utilities     │  │  ┌────▼────┐  │  │  ┌───────────┐  │  │
│  │  ─────────────  │  │  │Sanitizer│  │  │  │Dependency │  │  │
│  │  DataSanitizer  │  │  └────┬────┘  │  │  │ Tracker   │  │  │
│  │                 │  │       │       │  │  └───────────┘  │  │
│  └─────────────────┘  │  ┌────▼────┐  │  │                 │  │
│                       │  │Vertex AI│  │  │                 │  │
│                       │  └─────────┘  │  │                 │  │
│                       └───────────────┘  └─────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### Data Flow

1. **Scanners** collect security data from your infrastructure
2. **Sanitizer** removes/anonymizes sensitive data
3. **Local Model** performs initial classification (data stays local)
4. **Vertex AI** analyzes patterns from sanitized data
5. **Monitor** validates changes and tracks dependencies
6. **Reports** combine all insights with recommendations

## Configuration

### Full Configuration Example

```typescript
import { SecurityAuditAgent } from 'agent-squad';

const agent = new SecurityAuditAgent({
  name: 'ProductionSecurityAgent',
  description: 'Security auditor for production infrastructure',

  config: {
    // AI Model Configuration
    modelConfig: {
      modelId: 'anthropic.claude-3-sonnet-20240229-v1:0',
      temperature: 0,        // Deterministic for security
      maxTokens: 4096,
      streaming: true
    },

    // Local Model (keeps data on-premise)
    localModelConfig: {
      enabled: true,
      modelType: 'ollama',
      endpoint: 'http://localhost:11434',
      capabilities: ['scan', 'classify']
    },

    // Vertex AI (for pattern analysis)
    vertexConfig: {
      enabled: true,
      projectId: 'my-gcp-project',
      location: 'us-central1',
      modelId: 'gemini-1.5-pro',
      useForPatternAnalysis: true,
      useForAnomalyDetection: true
    },

    // Continuous Monitoring
    monitoringConfig: {
      enabled: true,
      intervalSeconds: 60,
      alertThresholds: [
        {
          metric: 'critical_findings',
          operator: 'gt',
          value: 0,
          severity: 'critical',
          cooldownSeconds: 300
        }
      ],
      notificationChannels: [
        {
          type: 'slack',
          config: { webhookUrl: 'https://hooks.slack.com/...' },
          severityFilter: ['critical', 'high']
        },
        {
          type: 'webhook',
          config: { url: 'https://my-siem.example.com/alerts' },
          severityFilter: ['critical', 'high', 'medium']
        }
      ]
    },

    // Data Sanitization
    sanitizationConfig: {
      enabled: true,
      preserveFormat: true,
      hashSensitiveValues: false,
      patterns: []  // Uses defaults, add custom patterns here
    },

    // Storage
    storageConfig: {
      type: 'database',  // 'memory' | 'file' | 'database'
      retentionDays: 90,
      encryptAtRest: true
    }
  }
});
```

### Environment Variables

```bash
# Google Cloud (for Vertex AI)
export GOOGLE_CLOUD_PROJECT=my-project-id
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/credentials.json

# Local Model
export OLLAMA_HOST=http://localhost:11434

# Optional: Custom scan targets
export SECURITY_SCAN_TARGETS=/app,/etc,/var
```

## Usage

### Programmatic API

#### Running Scans

```typescript
import { SecurityAuditAgent } from 'agent-squad';

const agent = new SecurityAuditAgent({ name: 'SecurityAgent' });

// Full audit (all scanners)
const fullAudit = await agent.processRequest('full audit', 'user', 'session', []);

// Individual scans
const configScan = await agent.processRequest('config audit', 'user', 'session', []);
const networkScan = await agent.processRequest('network map', 'user', 'session', []);
const containerScan = await agent.processRequest('container scan', 'user', 'session', []);
const authScan = await agent.processRequest('auth review', 'user', 'session', []);
const logScan = await agent.processRequest('log analysis', 'user', 'session', []);
```

#### Using Individual Scanners

```typescript
import {
  ConfigScanner,
  NetworkMapper,
  ContainerScanner,
  AuthScanner,
  LogAnalyzer
} from 'agent-squad';

// Config Scanner
const configScanner = new ConfigScanner({
  targets: ['/app', '/etc'],
  checkDefaultCredentials: true,
  checkExposedPorts: true,
  checkWeakAuth: true,
  maxDepth: 5
});
const configResult = await configScanner.scan();

// Network Mapper
const networkMapper = new NetworkMapper({
  discoverHosts: true,
  scanPorts: true,
  detectServices: true,
  mapTopology: true
});
const networkResult = await networkMapper.scan();
const topology = networkMapper.getTopology();

// Container Scanner
const containerScanner = new ContainerScanner({
  checkPrivileged: true,
  checkVolumes: true,
  checkNetwork: true,
  checkCapabilities: true,
  checkSecrets: true,
  checkImages: true
});
const containerResult = await containerScanner.scan();

// Auth Scanner
const authScanner = new AuthScanner({
  checkSharedCredentials: true,
  checkPasswordStrength: true,
  checkMFA: true,
  checkPermissions: true,
  checkCredentialAge: true,
  maxCredentialAgeDays: 90
});
const authResult = await authScanner.scan();

// Log Analyzer
const logAnalyzer = new LogAnalyzer({
  logSources: ['/var/log/auth.log', '/var/log/syslog'],
  timeRange: {
    start: new Date(Date.now() - 24 * 60 * 60 * 1000),
    end: new Date()
  },
  enableAnomalyDetection: true
});
const logResult = await logAnalyzer.scan();
```

#### Continuous Monitoring

```typescript
import { ContinuousMonitor } from 'agent-squad';

const monitor = new ContinuousMonitor({
  enabled: true,
  intervalSeconds: 60,
  alertThresholds: [
    { metric: 'critical_findings', operator: 'gt', value: 0, severity: 'critical', cooldownSeconds: 300 }
  ],
  notificationChannels: []
});

// Event handlers
monitor.on('alert', (data) => {
  console.log('Security Alert:', data);
});

monitor.on('change', (change) => {
  console.log('Change detected:', change.changeType, change.resourceId);
});

monitor.on('validation', (data) => {
  if (!data.result.passed) {
    console.log('Validation failed:', data.change.resourceId);
  }
});

// Start monitoring
await monitor.start();

// Validate a change before deployment
const validationResult = await monitor.validateChange({
  id: 'change-123',
  timestamp: new Date(),
  changeType: 'container',
  resourceId: 'my-container',
  resourceType: 'docker',
  previousState: {},
  newState: { privileged: false, image: 'myapp:v1.2.3' },
  validated: false
});

if (!validationResult.passed) {
  console.log('Deployment blocked:', validationResult.errors);
}

// Analyze impact of service change
const impact = await monitor.analyzeImpact('database-service');
console.log('Impact analysis:', impact);

// Get affected services
const affected = monitor.getAffectedServices('api-gateway');
console.log('Services affected by api-gateway:', affected);

// Stop monitoring
monitor.stop();
```

### CLI Interface

```bash
# Show help
security-audit --help

# Run full audit
security-audit full-audit

# Run specific scans
security-audit config-audit
security-audit network-map
security-audit container-scan
security-audit auth-review
security-audit log-analysis

# Scan specific targets
security-audit config-audit -t /path/to/project -t /etc

# Output as JSON (for automation)
security-audit full-audit -o json

# Interactive mode
security-audit -i

# Start continuous monitoring
security-audit monitor

# Verbose output
security-audit full-audit -v
```

## Scanners

### ConfigScanner

Scans configuration files and running services for security issues.

**Checks performed:**
- Default credentials for common services (MySQL, PostgreSQL, Redis, etc.)
- Exposed ports on all interfaces (0.0.0.0)
- Weak authentication settings
- Hardcoded secrets in config files
- Insecure environment variables

```typescript
const scanner = new ConfigScanner({
  targets: ['/app', '/etc', process.cwd()],
  excludePatterns: ['node_modules', '.git'],
  checkDefaultCredentials: true,
  checkExposedPorts: true,
  checkWeakAuth: true,
  maxDepth: 5
});
```

### NetworkMapper

Maps network topology and identifies exposure.

**Checks performed:**
- Host discovery (Docker, Kubernetes, local)
- Port scanning and service detection
- Unnecessary external exposure
- Unencrypted protocols on exposed ports
- Missing network segmentation

```typescript
const mapper = new NetworkMapper({
  discoverHosts: true,
  scanPorts: true,
  portRange: { start: 1, end: 65535 },
  detectServices: true,
  mapTopology: true
});

const result = await mapper.scan();
const topology = mapper.getTopology();
// topology.nodes, topology.edges, topology.zones
```

### ContainerScanner

Audits Docker container security.

**Checks performed:**
- Privileged containers
- Docker socket mounts
- Sensitive volume mounts
- Host network mode
- Dangerous capabilities (CAP_SYS_ADMIN, etc.)
- Secrets in environment variables
- Running as root
- Use of :latest tag
- Docker daemon configuration

```typescript
const scanner = new ContainerScanner({
  checkPrivileged: true,
  checkVolumes: true,
  checkNetwork: true,
  checkCapabilities: true,
  checkSecrets: true,
  checkImages: true
});
```

### AuthScanner

Reviews authentication and authorization setup.

**Checks performed:**
- Shared credentials across environments
- Weak passwords
- Missing MFA
- Insecure file permissions
- Stale credentials
- Service account issues
- SSH configuration
- API key management

```typescript
const scanner = new AuthScanner({
  targets: [process.cwd(), process.env.HOME],
  checkSharedCredentials: true,
  checkPasswordStrength: true,
  checkMFA: true,
  checkPermissions: true,
  checkCredentialAge: true,
  maxCredentialAgeDays: 90
});
```

### LogAnalyzer

Analyzes logs for security patterns and anomalies.

**Patterns detected:**
- Brute force attacks (SSH, generic auth failures)
- Privilege escalation attempts
- Data exfiltration indicators
- Lateral movement
- Unusual access patterns
- Web attacks (SQL injection, XSS, path traversal)
- IMSI/mobile tracking data

```typescript
const analyzer = new LogAnalyzer({
  logSources: [
    '/var/log/auth.log',
    '/var/log/syslog',
    '/var/log/nginx/access.log'
  ],
  timeRange: {
    start: new Date(Date.now() - 24 * 60 * 60 * 1000),
    end: new Date()
  },
  enableAnomalyDetection: true,
  baselineWindow: 7  // days
});
```

## Hybrid AI Processing

The agent uses a hybrid approach to balance privacy with capability:

### Local Processing (Data Stays On-Premise)

- Initial scan and data collection
- Classification of findings
- Risk scoring
- All sensitive data processing

### Cloud Processing (Sanitized Data Only)

- Pattern detection across findings
- Anomaly detection
- Correlation analysis
- Advanced threat intelligence

```typescript
import { HybridAIProcessor } from 'agent-squad';

const processor = new HybridAIProcessor(
  // Local model config
  {
    enabled: true,
    modelType: 'ollama',
    endpoint: 'http://localhost:11434',
    capabilities: ['scan', 'classify']
  },
  // Vertex AI config
  {
    enabled: true,
    projectId: 'my-project',
    location: 'us-central1',
    modelId: 'gemini-1.5-pro',
    useForPatternAnalysis: true,
    useForAnomalyDetection: true
  },
  // Sanitization config
  {
    enabled: true,
    preserveFormat: true
  }
);

await processor.initialize();
const analysis = await processor.processAuditResults(auditResults);
// analysis.insights, analysis.patterns, analysis.recommendations
```

## Continuous Monitoring

### Change Validation

Validates changes before deployment against security policies:

```typescript
// Built-in validation checks:
// - no_privileged_containers
// - no_public_database_ports
// - no_hardcoded_secrets
// - strong_auth_required
// - no_sensitive_mounts
// - no_latest_tag

// Add custom validation
monitor.addValidationCheck({
  name: 'require_resource_limits',
  check: async (change) => {
    if (change.changeType !== 'container') {
      return { passed: true, message: 'N/A' };
    }
    const hasLimits = change.newState.resources?.limits;
    return {
      passed: !!hasLimits,
      message: hasLimits ? 'Resource limits set' : 'Container must have resource limits'
    };
  },
  severity: 'medium'
});
```

### Dependency Tracking

Track service dependencies to understand blast radius:

```typescript
// Build dependency map from running infrastructure
const dependencyMap = await monitor.buildDependencyMap();

// Analyze impact before making changes
const impact = await monitor.analyzeImpact('database-service');
console.log(impact.directDependents);   // Services that directly depend on database
console.log(impact.indirectDependents); // Services affected transitively
console.log(impact.criticalPath);       // Is this a critical service?
console.log(impact.impactSummary);      // Human-readable summary

// Get all services affected if one fails
const affected = monitor.getAffectedServices('api-gateway');
```

## Data Sanitization

The `DataSanitizer` ensures sensitive data never leaves your infrastructure:

### Default Patterns Sanitized

- Passwords and secrets
- API keys and tokens
- AWS/Azure/GCP credentials
- Private keys
- Email addresses (partially)
- Phone numbers
- SSN/credit cards
- IMSI/IMEI numbers
- Internal IP addresses (partially)
- MAC addresses
- Internal hostnames
- File paths
- Database connection strings

### Custom Patterns

```typescript
import { DataSanitizer } from 'agent-squad';

const sanitizer = new DataSanitizer({
  enabled: true,
  preserveFormat: true,
  patterns: [
    // Add custom patterns
    {
      name: 'customer_id',
      pattern: /CUST-[A-Z0-9]{8}/g,
      replacement: '[CUSTOMER_ID_REDACTED]',
      category: 'pii'
    }
  ]
});

// Sanitize a string
const result = sanitizer.sanitizeString('password=secret123');
// result.sanitized = 'password=[REDACTED]'

// Sanitize an object
const sanitized = sanitizer.sanitizeObject(configData);
// sanitized.data - cleaned data
// sanitized.sanitizationLog - what was redacted

// Extract patterns for cloud analysis (no sensitive data)
const patterns = sanitizer.extractPatterns(data);
// patterns.structure - data structure
// patterns.types - type counts
// patterns.keyPatterns - key names (safe)
```

## API Reference

### SecurityAuditAgent

```typescript
class SecurityAuditAgent extends Agent {
  constructor(options: SecurityAuditAgentOptions);

  processRequest(
    inputText: string,
    userId: string,
    sessionId: string,
    chatHistory: ConversationMessage[],
    additionalParams?: Record<string, string>
  ): Promise<ConversationMessage>;

  runFullAudit(): Promise<string>;
  runConfigAudit(): Promise<string>;
  runNetworkMapping(): Promise<string>;
  runContainerScan(): Promise<string>;
  runAuthReview(): Promise<string>;
  runLogAnalysis(): Promise<string>;
  validateChange(params: Record<string, string>): Promise<string>;
  analyzeImpact(serviceId: string): Promise<string>;
  startMonitoring(): Promise<string>;
  stopMonitoring(): Promise<string>;
  getStatus(): string;
  getHelp(): string;
}
```

### Types

```typescript
enum SeverityLevel {
  CRITICAL = 'critical',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low',
  INFO = 'info'
}

enum ScanType {
  CONFIG_AUDIT = 'config_audit',
  NETWORK_MAPPING = 'network_mapping',
  CONTAINER_SECURITY = 'container_security',
  AUTH_REVIEW = 'auth_review',
  LOG_ANALYSIS = 'log_analysis',
  FULL_AUDIT = 'full_audit'
}

interface SecurityFinding {
  id: string;
  type: string;
  severity: SeverityLevel;
  title: string;
  description: string;
  location: string;
  evidence: string[];
  remediation: string;
  detectedAt: Date;
  status: 'open' | 'acknowledged' | 'mitigated' | 'false_positive';
}

interface AuditResult {
  auditId: string;
  scanType: ScanType;
  status: AuditStatus;
  startTime: Date;
  endTime?: Date;
  findings: SecurityFinding[];
  summary: AuditSummary;
}

interface ValidationResult {
  passed: boolean;
  errors: string[];
  warnings: string[];
  securityImpact: SeverityLevel;
}
```

## Examples

### CI/CD Integration

```yaml
# .github/workflows/security-audit.yml
name: Security Audit

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install dependencies
        run: npm ci

      - name: Run Security Audit
        run: npx security-audit full-audit -o json > audit-results.json

      - name: Check for Critical Findings
        run: |
          CRITICAL=$(jq '.response | match("Critical.*[1-9]") | length' audit-results.json)
          if [ "$CRITICAL" -gt 0 ]; then
            echo "Critical security findings detected!"
            exit 1
          fi

      - name: Upload Audit Results
        uses: actions/upload-artifact@v4
        with:
          name: security-audit-results
          path: audit-results.json
```

### Pre-Deployment Validation

```typescript
import { ContinuousMonitor } from 'agent-squad';

async function validateDeployment(deployment: any): Promise<boolean> {
  const monitor = new ContinuousMonitor();

  const result = await monitor.validateChange({
    id: `deploy-${Date.now()}`,
    timestamp: new Date(),
    changeType: 'deployment',
    resourceId: deployment.name,
    resourceType: 'kubernetes-deployment',
    previousState: {},
    newState: deployment.spec,
    validated: false
  });

  if (!result.passed) {
    console.error('Deployment blocked by security policy:');
    result.errors.forEach(err => console.error(`  - ${err}`));
    return false;
  }

  if (result.warnings.length > 0) {
    console.warn('Deployment warnings:');
    result.warnings.forEach(warn => console.warn(`  - ${warn}`));
  }

  return true;
}
```

### Slack Alert Integration

```typescript
import { SecurityAuditAgent, ContinuousMonitor } from 'agent-squad';

const agent = new SecurityAuditAgent({
  name: 'ProductionSecurityAgent',
  config: {
    monitoringConfig: {
      enabled: true,
      intervalSeconds: 300, // 5 minutes
      alertThresholds: [
        { metric: 'critical_findings', operator: 'gt', value: 0, severity: 'critical', cooldownSeconds: 3600 }
      ],
      notificationChannels: [
        {
          type: 'slack',
          config: {
            webhookUrl: process.env.SLACK_WEBHOOK_URL!
          },
          severityFilter: ['critical', 'high']
        }
      ]
    }
  }
});

// Start continuous monitoring
await agent.processRequest('start monitoring', 'system', 'monitor-session', []);
```

## Troubleshooting

### Common Issues

**Docker scanner returns no results:**
- Ensure Docker is running
- Check permissions: user must be in `docker` group or run as root

**Vertex AI not available:**
- Verify `GOOGLE_CLOUD_PROJECT` is set
- Run `gcloud auth application-default login`
- Check IAM permissions for Vertex AI API

**Local model not detected:**
- Ensure Ollama is running: `ollama serve`
- Check endpoint: `curl http://localhost:11434/api/tags`

**Permission denied on log files:**
- Run with appropriate permissions for log access
- Add user to relevant groups (adm, syslog)

### Debug Mode

```bash
# Enable verbose logging
security-audit full-audit -v

# Or programmatically
const agent = new SecurityAuditAgent({
  name: 'DebugAgent',
  LOG_AGENT_DEBUG_TRACE: true
});
```

## License

MIT License - see LICENSE file for details.

## Contributing

Contributions welcome! Please read CONTRIBUTING.md for guidelines.

## Security

To report security vulnerabilities, please email security@example.com or open a private security advisory.
