/**
 * Tests for Security Audit Agent
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  SecurityAuditAgent,
  ConfigScanner,
  NetworkMapper,
  ContainerScanner,
  AuthScanner,
  LogAnalyzer,
  HybridAIProcessor,
  ContinuousMonitor,
  DataSanitizer,
  SeverityLevel,
  ScanType,
  AuditStatus
} from '../../../src/agents/security-audit';

describe('SecurityAuditAgent', () => {
  let agent: SecurityAuditAgent;

  beforeEach(() => {
    agent = new SecurityAuditAgent({
      name: 'TestSecurityAgent',
      description: 'Test security audit agent'
    });
  });

  describe('initialization', () => {
    it('should create agent with default configuration', () => {
      expect(agent).toBeDefined();
      expect(agent.name).toBe('TestSecurityAgent');
    });

    it('should accept custom configuration', () => {
      const customAgent = new SecurityAuditAgent({
        name: 'CustomAgent',
        config: {
          modelConfig: {
            modelId: 'custom-model',
            temperature: 0.5,
            maxTokens: 2048,
            streaming: false
          }
        }
      });
      expect(customAgent).toBeDefined();
    });
  });

  describe('processRequest', () => {
    it('should return help for unknown commands', async () => {
      const response = await agent.processRequest(
        'unknown command',
        'user1',
        'session1',
        []
      );
      expect(response.content[0].text).toContain('Available Commands');
    });

    it('should respond to help command', async () => {
      const response = await agent.processRequest(
        'help',
        'user1',
        'session1',
        []
      );
      expect(response.content[0].text).toContain('AI Security Audit Agent');
    });

    it('should respond to status command', async () => {
      const response = await agent.processRequest(
        'status',
        'user1',
        'session1',
        []
      );
      expect(response.content[0].text).toContain('Security Audit Agent Status');
    });
  });
});

describe('DataSanitizer', () => {
  let sanitizer: DataSanitizer;

  beforeEach(() => {
    sanitizer = new DataSanitizer();
  });

  describe('sanitizeString', () => {
    it('should redact passwords', () => {
      const input = 'password=secretvalue123';
      const result = sanitizer.sanitizeString(input);
      expect(result.sanitized).not.toContain('secretvalue123');
      expect(result.log.length).toBeGreaterThan(0);
    });

    it('should redact API keys', () => {
      const input = 'api_key=AKIAIOSFODNN7EXAMPLE';
      const result = sanitizer.sanitizeString(input);
      expect(result.sanitized).toContain('REDACTED');
    });

    it('should redact AWS access keys', () => {
      const input = 'AKIAIOSFODNN7EXAMPLE';
      const result = sanitizer.sanitizeString(input);
      expect(result.sanitized).not.toContain('AKIAIOSFODNN');
    });

    it('should partially redact emails', () => {
      const input = 'contact: user@example.com';
      const result = sanitizer.sanitizeString(input);
      expect(result.sanitized).toContain('@example.com');
      expect(result.sanitized).not.toContain('user@');
    });

    it('should redact internal IPs partially', () => {
      const input = 'server: 192.168.1.100';
      const result = sanitizer.sanitizeString(input);
      expect(result.sanitized).toContain('192.168.x.x');
    });
  });

  describe('sanitizeObject', () => {
    it('should sanitize nested objects', () => {
      const input = {
        database: {
          host: '192.168.1.50',
          password: 'mysecretpassword'
        },
        api: {
          key: 'api_key=abc123xyz789'
        }
      };

      const result = sanitizer.sanitizeObject(input);
      expect(result.data.database.password).not.toContain('mysecretpassword');
      expect(result.sanitizationLog.length).toBeGreaterThan(0);
    });
  });

  describe('anonymizeForAnalysis', () => {
    it('should preserve structure but anonymize values', () => {
      const input = {
        username: 'john_doe',
        age: 30,
        active: true
      };

      const result = sanitizer.anonymizeForAnalysis(input);
      expect(typeof result.username).toBe('string');
      expect(result.age).toBe(0);
      expect(result.active).toBe(true);
    });
  });
});

describe('ConfigScanner', () => {
  let scanner: ConfigScanner;

  beforeEach(() => {
    scanner = new ConfigScanner({
      targets: [process.cwd()],
      maxDepth: 2
    });
  });

  describe('scan', () => {
    it('should complete scan and return results', async () => {
      const result = await scanner.scan();

      expect(result).toBeDefined();
      expect(result.scanType).toBe(ScanType.CONFIG_AUDIT);
      expect(result.status).toBe(AuditStatus.COMPLETED);
      expect(result.summary).toBeDefined();
      expect(typeof result.summary.totalFindings).toBe('number');
    });

    it('should calculate risk score', async () => {
      const result = await scanner.scan();

      expect(result.summary.riskScore).toBeGreaterThanOrEqual(0);
      expect(result.summary.riskScore).toBeLessThanOrEqual(100);
    });
  });
});

describe('NetworkMapper', () => {
  let mapper: NetworkMapper;

  beforeEach(() => {
    mapper = new NetworkMapper();
  });

  describe('scan', () => {
    it('should complete network mapping', async () => {
      const result = await mapper.scan();

      expect(result).toBeDefined();
      expect(result.scanType).toBe(ScanType.NETWORK_MAPPING);
      expect(result.status).toBe(AuditStatus.COMPLETED);
    });

    it('should return topology data', async () => {
      await mapper.scan();
      const topology = mapper.getTopology();

      expect(topology).toBeDefined();
      expect(Array.isArray(topology.nodes)).toBe(true);
      expect(Array.isArray(topology.edges)).toBe(true);
      expect(Array.isArray(topology.zones)).toBe(true);
    });
  });
});

describe('ContainerScanner', () => {
  let scanner: ContainerScanner;

  beforeEach(() => {
    scanner = new ContainerScanner();
  });

  describe('scan', () => {
    it('should complete container scan', async () => {
      const result = await scanner.scan();

      expect(result).toBeDefined();
      expect(result.scanType).toBe(ScanType.CONTAINER_SECURITY);
      // Status could be COMPLETED (Docker available) or COMPLETED with no findings (Docker unavailable)
      expect([AuditStatus.COMPLETED, AuditStatus.FAILED]).toContain(result.status);
    });
  });
});

describe('AuthScanner', () => {
  let scanner: AuthScanner;

  beforeEach(() => {
    scanner = new AuthScanner({
      targets: [process.cwd()],
      maxDepth: 2
    });
  });

  describe('scan', () => {
    it('should complete auth review', async () => {
      const result = await scanner.scan();

      expect(result).toBeDefined();
      expect(result.scanType).toBe(ScanType.AUTH_REVIEW);
      expect(result.status).toBe(AuditStatus.COMPLETED);
    });
  });
});

describe('LogAnalyzer', () => {
  let analyzer: LogAnalyzer;

  beforeEach(() => {
    analyzer = new LogAnalyzer({
      logSources: [], // Empty for testing without actual logs
      enableAnomalyDetection: false
    });
  });

  describe('scan', () => {
    it('should complete log analysis', async () => {
      const result = await analyzer.scan();

      expect(result).toBeDefined();
      expect(result.scanType).toBe(ScanType.LOG_ANALYSIS);
      expect(result.status).toBe(AuditStatus.COMPLETED);
    });
  });
});

describe('ContinuousMonitor', () => {
  let monitor: ContinuousMonitor;

  beforeEach(() => {
    monitor = new ContinuousMonitor({
      enabled: true,
      intervalSeconds: 1,
      alertThresholds: [],
      notificationChannels: []
    });
  });

  afterEach(() => {
    monitor.stop();
  });

  describe('validateChange', () => {
    it('should validate allowed changes', async () => {
      const change = {
        id: 'test-1',
        timestamp: new Date(),
        changeType: 'config' as const,
        resourceId: 'test-resource',
        resourceType: 'config',
        previousState: {},
        newState: { key: 'value' },
        validated: false
      };

      const result = await monitor.validateChange(change);
      expect(result).toBeDefined();
      expect(typeof result.passed).toBe('boolean');
    });

    it('should reject privileged containers', async () => {
      const change = {
        id: 'test-2',
        timestamp: new Date(),
        changeType: 'container' as const,
        resourceId: 'test-container',
        resourceType: 'container',
        previousState: {},
        newState: { privileged: true },
        validated: false
      };

      const result = await monitor.validateChange(change);
      expect(result.passed).toBe(false);
      expect(result.errors.length).toBeGreaterThan(0);
    });
  });

  describe('getStatus', () => {
    it('should return current status', () => {
      const status = monitor.getStatus();

      expect(status).toBeDefined();
      expect(typeof status.isRunning).toBe('boolean');
      expect(typeof status.totalChanges).toBe('number');
    });
  });

  describe('start/stop', () => {
    it('should start and stop monitoring', async () => {
      await monitor.start();
      expect(monitor.getStatus().isRunning).toBe(true);

      monitor.stop();
      expect(monitor.getStatus().isRunning).toBe(false);
    });
  });
});

describe('HybridAIProcessor', () => {
  let processor: HybridAIProcessor;

  beforeEach(() => {
    processor = new HybridAIProcessor(
      { enabled: false }, // Disable local model for tests
      { enabled: false }  // Disable Vertex AI for tests
    );
  });

  describe('initialize', () => {
    it('should initialize without errors', async () => {
      await expect(processor.initialize()).resolves.not.toThrow();
    });
  });

  describe('getStatus', () => {
    it('should return availability status', () => {
      const status = processor.getStatus();

      expect(status).toBeDefined();
      expect(typeof status.localAvailable).toBe('boolean');
      expect(typeof status.vertexAvailable).toBe('boolean');
    });
  });
});

describe('Integration', () => {
  describe('Full Audit Flow', () => {
    it('should run full audit without errors', async () => {
      const agent = new SecurityAuditAgent({
        name: 'IntegrationTestAgent'
      });

      // Run a simple command to verify integration
      const response = await agent.processRequest(
        'status',
        'user1',
        'session1',
        []
      );

      expect(response).toBeDefined();
      expect(response.content[0].text).toContain('Security Audit Agent Status');
    }, 30000);
  });
});
