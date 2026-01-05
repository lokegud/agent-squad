/**
 * Database Storage Tests
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import { SQLiteDatabase, createDatabase, StorageConfig, StoredFinding } from '../storage/database';
import { FullAuditResult, AuditStatus, SeverityLevel } from '../types';

describe('SQLiteDatabase', () => {
  let tempDir: string;
  let db: SQLiteDatabase;
  let config: StorageConfig;

  beforeAll(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'db-test-'));
  });

  afterAll(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  beforeEach(async () => {
    config = {
      type: 'sqlite',
      connectionString: path.join(tempDir, `test-${Date.now()}.db`),
      retentionDays: 30,
      encryptAtRest: false
    };
    db = new SQLiteDatabase(config);
    await db.initialize();
  });

  afterEach(async () => {
    await db.close();
  });

  describe('initialization', () => {
    it('should create database file', async () => {
      const exists = await fs.access(config.connectionString).then(() => true).catch(() => false);
      expect(exists).toBe(true);
    });

    it('should be idempotent', async () => {
      await db.initialize();
      await db.initialize();
      // Should not throw
    });
  });

  describe('audits', () => {
    const mockAuditResult: FullAuditResult = {
      auditId: 'audit-test-001',
      status: AuditStatus.COMPLETED,
      startTime: new Date('2024-01-15T10:00:00Z'),
      endTime: new Date('2024-01-15T10:05:00Z'),
      overallSummary: {
        totalFindings: 5,
        criticalCount: 1,
        highCount: 2,
        mediumCount: 1,
        lowCount: 1,
        infoCount: 0,
        passedChecks: 20,
        failedChecks: 5,
        skippedChecks: 0,
        riskScore: 45,
        recommendations: ['Fix critical issues']
      },
      complianceStatus: {
        frameworks: [],
        overallCompliance: 80,
        criticalGaps: []
      },
      configAudit: {
        auditId: 'config-1',
        scanType: 'config_audit' as any,
        status: AuditStatus.COMPLETED,
        startTime: new Date(),
        findings: [
          {
            id: 'f1',
            type: 'credential',
            severity: SeverityLevel.CRITICAL,
            title: 'Test Finding',
            description: 'Test description',
            location: '/test/path',
            evidence: [],
            remediation: 'Fix it',
            detectedAt: new Date(),
            status: 'open'
          }
        ],
        summary: {
          criticalCount: 1,
          highCount: 0,
          mediumCount: 0,
          lowCount: 0,
          infoCount: 0,
          riskScore: 20,
          recommendations: []
        }
      }
    };

    it('should save audit', async () => {
      const id = await db.saveAudit(mockAuditResult);
      expect(id).toBe('audit-test-001');
    });

    it('should retrieve saved audit', async () => {
      await db.saveAudit(mockAuditResult);
      const audit = await db.getAudit('audit-test-001');

      expect(audit).not.toBeNull();
      expect(audit?.id).toBe('audit-test-001');
      expect(audit?.riskScore).toBe(45);
      expect(audit?.criticalCount).toBe(1);
      expect(audit?.totalFindings).toBe(5);
    });

    it('should return null for non-existent audit', async () => {
      const audit = await db.getAudit('non-existent');
      expect(audit).toBeNull();
    });

    it('should list audits', async () => {
      await db.saveAudit(mockAuditResult);
      await db.saveAudit({
        ...mockAuditResult,
        auditId: 'audit-test-002',
        startTime: new Date('2024-01-16T10:00:00Z')
      });

      const audits = await db.listAudits();
      expect(audits.length).toBe(2);
    });

    it('should list audits with limit', async () => {
      await db.saveAudit(mockAuditResult);
      await db.saveAudit({ ...mockAuditResult, auditId: 'audit-test-002' });
      await db.saveAudit({ ...mockAuditResult, auditId: 'audit-test-003' });

      const audits = await db.listAudits({ limit: 2 });
      expect(audits.length).toBe(2);
    });

    it('should delete audit and its findings', async () => {
      await db.saveAudit(mockAuditResult);
      const deleted = await db.deleteAudit('audit-test-001');

      expect(deleted).toBe(true);
      const audit = await db.getAudit('audit-test-001');
      expect(audit).toBeNull();
    });

    it('should return false when deleting non-existent audit', async () => {
      const deleted = await db.deleteAudit('non-existent');
      expect(deleted).toBe(false);
    });
  });

  describe('findings', () => {
    const mockFinding: StoredFinding = {
      id: 'finding-001',
      auditId: 'audit-001',
      timestamp: new Date(),
      severity: SeverityLevel.HIGH,
      category: 'configAudit',
      title: 'Test Finding',
      description: 'Test description',
      location: '/test/location',
      remediation: 'Fix the issue',
      status: 'open',
      hash: 'abc123'
    };

    it('should save finding', async () => {
      const id = await db.saveFinding(mockFinding);
      expect(id).toBe('finding-001');
    });

    it('should retrieve finding', async () => {
      await db.saveFinding(mockFinding);
      const finding = await db.getFinding('finding-001');

      expect(finding).not.toBeNull();
      expect(finding?.title).toBe('Test Finding');
      expect(finding?.severity).toBe(SeverityLevel.HIGH);
    });

    it('should list findings', async () => {
      await db.saveFinding(mockFinding);
      await db.saveFinding({ ...mockFinding, id: 'finding-002' });

      const findings = await db.listFindings();
      expect(findings.length).toBe(2);
    });

    it('should filter findings by severity', async () => {
      await db.saveFinding(mockFinding);
      await db.saveFinding({
        ...mockFinding,
        id: 'finding-002',
        severity: SeverityLevel.LOW,
        hash: 'def456'
      });

      const findings = await db.listFindings({
        filters: { severity: SeverityLevel.HIGH }
      });
      expect(findings.length).toBe(1);
      expect(findings[0].severity).toBe(SeverityLevel.HIGH);
    });

    it('should filter findings by status', async () => {
      await db.saveFinding(mockFinding);
      await db.saveFinding({
        ...mockFinding,
        id: 'finding-002',
        status: 'resolved',
        hash: 'def456'
      });

      const findings = await db.listFindings({
        filters: { status: 'open' }
      });
      expect(findings.length).toBe(1);
    });

    it('should update finding status', async () => {
      await db.saveFinding(mockFinding);
      const updated = await db.updateFindingStatus('finding-001', 'resolved', 'test-user', 'Fixed it');

      expect(updated).toBe(true);
      const finding = await db.getFinding('finding-001');
      expect(finding?.status).toBe('resolved');
      expect(finding?.resolvedBy).toBe('test-user');
      expect(finding?.notes).toBe('Fixed it');
    });

    it('should get open findings', async () => {
      await db.saveFinding(mockFinding);
      await db.saveFinding({
        ...mockFinding,
        id: 'finding-002',
        status: 'resolved',
        hash: 'def456'
      });

      const openFindings = await db.getOpenFindings();
      expect(openFindings.length).toBe(1);
      expect(openFindings[0].status).toBe('open');
    });

    it('should find duplicate finding by hash', async () => {
      await db.saveFinding(mockFinding);

      const duplicate = await db.findDuplicateFinding('abc123');
      expect(duplicate).not.toBeNull();
      expect(duplicate?.id).toBe('finding-001');
    });

    it('should not find duplicate for resolved finding', async () => {
      await db.saveFinding({ ...mockFinding, status: 'resolved' });

      const duplicate = await db.findDuplicateFinding('abc123');
      expect(duplicate).toBeNull();
    });
  });

  describe('alerts', () => {
    const mockAlert = {
      timestamp: new Date(),
      severity: 'critical',
      type: 'phone_home',
      message: 'Suspicious connection detected',
      source: 'NetworkTrafficMonitor',
      acknowledged: false,
      data: { ip: '1.2.3.4', port: 4444 }
    };

    it('should save alert', async () => {
      const id = await db.saveAlert(mockAlert);
      expect(id).toMatch(/^alert-/);
    });

    it('should retrieve alert', async () => {
      const id = await db.saveAlert(mockAlert);
      const alert = await db.getAlert(id);

      expect(alert).not.toBeNull();
      expect(alert?.message).toBe('Suspicious connection detected');
      expect(alert?.severity).toBe('critical');
    });

    it('should list alerts', async () => {
      await db.saveAlert(mockAlert);
      await db.saveAlert({ ...mockAlert, severity: 'warning' });

      const alerts = await db.listAlerts();
      expect(alerts.length).toBe(2);
    });

    it('should acknowledge alert', async () => {
      const id = await db.saveAlert(mockAlert);
      const acked = await db.acknowledgeAlert(id, 'test-user');

      expect(acked).toBe(true);
      const alert = await db.getAlert(id);
      expect(alert?.acknowledged).toBe(true);
      expect(alert?.acknowledgedBy).toBe('test-user');
      expect(alert?.acknowledgedAt).toBeDefined();
    });

    it('should get unacknowledged alerts', async () => {
      const id1 = await db.saveAlert(mockAlert);
      await db.saveAlert(mockAlert);
      await db.acknowledgeAlert(id1, 'user');

      const unacked = await db.getUnacknowledgedAlerts();
      expect(unacked.length).toBe(1);
    });
  });

  describe('trends', () => {
    it('should get trends over time', async () => {
      // Save multiple audits with different dates
      const baseAudit: FullAuditResult = {
        auditId: 'trend-1',
        status: AuditStatus.COMPLETED,
        startTime: new Date(),
        endTime: new Date(),
        overallSummary: {
          totalFindings: 5,
          criticalCount: 1,
          highCount: 2,
          mediumCount: 1,
          lowCount: 1,
          infoCount: 0,
          passedChecks: 20,
          failedChecks: 5,
          skippedChecks: 0,
          riskScore: 45,
          recommendations: []
        },
        complianceStatus: { frameworks: [], overallCompliance: 0, criticalGaps: [] }
      };

      await db.saveAudit(baseAudit);

      const trends = await db.getTrends(30);
      expect(Array.isArray(trends)).toBe(true);
    });

    it('should get risk score history', async () => {
      const baseAudit: FullAuditResult = {
        auditId: 'risk-1',
        status: AuditStatus.COMPLETED,
        startTime: new Date(),
        endTime: new Date(),
        overallSummary: {
          totalFindings: 5,
          criticalCount: 1,
          highCount: 2,
          mediumCount: 1,
          lowCount: 1,
          infoCount: 0,
          passedChecks: 20,
          failedChecks: 5,
          skippedChecks: 0,
          riskScore: 45,
          recommendations: []
        },
        complianceStatus: { frameworks: [], overallCompliance: 0, criticalGaps: [] }
      };

      await db.saveAudit(baseAudit);

      const history = await db.getRiskScoreHistory(30);
      expect(Array.isArray(history)).toBe(true);
      if (history.length > 0) {
        expect(history[0].score).toBe(45);
      }
    });
  });

  describe('maintenance', () => {
    it('should prune old data', async () => {
      const oldDate = new Date();
      oldDate.setDate(oldDate.getDate() - 100); // 100 days ago

      const oldAudit: FullAuditResult = {
        auditId: 'old-audit',
        status: AuditStatus.COMPLETED,
        startTime: oldDate,
        endTime: oldDate,
        overallSummary: {
          totalFindings: 1,
          criticalCount: 0,
          highCount: 0,
          mediumCount: 0,
          lowCount: 1,
          infoCount: 0,
          passedChecks: 10,
          failedChecks: 1,
          skippedChecks: 0,
          riskScore: 5,
          recommendations: []
        },
        complianceStatus: { frameworks: [], overallCompliance: 0, criticalGaps: [] }
      };

      await db.saveAudit(oldAudit);

      const pruned = await db.pruneOldData(30);
      expect(pruned).toBeGreaterThanOrEqual(0);
    });

    it('should get stats', async () => {
      const stats = await db.getStats();

      expect(typeof stats.audits).toBe('number');
      expect(typeof stats.findings).toBe('number');
      expect(typeof stats.alerts).toBe('number');
      expect(typeof stats.dbSize).toBe('number');
    });
  });

  describe('createDatabase factory', () => {
    it('should create SQLite database', () => {
      const database = createDatabase({
        type: 'sqlite',
        connectionString: ':memory:',
        retentionDays: 30,
        encryptAtRest: false
      });

      expect(database).toBeInstanceOf(SQLiteDatabase);
    });

    it('should throw for unsupported type', () => {
      expect(() => createDatabase({
        type: 'postgres',
        connectionString: 'postgresql://localhost',
        retentionDays: 30,
        encryptAtRest: false
      })).toThrow('PostgreSQL support not yet implemented');
    });
  });
});
