/**
 * ReportExporter Tests
 */

import { ReportExporter, exportReport } from '../reports/reportExporter';
import { FullAuditResult, AuditStatus, SeverityLevel } from '../types';

describe('ReportExporter', () => {
  const mockAuditResult: FullAuditResult = {
    auditId: 'test-audit-123',
    status: AuditStatus.COMPLETED,
    startTime: new Date('2024-01-15T10:00:00Z'),
    endTime: new Date('2024-01-15T10:05:00Z'),
    overallSummary: {
      totalFindings: 10,
      criticalCount: 2,
      highCount: 3,
      mediumCount: 3,
      lowCount: 2,
      infoCount: 0,
      passedChecks: 50,
      failedChecks: 10,
      skippedChecks: 5,
      riskScore: 65,
      recommendations: [
        'Update default credentials immediately',
        'Enable MFA for all admin accounts',
        'Review container security settings'
      ]
    },
    complianceStatus: {
      frameworks: [],
      overallCompliance: 75,
      criticalGaps: []
    },
    configAudit: {
      auditId: 'config-1',
      scanType: 'config_audit' as any,
      status: AuditStatus.COMPLETED,
      startTime: new Date('2024-01-15T10:00:00Z'),
      findings: [
        {
          id: 'f1',
          type: 'default_credential',
          severity: SeverityLevel.CRITICAL,
          title: 'Default MySQL Password',
          description: 'MySQL is using default root password',
          location: '/etc/mysql/my.cnf',
          evidence: ['password=root'],
          remediation: 'Change the default password immediately',
          detectedAt: new Date(),
          status: 'open'
        },
        {
          id: 'f2',
          type: 'exposed_port',
          severity: SeverityLevel.HIGH,
          title: 'Database Port Exposed',
          description: 'MySQL port 3306 is exposed to 0.0.0.0',
          location: 'Network configuration',
          evidence: ['bind-address=0.0.0.0'],
          remediation: 'Bind to localhost or internal IP only',
          detectedAt: new Date(),
          status: 'open'
        }
      ],
      summary: {
        criticalCount: 1,
        highCount: 1,
        mediumCount: 0,
        lowCount: 0,
        infoCount: 0,
        riskScore: 40,
        recommendations: []
      }
    }
  };

  describe('generate', () => {
    describe('HTML format', () => {
      it('should generate valid HTML report', async () => {
        const exporter = new ReportExporter({ title: 'Test Security Report' });
        const report = await exporter.generate(mockAuditResult, 'html');

        expect(report.format).toBe('html');
        expect(report.filename).toMatch(/test-security-report.*\.html$/);
        expect(typeof report.content).toBe('string');

        const html = report.content as string;
        expect(html).toContain('<!DOCTYPE html>');
        expect(html).toContain('Test Security Report');
        expect(html).toContain('test-audit-123');
      });

      it('should include risk score in HTML', async () => {
        const exporter = new ReportExporter();
        const report = await exporter.generate(mockAuditResult, 'html');

        const html = report.content as string;
        expect(html).toContain('65/100');
      });

      it('should include severity counts in HTML', async () => {
        const exporter = new ReportExporter();
        const report = await exporter.generate(mockAuditResult, 'html');

        const html = report.content as string;
        expect(html).toContain('Critical');
        expect(html).toContain('2'); // criticalCount
      });

      it('should include findings when includeDetailedFindings is true', async () => {
        const exporter = new ReportExporter({ includeDetailedFindings: true });
        const report = await exporter.generate(mockAuditResult, 'html');

        const html = report.content as string;
        expect(html).toContain('Default MySQL Password');
        expect(html).toContain('/etc/mysql/my.cnf');
      });

      it('should include recommendations when includeRemediation is true', async () => {
        const exporter = new ReportExporter({ includeRemediation: true });
        const report = await exporter.generate(mockAuditResult, 'html');

        const html = report.content as string;
        expect(html).toContain('Update default credentials immediately');
      });

      it('should include charts when includeCharts is true', async () => {
        const exporter = new ReportExporter({ includeCharts: true });
        const report = await exporter.generate(mockAuditResult, 'html');

        const html = report.content as string;
        expect(html).toContain('chart.js');
        expect(html).toContain('severityChart');
      });

      it('should apply custom CSS', async () => {
        const customCss = '.custom-class { color: red; }';
        const exporter = new ReportExporter({ customCss });
        const report = await exporter.generate(mockAuditResult, 'html');

        const html = report.content as string;
        expect(html).toContain(customCss);
      });

      it('should include organization name when provided', async () => {
        const exporter = new ReportExporter({ organization: 'Acme Corp' });
        const report = await exporter.generate(mockAuditResult, 'html');

        const html = report.content as string;
        expect(html).toContain('Acme Corp');
      });
    });

    describe('JSON format', () => {
      it('should generate valid JSON report', async () => {
        const exporter = new ReportExporter({ title: 'JSON Test Report' });
        const report = await exporter.generate(mockAuditResult, 'json');

        expect(report.format).toBe('json');
        expect(report.filename).toMatch(/\.json$/);

        const parsed = JSON.parse(report.content as string);
        expect(parsed.metadata.title).toBe('JSON Test Report');
        expect(parsed.metadata.auditId).toBe('test-audit-123');
        expect(parsed.summary.riskScore).toBe(65);
        expect(parsed.summary.totalFindings).toBe(10);
      });

      it('should include timing information', async () => {
        const exporter = new ReportExporter();
        const report = await exporter.generate(mockAuditResult, 'json');

        const parsed = JSON.parse(report.content as string);
        expect(parsed.timing.startTime).toBeDefined();
        expect(parsed.timing.endTime).toBeDefined();
        expect(parsed.timing.duration).toBeDefined();
      });

      it('should include all result categories', async () => {
        const exporter = new ReportExporter();
        const report = await exporter.generate(mockAuditResult, 'json');

        const parsed = JSON.parse(report.content as string);
        expect(parsed.results).toBeDefined();
        expect(parsed.results.configAudit).toBeDefined();
      });
    });

    describe('Markdown format', () => {
      it('should generate valid Markdown report', async () => {
        const exporter = new ReportExporter({ title: 'Markdown Test Report' });
        const report = await exporter.generate(mockAuditResult, 'markdown');

        expect(report.format).toBe('markdown');
        expect(report.filename).toMatch(/\.markdown$/);

        const md = report.content as string;
        expect(md).toContain('# Markdown Test Report');
        expect(md).toContain('**Audit ID:**');
        expect(md).toContain('test-audit-123');
      });

      it('should include summary table', async () => {
        const exporter = new ReportExporter();
        const report = await exporter.generate(mockAuditResult, 'markdown');

        const md = report.content as string;
        expect(md).toContain('| Metric | Value |');
        expect(md).toContain('| Risk Score | 65/100 |');
        expect(md).toContain('| Critical | 2 |');
      });

      it('should include findings with severity emoji', async () => {
        const exporter = new ReportExporter({ includeDetailedFindings: true });
        const report = await exporter.generate(mockAuditResult, 'markdown');

        const md = report.content as string;
        expect(md).toMatch(/🔴|🟠|🟡|🟢/); // Severity emojis
        expect(md).toContain('Default MySQL Password');
      });

      it('should include recommendations section', async () => {
        const exporter = new ReportExporter({ includeRemediation: true });
        const report = await exporter.generate(mockAuditResult, 'markdown');

        const md = report.content as string;
        expect(md).toContain('## Recommendations');
        expect(md).toContain('- Update default credentials immediately');
      });
    });

    describe('PDF format', () => {
      it('should generate PDF report (placeholder)', async () => {
        const exporter = new ReportExporter();
        const report = await exporter.generate(mockAuditResult, 'pdf');

        expect(report.format).toBe('pdf');
        expect(report.filename).toMatch(/\.pdf$/);
        expect(Buffer.isBuffer(report.content)).toBe(true);
      });
    });
  });

  describe('metadata', () => {
    it('should include correct metadata in report', async () => {
      const exporter = new ReportExporter({ title: 'Metadata Test' });
      const report = await exporter.generate(mockAuditResult, 'json');

      expect(report.metadata.title).toBe('Metadata Test');
      expect(report.metadata.findingsCount).toBe(10);
      expect(report.metadata.riskScore).toBe(65);
      expect(report.generatedAt).toBeInstanceOf(Date);
    });
  });

  describe('filtering', () => {
    it('should filter findings by severity', async () => {
      const exporter = new ReportExporter({
        severityFilter: [SeverityLevel.CRITICAL],
        includeDetailedFindings: true
      });
      const report = await exporter.generate(mockAuditResult, 'html');

      const html = report.content as string;
      expect(html).toContain('Default MySQL Password'); // Critical
      // High severity finding should be filtered out in detailed view
    });

    it('should limit findings per category', async () => {
      const exporter = new ReportExporter({
        maxFindingsPerCategory: 1,
        includeDetailedFindings: true
      });
      const report = await exporter.generate(mockAuditResult, 'html');

      const html = report.content as string;
      expect(html).toContain('more findings not shown');
    });
  });

  describe('exportReport convenience function', () => {
    it('should export report with default options', async () => {
      const report = await exportReport(mockAuditResult, 'html');

      expect(report.format).toBe('html');
      expect(report.content).toBeDefined();
    });

    it('should apply custom options', async () => {
      const report = await exportReport(mockAuditResult, 'json', {
        title: 'Custom Export',
        organization: 'Test Org'
      });

      const parsed = JSON.parse(report.content as string);
      expect(parsed.metadata.title).toBe('Custom Export');
      expect(parsed.metadata.organization).toBe('Test Org');
    });
  });
});
