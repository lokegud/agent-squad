/**
 * Report Exporter
 *
 * Generates security audit reports in multiple formats:
 * - HTML: Interactive web reports with charts
 * - PDF: Print-ready documents for stakeholders
 * - JSON: Machine-readable for automation
 * - Markdown: Documentation-friendly format
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { FullAuditResult, AuditResult, SeverityLevel, Finding } from '../types';

// ============================================================================
// Types
// ============================================================================

export interface ReportOptions {
  /** Report title */
  title?: string;
  /** Organization name */
  organization?: string;
  /** Report author */
  author?: string;
  /** Include executive summary */
  includeExecutiveSummary?: boolean;
  /** Include detailed findings */
  includeDetailedFindings?: boolean;
  /** Include remediation steps */
  includeRemediation?: boolean;
  /** Include charts/graphs (HTML only) */
  includeCharts?: boolean;
  /** Include raw data appendix */
  includeRawData?: boolean;
  /** Logo URL or base64 */
  logo?: string;
  /** Custom CSS (HTML only) */
  customCss?: string;
  /** Severity filter - only include these severities */
  severityFilter?: SeverityLevel[];
  /** Maximum findings to include per category */
  maxFindingsPerCategory?: number;
}

export interface GeneratedReport {
  format: 'html' | 'pdf' | 'json' | 'markdown';
  content: Buffer | string;
  filename: string;
  generatedAt: Date;
  metadata: {
    title: string;
    findingsCount: number;
    riskScore: number;
  };
}

// ============================================================================
// HTML Templates
// ============================================================================

const HTML_TEMPLATE = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{{title}}</title>
  <style>
    :root {
      --critical: #dc2626;
      --high: #ea580c;
      --medium: #ca8a04;
      --low: #16a34a;
      --info: #2563eb;
      --bg: #f8fafc;
      --card-bg: #ffffff;
      --text: #1e293b;
      --text-muted: #64748b;
      --border: #e2e8f0;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      padding: 2rem;
    }

    .container { max-width: 1200px; margin: 0 auto; }

    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 2rem;
      padding-bottom: 1rem;
      border-bottom: 2px solid var(--border);
    }

    header h1 { font-size: 1.75rem; }
    header .meta { color: var(--text-muted); font-size: 0.875rem; }

    .card {
      background: var(--card-bg);
      border-radius: 0.5rem;
      padding: 1.5rem;
      margin-bottom: 1.5rem;
      box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }

    .card h2 {
      font-size: 1.25rem;
      margin-bottom: 1rem;
      padding-bottom: 0.5rem;
      border-bottom: 1px solid var(--border);
    }

    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
      margin-bottom: 1.5rem;
    }

    .stat-card {
      background: var(--card-bg);
      border-radius: 0.5rem;
      padding: 1.25rem;
      text-align: center;
      box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }

    .stat-card .value {
      font-size: 2.5rem;
      font-weight: 700;
      line-height: 1;
    }

    .stat-card .label {
      color: var(--text-muted);
      font-size: 0.875rem;
      margin-top: 0.5rem;
    }

    .stat-card.critical .value { color: var(--critical); }
    .stat-card.high .value { color: var(--high); }
    .stat-card.medium .value { color: var(--medium); }
    .stat-card.low .value { color: var(--low); }

    .risk-score {
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      font-size: 1.5rem;
      font-weight: 700;
    }

    .risk-score.critical { color: var(--critical); }
    .risk-score.high { color: var(--high); }
    .risk-score.medium { color: var(--medium); }
    .risk-score.low { color: var(--low); }

    .severity-badge {
      display: inline-block;
      padding: 0.25rem 0.75rem;
      border-radius: 9999px;
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
    }

    .severity-badge.critical { background: #fef2f2; color: var(--critical); }
    .severity-badge.high { background: #fff7ed; color: var(--high); }
    .severity-badge.medium { background: #fefce8; color: var(--medium); }
    .severity-badge.low { background: #f0fdf4; color: var(--low); }
    .severity-badge.info { background: #eff6ff; color: var(--info); }

    .finding {
      border: 1px solid var(--border);
      border-radius: 0.5rem;
      margin-bottom: 1rem;
      overflow: hidden;
    }

    .finding-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 1rem;
      background: var(--bg);
      cursor: pointer;
    }

    .finding-header h3 {
      font-size: 1rem;
      font-weight: 600;
    }

    .finding-body {
      padding: 1rem;
      border-top: 1px solid var(--border);
    }

    .finding-body dt {
      font-weight: 600;
      color: var(--text-muted);
      font-size: 0.75rem;
      text-transform: uppercase;
      margin-top: 0.75rem;
    }

    .finding-body dd {
      margin-top: 0.25rem;
    }

    .finding-body code {
      background: var(--bg);
      padding: 0.125rem 0.375rem;
      border-radius: 0.25rem;
      font-size: 0.875rem;
    }

    .chart-container {
      height: 300px;
      margin: 1rem 0;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.875rem;
    }

    th, td {
      padding: 0.75rem;
      text-align: left;
      border-bottom: 1px solid var(--border);
    }

    th {
      background: var(--bg);
      font-weight: 600;
      color: var(--text-muted);
      text-transform: uppercase;
      font-size: 0.75rem;
    }

    .recommendations li {
      margin-bottom: 0.5rem;
      padding-left: 1.5rem;
      position: relative;
    }

    .recommendations li::before {
      content: "→";
      position: absolute;
      left: 0;
      color: var(--info);
    }

    footer {
      margin-top: 3rem;
      padding-top: 1rem;
      border-top: 1px solid var(--border);
      color: var(--text-muted);
      font-size: 0.75rem;
      text-align: center;
    }

    @media print {
      body { padding: 0; background: white; }
      .card { box-shadow: none; border: 1px solid var(--border); }
      .finding { page-break-inside: avoid; }
    }

    {{customCss}}
  </style>
  {{chartScripts}}
</head>
<body>
  <div class="container">
    {{content}}
  </div>
</body>
</html>
`;

// ============================================================================
// Report Exporter Implementation
// ============================================================================

export class ReportExporter {
  private options: ReportOptions;

  constructor(options?: ReportOptions) {
    this.options = {
      title: options?.title || 'Security Audit Report',
      organization: options?.organization || '',
      author: options?.author || 'Security Audit Agent',
      includeExecutiveSummary: options?.includeExecutiveSummary ?? true,
      includeDetailedFindings: options?.includeDetailedFindings ?? true,
      includeRemediation: options?.includeRemediation ?? true,
      includeCharts: options?.includeCharts ?? true,
      includeRawData: options?.includeRawData ?? false,
      logo: options?.logo,
      customCss: options?.customCss || '',
      severityFilter: options?.severityFilter,
      maxFindingsPerCategory: options?.maxFindingsPerCategory || 50
    };
  }

  /**
   * Generate report in specified format
   */
  async generate(
    result: FullAuditResult,
    format: 'html' | 'pdf' | 'json' | 'markdown'
  ): Promise<GeneratedReport> {
    const generatedAt = new Date();
    const filename = this.generateFilename(result, format);

    let content: Buffer | string;

    switch (format) {
      case 'html':
        content = this.generateHtml(result);
        break;
      case 'pdf':
        content = await this.generatePdf(result);
        break;
      case 'json':
        content = this.generateJson(result);
        break;
      case 'markdown':
        content = this.generateMarkdown(result);
        break;
    }

    return {
      format,
      content,
      filename,
      generatedAt,
      metadata: {
        title: this.options.title!,
        findingsCount: result.overallSummary.totalFindings,
        riskScore: result.overallSummary.riskScore
      }
    };
  }

  /**
   * Save report to file
   */
  async saveToFile(report: GeneratedReport, outputPath: string): Promise<string> {
    const fullPath = path.join(outputPath, report.filename);
    await fs.mkdir(path.dirname(fullPath), { recursive: true });

    if (Buffer.isBuffer(report.content)) {
      await fs.writeFile(fullPath, report.content);
    } else {
      await fs.writeFile(fullPath, report.content, 'utf-8');
    }

    return fullPath;
  }

  /**
   * Generate HTML report
   */
  private generateHtml(result: FullAuditResult): string {
    const content = this.buildHtmlContent(result);
    const chartScripts = this.options.includeCharts ? this.getChartScripts(result) : '';

    return HTML_TEMPLATE
      .replace('{{title}}', this.escapeHtml(this.options.title!))
      .replace('{{customCss}}', this.options.customCss || '')
      .replace('{{chartScripts}}', chartScripts)
      .replace('{{content}}', content);
  }

  /**
   * Build HTML content sections
   */
  private buildHtmlContent(result: FullAuditResult): string {
    const sections: string[] = [];

    // Header
    sections.push(`
      <header>
        <div>
          ${this.options.logo ? `<img src="${this.options.logo}" alt="Logo" style="height: 40px; margin-right: 1rem;">` : ''}
          <h1>${this.escapeHtml(this.options.title!)}</h1>
        </div>
        <div class="meta">
          <div>Generated: ${new Date().toLocaleDateString()} ${new Date().toLocaleTimeString()}</div>
          ${this.options.organization ? `<div>Organization: ${this.escapeHtml(this.options.organization)}</div>` : ''}
          <div>Audit ID: ${result.auditId}</div>
        </div>
      </header>
    `);

    // Risk Score & Stats
    const riskClass = this.getRiskClass(result.overallSummary.riskScore);
    sections.push(`
      <div class="stats-grid">
        <div class="stat-card">
          <div class="risk-score ${riskClass}">${result.overallSummary.riskScore}/100</div>
          <div class="label">Risk Score</div>
        </div>
        <div class="stat-card critical">
          <div class="value">${result.overallSummary.criticalCount}</div>
          <div class="label">Critical</div>
        </div>
        <div class="stat-card high">
          <div class="value">${result.overallSummary.highCount}</div>
          <div class="label">High</div>
        </div>
        <div class="stat-card medium">
          <div class="value">${result.overallSummary.mediumCount}</div>
          <div class="label">Medium</div>
        </div>
        <div class="stat-card low">
          <div class="value">${result.overallSummary.lowCount}</div>
          <div class="label">Low</div>
        </div>
      </div>
    `);

    // Executive Summary
    if (this.options.includeExecutiveSummary) {
      sections.push(`
        <div class="card">
          <h2>Executive Summary</h2>
          <p>This security audit was conducted on <strong>${result.startTime.toLocaleDateString()}</strong>
          and completed in <strong>${this.getDuration(result)}</strong>.</p>
          <p style="margin-top: 1rem;">
            The audit identified <strong>${result.overallSummary.totalFindings} findings</strong> across
            ${this.getScannedCategories(result).length} security categories, resulting in a
            <span class="risk-score ${riskClass}" style="font-size: 1rem;">risk score of ${result.overallSummary.riskScore}/100</span>.
          </p>
          ${result.overallSummary.criticalCount > 0 ? `
            <p style="margin-top: 1rem; color: var(--critical);">
              <strong>Immediate attention required:</strong> ${result.overallSummary.criticalCount} critical
              finding(s) require immediate remediation.
            </p>
          ` : ''}
        </div>
      `);
    }

    // Charts
    if (this.options.includeCharts) {
      sections.push(`
        <div class="card">
          <h2>Findings Distribution</h2>
          <div class="chart-container">
            <canvas id="severityChart"></canvas>
          </div>
        </div>
      `);
    }

    // Category Results
    const categories = this.getScannedCategories(result);
    for (const category of categories) {
      const auditResult = (result as Record<string, unknown>)[category] as AuditResult | undefined;
      if (auditResult) {
        sections.push(this.buildCategorySection(category, auditResult));
      }
    }

    // Recommendations
    if (this.options.includeRemediation && result.overallSummary.recommendations.length > 0) {
      sections.push(`
        <div class="card">
          <h2>Recommendations</h2>
          <ul class="recommendations">
            ${result.overallSummary.recommendations.map(r => `<li>${this.escapeHtml(r)}</li>`).join('')}
          </ul>
        </div>
      `);
    }

    // Footer
    sections.push(`
      <footer>
        <p>Generated by ${this.escapeHtml(this.options.author!)} | Security Audit Agent</p>
        <p>Report ID: ${result.auditId}</p>
      </footer>
    `);

    return sections.join('\n');
  }

  /**
   * Build category section HTML
   */
  private buildCategorySection(category: string, result: AuditResult): string {
    const categoryName = this.formatCategoryName(category);
    const findings = this.filterFindings(result.findings);

    return `
      <div class="card">
        <h2>${categoryName}</h2>
        <p style="color: var(--text-muted); margin-bottom: 1rem;">
          ${result.findings.length} findings | Risk contribution: ${result.summary.riskScore}
        </p>

        ${this.options.includeDetailedFindings && findings.length > 0 ? `
          ${findings.slice(0, this.options.maxFindingsPerCategory).map(finding => `
            <div class="finding">
              <div class="finding-header">
                <h3>${this.escapeHtml(finding.title)}</h3>
                <span class="severity-badge ${finding.severity}">${finding.severity}</span>
              </div>
              <div class="finding-body">
                <dl>
                  <dt>Location</dt>
                  <dd><code>${this.escapeHtml(finding.location)}</code></dd>
                  <dt>Description</dt>
                  <dd>${this.escapeHtml(finding.description)}</dd>
                  ${this.options.includeRemediation ? `
                    <dt>Remediation</dt>
                    <dd>${this.escapeHtml(finding.remediation)}</dd>
                  ` : ''}
                </dl>
              </div>
            </div>
          `).join('')}
          ${findings.length > this.options.maxFindingsPerCategory! ? `
            <p style="color: var(--text-muted); font-style: italic;">
              + ${findings.length - this.options.maxFindingsPerCategory!} more findings not shown
            </p>
          ` : ''}
        ` : ''}
      </div>
    `;
  }

  /**
   * Get chart scripts for HTML report
   */
  private getChartScripts(result: FullAuditResult): string {
    return `
      <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
      <script>
        document.addEventListener('DOMContentLoaded', function() {
          const ctx = document.getElementById('severityChart');
          if (ctx) {
            new Chart(ctx, {
              type: 'doughnut',
              data: {
                labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
                datasets: [{
                  data: [
                    ${result.overallSummary.criticalCount},
                    ${result.overallSummary.highCount},
                    ${result.overallSummary.mediumCount},
                    ${result.overallSummary.lowCount},
                    ${result.overallSummary.infoCount}
                  ],
                  backgroundColor: ['#dc2626', '#ea580c', '#ca8a04', '#16a34a', '#2563eb']
                }]
              },
              options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                  legend: { position: 'right' }
                }
              }
            });
          }
        });
      </script>
    `;
  }

  /**
   * Generate PDF report
   */
  private async generatePdf(result: FullAuditResult): Promise<Buffer> {
    // For PDF generation, we'll create a simplified version
    // In production, you'd use a library like puppeteer or pdfkit

    // Generate HTML first, then convert
    const html = this.generateHtml(result);

    // Return HTML as buffer for now - in production, convert to PDF
    // using: const browser = await puppeteer.launch();
    //        const page = await browser.newPage();
    //        await page.setContent(html);
    //        const pdf = await page.pdf({ format: 'A4' });

    // Placeholder: return HTML content as buffer with PDF indicator
    const pdfPlaceholder = `%PDF-PLACEHOLDER%\n${html}`;
    return Buffer.from(pdfPlaceholder, 'utf-8');
  }

  /**
   * Generate JSON report
   */
  private generateJson(result: FullAuditResult): string {
    const report = {
      metadata: {
        title: this.options.title,
        organization: this.options.organization,
        author: this.options.author,
        generatedAt: new Date().toISOString(),
        auditId: result.auditId
      },
      summary: result.overallSummary,
      status: result.status,
      timing: {
        startTime: result.startTime.toISOString(),
        endTime: result.endTime?.toISOString(),
        duration: this.getDuration(result)
      },
      results: {
        configAudit: result.configAudit,
        networkMapping: result.networkMapping,
        containerSecurity: result.containerSecurity,
        authReview: result.authReview,
        logAnalysis: result.logAnalysis
      },
      compliance: result.complianceStatus
    };

    return JSON.stringify(report, null, 2);
  }

  /**
   * Generate Markdown report
   */
  private generateMarkdown(result: FullAuditResult): string {
    const lines: string[] = [];

    // Title
    lines.push(`# ${this.options.title}`);
    lines.push('');
    lines.push(`**Generated:** ${new Date().toISOString()}`);
    lines.push(`**Audit ID:** ${result.auditId}`);
    if (this.options.organization) {
      lines.push(`**Organization:** ${this.options.organization}`);
    }
    lines.push('');

    // Summary
    lines.push('## Summary');
    lines.push('');
    lines.push(`| Metric | Value |`);
    lines.push(`|--------|-------|`);
    lines.push(`| Risk Score | ${result.overallSummary.riskScore}/100 |`);
    lines.push(`| Total Findings | ${result.overallSummary.totalFindings} |`);
    lines.push(`| Critical | ${result.overallSummary.criticalCount} |`);
    lines.push(`| High | ${result.overallSummary.highCount} |`);
    lines.push(`| Medium | ${result.overallSummary.mediumCount} |`);
    lines.push(`| Low | ${result.overallSummary.lowCount} |`);
    lines.push('');

    // Categories
    const categories = this.getScannedCategories(result);
    for (const category of categories) {
      const auditResult = (result as Record<string, unknown>)[category] as AuditResult | undefined;
      if (auditResult) {
        lines.push(`## ${this.formatCategoryName(category)}`);
        lines.push('');
        lines.push(`Findings: ${auditResult.findings.length}`);
        lines.push('');

        if (this.options.includeDetailedFindings) {
          const findings = this.filterFindings(auditResult.findings);
          for (const finding of findings.slice(0, this.options.maxFindingsPerCategory)) {
            lines.push(`### ${this.getSeverityEmoji(finding.severity)} ${finding.title}`);
            lines.push('');
            lines.push(`- **Severity:** ${finding.severity}`);
            lines.push(`- **Location:** \`${finding.location}\``);
            lines.push(`- **Description:** ${finding.description}`);
            if (this.options.includeRemediation) {
              lines.push(`- **Remediation:** ${finding.remediation}`);
            }
            lines.push('');
          }
        }
      }
    }

    // Recommendations
    if (this.options.includeRemediation && result.overallSummary.recommendations.length > 0) {
      lines.push('## Recommendations');
      lines.push('');
      for (const rec of result.overallSummary.recommendations) {
        lines.push(`- ${rec}`);
      }
      lines.push('');
    }

    // Footer
    lines.push('---');
    lines.push(`*Generated by ${this.options.author}*`);

    return lines.join('\n');
  }

  // ============================================================================
  // Helper Methods
  // ============================================================================

  private generateFilename(result: FullAuditResult, format: string): string {
    const date = result.startTime.toISOString().split('T')[0];
    const sanitizedTitle = this.options.title!.toLowerCase().replace(/[^a-z0-9]+/g, '-');
    return `${sanitizedTitle}-${date}.${format}`;
  }

  private escapeHtml(text: string): string {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  private getRiskClass(score: number): string {
    if (score >= 70) return 'critical';
    if (score >= 40) return 'high';
    if (score >= 20) return 'medium';
    return 'low';
  }

  private getDuration(result: FullAuditResult): string {
    if (!result.endTime) return 'In progress';
    const ms = result.endTime.getTime() - result.startTime.getTime();
    const seconds = Math.round(ms / 1000);
    if (seconds < 60) return `${seconds}s`;
    const minutes = Math.round(seconds / 60);
    return `${minutes}m ${seconds % 60}s`;
  }

  private getScannedCategories(result: FullAuditResult): string[] {
    const categories = ['configAudit', 'networkMapping', 'containerSecurity', 'authReview', 'logAnalysis'];
    return categories.filter(c => (result as Record<string, unknown>)[c] !== undefined);
  }

  private formatCategoryName(category: string): string {
    const names: Record<string, string> = {
      configAudit: 'Configuration Audit',
      networkMapping: 'Network Mapping',
      containerSecurity: 'Container Security',
      authReview: 'Authentication Review',
      logAnalysis: 'Log Analysis'
    };
    return names[category] || category;
  }

  private filterFindings(findings: Finding[]): Finding[] {
    if (!this.options.severityFilter) return findings;
    return findings.filter(f => this.options.severityFilter!.includes(f.severity));
  }

  private getSeverityEmoji(severity: SeverityLevel): string {
    const emojis: Record<string, string> = {
      [SeverityLevel.CRITICAL]: '🔴',
      [SeverityLevel.HIGH]: '🟠',
      [SeverityLevel.MEDIUM]: '🟡',
      [SeverityLevel.LOW]: '🟢',
      [SeverityLevel.INFO]: 'ℹ️'
    };
    return emojis[severity] || '•';
  }
}

/**
 * Convenience function to export a report
 */
export async function exportReport(
  result: FullAuditResult,
  format: 'html' | 'pdf' | 'json' | 'markdown',
  options?: ReportOptions
): Promise<GeneratedReport> {
  const exporter = new ReportExporter(options);
  return exporter.generate(result, format);
}

export default ReportExporter;
