/**
 * AI Security Audit Agent
 * A comprehensive, deployable AI agent for infrastructure security
 *
 * Features:
 * - Config audit: scans for default credentials, exposed ports, weak auth
 * - Network mapping: documents topology, identifies unnecessary exposure
 * - Container security: checks Docker configs, privileged containers, volumes
 * - Auth review: shared credentials vs proper isolation
 * - Log analysis: pattern detection for unusual access, IMSI concerns
 * - Hybrid AI: local model for scanning, Vertex AI for pattern analysis
 * - Continuous monitoring: change validation, dependency tracking
 */

import { Agent, AgentOptions } from '../agent';
import { ConversationMessage, ParticipantRole } from '../../types';
import {
  SecurityAuditAgentConfig,
  ScanType,
  AuditResult,
  FullAuditResult,
  AuditStatus,
  SeverityLevel,
  ChangeEvent,
  ValidationResult
} from './types';

// Import scanners
import { ConfigScanner } from './scanners/configScanner';
import { NetworkMapper } from './scanners/networkMapper';
import { ContainerScanner } from './scanners/containerScanner';
import { AuthScanner } from './scanners/authScanner';
import { LogAnalyzer } from './scanners/logAnalyzer';

// Import analyzers
import { HybridAIProcessor } from './analyzers/hybridAIProcessor';
import { ContinuousMonitor } from './analyzers/continuousMonitor';

// Import utilities
import { DataSanitizer } from './utils/sanitizer';

import { v4 as uuidv4 } from 'uuid';

export interface SecurityAuditAgentOptions extends AgentOptions {
  config?: Partial<SecurityAuditAgentConfig>;
}

export class SecurityAuditAgent extends Agent {
  private agentConfig: SecurityAuditAgentConfig;
  private configScanner: ConfigScanner;
  private networkMapper: NetworkMapper;
  private containerScanner: ContainerScanner;
  private authScanner: AuthScanner;
  private logAnalyzer: LogAnalyzer;
  private hybridProcessor: HybridAIProcessor;
  private continuousMonitor: ContinuousMonitor;
  private sanitizer: DataSanitizer;
  private lastAuditResult?: FullAuditResult;

  constructor(options: SecurityAuditAgentOptions) {
    super({
      name: options.name || 'SecurityAuditAgent',
      description: options.description || `
        Comprehensive AI-powered security audit agent that performs:
        - Configuration audits for credentials, ports, and authentication
        - Network topology mapping and exposure analysis
        - Container security assessment
        - Authentication and authorization review
        - Log analysis for anomalies and attack patterns
        - Continuous security monitoring and change validation
      `.trim(),
      ...options
    });

    // Initialize configuration with defaults
    this.agentConfig = {
      name: options.name || 'SecurityAuditAgent',
      description: options.description || 'AI Security Audit Agent',
      modelConfig: {
        modelId: options.config?.modelConfig?.modelId || 'anthropic.claude-3-sonnet-20240229-v1:0',
        temperature: options.config?.modelConfig?.temperature ?? 0,
        maxTokens: options.config?.modelConfig?.maxTokens || 4096,
        streaming: options.config?.modelConfig?.streaming ?? true
      },
      localModelConfig: options.config?.localModelConfig || {
        enabled: true,
        modelPath: '',
        modelType: 'ollama',
        endpoint: 'http://localhost:11434',
        capabilities: ['scan', 'classify']
      },
      vertexConfig: options.config?.vertexConfig || {
        enabled: true,
        projectId: process.env.GOOGLE_CLOUD_PROJECT || '',
        location: 'us-central1',
        modelId: 'gemini-1.5-pro',
        useForPatternAnalysis: true,
        useForAnomalyDetection: true
      },
      scanConfigs: options.config?.scanConfigs || [],
      monitoringConfig: options.config?.monitoringConfig || {
        enabled: true,
        intervalSeconds: 60,
        alertThresholds: [],
        notificationChannels: []
      },
      sanitizationConfig: options.config?.sanitizationConfig || {
        enabled: true,
        patterns: [],
        preserveFormat: true,
        hashSensitiveValues: false
      },
      storageConfig: options.config?.storageConfig || {
        type: 'memory',
        retentionDays: 30,
        encryptAtRest: true
      }
    };

    // Initialize components
    this.configScanner = new ConfigScanner();
    this.networkMapper = new NetworkMapper();
    this.containerScanner = new ContainerScanner();
    this.authScanner = new AuthScanner();
    this.logAnalyzer = new LogAnalyzer();

    this.sanitizer = new DataSanitizer(this.agentConfig.sanitizationConfig);

    this.hybridProcessor = new HybridAIProcessor(
      this.agentConfig.localModelConfig,
      this.agentConfig.vertexConfig,
      this.agentConfig.sanitizationConfig
    );

    this.continuousMonitor = new ContinuousMonitor(
      this.agentConfig.monitoringConfig
    );

    // Set up event handlers
    this.setupEventHandlers();
  }

  /**
   * Process incoming requests
   */
  async processRequest(
    inputText: string,
    userId: string,
    sessionId: string,
    chatHistory: ConversationMessage[],
    additionalParams?: Record<string, string>
  ): Promise<ConversationMessage> {
    const command = this.parseCommand(inputText);

    try {
      let response: string;

      switch (command.action) {
        case 'full_audit':
          response = await this.runFullAudit();
          break;

        case 'config_audit':
          response = await this.runConfigAudit();
          break;

        case 'network_map':
          response = await this.runNetworkMapping();
          break;

        case 'container_scan':
          response = await this.runContainerScan();
          break;

        case 'auth_review':
          response = await this.runAuthReview();
          break;

        case 'log_analysis':
          response = await this.runLogAnalysis();
          break;

        case 'validate_change':
          response = await this.validateChange(command.params);
          break;

        case 'impact_analysis':
          response = await this.analyzeImpact(command.params.serviceId);
          break;

        case 'start_monitoring':
          response = await this.startMonitoring();
          break;

        case 'stop_monitoring':
          response = await this.stopMonitoring();
          break;

        case 'status':
          response = this.getStatus();
          break;

        case 'help':
        default:
          response = this.getHelp();
          break;
      }

      return {
        role: ParticipantRole.ASSISTANT,
        content: [{ text: response }]
      };
    } catch (error) {
      return {
        role: ParticipantRole.ASSISTANT,
        content: [{
          text: `Error processing request: ${error instanceof Error ? error.message : String(error)}`
        }]
      };
    }
  }

  /**
   * Parse input command
   */
  private parseCommand(input: string): { action: string; params: Record<string, string> } {
    const lowerInput = input.toLowerCase();

    // Command patterns
    const patterns: Array<{ pattern: RegExp; action: string }> = [
      { pattern: /full\s*audit|complete\s*scan|security\s*audit/i, action: 'full_audit' },
      { pattern: /config(uration)?\s*(audit|scan|check)/i, action: 'config_audit' },
      { pattern: /network\s*(map|scan|topology)/i, action: 'network_map' },
      { pattern: /container\s*(scan|security|check)|docker\s*scan/i, action: 'container_scan' },
      { pattern: /auth(entication)?\s*(review|check|audit)/i, action: 'auth_review' },
      { pattern: /log\s*(analysis|scan|check)|analyze\s*logs/i, action: 'log_analysis' },
      { pattern: /validate\s*(change|deployment)/i, action: 'validate_change' },
      { pattern: /impact\s*(analysis|check)/i, action: 'impact_analysis' },
      { pattern: /start\s*monitor/i, action: 'start_monitoring' },
      { pattern: /stop\s*monitor/i, action: 'stop_monitoring' },
      { pattern: /status|state/i, action: 'status' },
      { pattern: /help|commands|what can you do/i, action: 'help' }
    ];

    for (const { pattern, action } of patterns) {
      if (pattern.test(lowerInput)) {
        return { action, params: this.extractParams(input) };
      }
    }

    return { action: 'help', params: {} };
  }

  private extractParams(input: string): Record<string, string> {
    const params: Record<string, string> = {};

    // Extract service ID
    const serviceMatch = input.match(/service[:\s]+(\S+)/i);
    if (serviceMatch) params.serviceId = serviceMatch[1];

    // Extract path
    const pathMatch = input.match(/path[:\s]+(\S+)/i);
    if (pathMatch) params.path = pathMatch[1];

    return params;
  }

  /**
   * Run a full security audit
   */
  async runFullAudit(): Promise<string> {
    const startTime = new Date();
    const auditId = uuidv4();

    const results: {
      configAudit?: AuditResult;
      networkMapping?: AuditResult;
      containerSecurity?: AuditResult;
      authReview?: AuditResult;
      logAnalysis?: AuditResult;
    } = {};

    // Run all scans in parallel
    const scanPromises = [
      this.configScanner.scan().then(r => results.configAudit = r),
      this.networkMapper.scan().then(r => results.networkMapping = r),
      this.containerScanner.scan().then(r => results.containerSecurity = r),
      this.authScanner.scan().then(r => results.authReview = r),
      this.logAnalyzer.scan().then(r => results.logAnalysis = r)
    ];

    await Promise.all(scanPromises);

    // Initialize hybrid processor
    await this.hybridProcessor.initialize();

    // Process results through hybrid AI
    const allResults = Object.values(results).filter(Boolean) as AuditResult[];
    const aiAnalysis = await this.hybridProcessor.processAuditResults(allResults);

    // Generate comprehensive report
    const fullResult: FullAuditResult = {
      auditId,
      status: AuditStatus.COMPLETED,
      startTime,
      endTime: new Date(),
      ...results,
      overallSummary: this.generateOverallSummary(allResults),
      complianceStatus: {
        frameworks: [],
        overallCompliance: 0,
        criticalGaps: []
      }
    };

    this.lastAuditResult = fullResult;

    return this.formatFullAuditReport(fullResult, aiAnalysis);
  }

  /**
   * Run individual scan types
   */
  async runConfigAudit(): Promise<string> {
    const result = await this.configScanner.scan();
    return this.formatAuditResult('Configuration Audit', result);
  }

  async runNetworkMapping(): Promise<string> {
    const result = await this.networkMapper.scan();
    const topology = this.networkMapper.getTopology();
    return this.formatAuditResult('Network Mapping', result, {
      nodesDiscovered: topology.nodes.length,
      zonesIdentified: topology.zones.length
    });
  }

  async runContainerScan(): Promise<string> {
    const result = await this.containerScanner.scan();
    const containers = this.containerScanner.getContainers();
    return this.formatAuditResult('Container Security', result, {
      containersScanned: containers.length
    });
  }

  async runAuthReview(): Promise<string> {
    const result = await this.authScanner.scan();
    return this.formatAuditResult('Authentication Review', result);
  }

  async runLogAnalysis(): Promise<string> {
    const result = await this.logAnalyzer.scan();
    return this.formatAuditResult('Log Analysis', result);
  }

  /**
   * Validate a proposed change
   */
  async validateChange(params: Record<string, string>): Promise<string> {
    const change: ChangeEvent = {
      id: uuidv4(),
      timestamp: new Date(),
      changeType: (params.type as 'config' | 'network' | 'container' | 'auth' | 'deployment') || 'config',
      resourceId: params.resourceId || 'unknown',
      resourceType: params.resourceType || 'unknown',
      previousState: {},
      newState: params,
      validated: false
    };

    const result = await this.continuousMonitor.validateChange(change);
    return this.formatValidationResult(result);
  }

  /**
   * Analyze impact of service change
   */
  async analyzeImpact(serviceId: string): Promise<string> {
    const impact = await this.continuousMonitor.analyzeImpact(serviceId);
    return this.formatImpactAnalysis(impact);
  }

  /**
   * Start continuous monitoring
   */
  async startMonitoring(): Promise<string> {
    await this.continuousMonitor.start();
    return `✓ Continuous monitoring started

Monitoring is now active with:
- Security scans every ${this.agentConfig.monitoringConfig.intervalSeconds} seconds
- Change validation enabled
- Alert thresholds configured: ${this.agentConfig.monitoringConfig.alertThresholds.length}

Use "stop monitoring" to disable.`;
  }

  /**
   * Stop continuous monitoring
   */
  async stopMonitoring(): Promise<string> {
    this.continuousMonitor.stop();
    return '✓ Continuous monitoring stopped';
  }

  /**
   * Get current status
   */
  getStatus(): string {
    const monitorStatus = this.continuousMonitor.getStatus();
    const processorStatus = this.hybridProcessor.getStatus();

    return `# Security Audit Agent Status

## Monitoring
- Status: ${monitorStatus.isRunning ? '🟢 Running' : '🔴 Stopped'}
- Services monitored: ${monitorStatus.servicesMonitored}
- Total changes tracked: ${monitorStatus.totalChanges}
- Failed validations: ${monitorStatus.failedValidations}
${monitorStatus.lastScan ? `- Last scan: ${monitorStatus.lastScan.toISOString()}` : ''}

## AI Processing
- Local model: ${processorStatus.localAvailable ? '🟢 Available' : '🔴 Unavailable'}
- Vertex AI: ${processorStatus.vertexAvailable ? '🟢 Available' : '🔴 Unavailable'}

## Last Audit
${this.lastAuditResult ? `
- Audit ID: ${this.lastAuditResult.auditId}
- Status: ${this.lastAuditResult.status}
- Findings: ${this.lastAuditResult.overallSummary.totalFindings}
- Risk Score: ${this.lastAuditResult.overallSummary.riskScore}/100
` : '- No audit run yet'}
`;
  }

  /**
   * Get help text
   */
  getHelp(): string {
    return `# AI Security Audit Agent

## Available Commands

### Scanning
- **full audit** - Run complete security audit (all scans)
- **config audit** - Scan for credentials, exposed ports, weak auth
- **network map** - Map network topology, identify exposure
- **container scan** - Check Docker security, privileged containers
- **auth review** - Review authentication and credential isolation
- **log analysis** - Detect unusual access patterns, IMSI concerns

### Monitoring
- **start monitoring** - Enable continuous security monitoring
- **stop monitoring** - Disable continuous monitoring
- **validate change** - Validate a proposed configuration change
- **impact analysis service:[name]** - Analyze impact if service changes

### Information
- **status** - Get current agent status
- **help** - Show this help

## Features

✓ **Local Processing** - Sensitive data stays on your infrastructure
✓ **Cloud Analysis** - Pattern detection via Vertex AI (sanitized data only)
✓ **Continuous Monitoring** - Real-time change validation
✓ **Dependency Tracking** - Know what breaks when services change

## Example Usage

\`\`\`
> full audit
> container scan
> start monitoring
> impact analysis service:database
\`\`\`
`;
  }

  /**
   * Format helpers
   */
  private formatFullAuditReport(
    result: FullAuditResult,
    aiAnalysis: { insights: string[]; recommendations: string[]; patterns?: Array<{ name: string; description: string }> }
  ): string {
    const summary = result.overallSummary;

    let report = `# Full Security Audit Report

## Summary
- **Audit ID**: ${result.auditId}
- **Status**: ${result.status}
- **Duration**: ${result.endTime ? Math.round((result.endTime.getTime() - result.startTime.getTime()) / 1000) : 0}s

## Risk Score: ${summary.riskScore}/100 ${this.getRiskEmoji(summary.riskScore)}

## Findings Overview
| Severity | Count |
|----------|-------|
| 🔴 Critical | ${summary.criticalCount} |
| 🟠 High | ${summary.highCount} |
| 🟡 Medium | ${summary.mediumCount} |
| 🟢 Low | ${summary.lowCount} |
| ℹ️ Info | ${summary.infoCount} |

**Total**: ${summary.totalFindings} findings

## Scan Results
`;

    if (result.configAudit) {
      report += this.formatScanSection('Configuration Audit', result.configAudit);
    }
    if (result.networkMapping) {
      report += this.formatScanSection('Network Mapping', result.networkMapping);
    }
    if (result.containerSecurity) {
      report += this.formatScanSection('Container Security', result.containerSecurity);
    }
    if (result.authReview) {
      report += this.formatScanSection('Auth Review', result.authReview);
    }
    if (result.logAnalysis) {
      report += this.formatScanSection('Log Analysis', result.logAnalysis);
    }

    // AI Insights
    if (aiAnalysis.insights.length > 0) {
      report += `\n## AI Insights\n`;
      for (const insight of aiAnalysis.insights) {
        report += `- ${insight}\n`;
      }
    }

    // Detected Patterns
    if (aiAnalysis.patterns && aiAnalysis.patterns.length > 0) {
      report += `\n## Detected Patterns\n`;
      for (const pattern of aiAnalysis.patterns) {
        report += `- **${pattern.name}**: ${pattern.description}\n`;
      }
    }

    // Recommendations
    report += `\n## Recommendations\n`;
    const allRecommendations = [
      ...summary.recommendations,
      ...aiAnalysis.recommendations
    ];
    for (const rec of [...new Set(allRecommendations)]) {
      report += `- ${rec}\n`;
    }

    return report;
  }

  private formatScanSection(name: string, result: AuditResult): string {
    let section = `\n### ${name}\n`;
    section += `- Findings: ${result.findings.length}\n`;
    section += `- Critical: ${result.summary.criticalCount}, High: ${result.summary.highCount}\n`;

    if (result.findings.length > 0) {
      section += `\nTop findings:\n`;
      for (const finding of result.findings.slice(0, 3)) {
        section += `- [${finding.severity.toUpperCase()}] ${finding.title}\n`;
      }
    }

    return section;
  }

  private formatAuditResult(
    name: string,
    result: AuditResult,
    metadata?: Record<string, unknown>
  ): string {
    let report = `# ${name} Results

## Summary
- **Status**: ${result.status}
- **Duration**: ${result.duration ? Math.round(result.duration / 1000) : 0}s
- **Risk Score**: ${result.summary.riskScore}/100

## Findings
| Severity | Count |
|----------|-------|
| Critical | ${result.summary.criticalCount} |
| High | ${result.summary.highCount} |
| Medium | ${result.summary.mediumCount} |
| Low | ${result.summary.lowCount} |

`;

    if (metadata) {
      report += `## Metadata\n`;
      for (const [key, value] of Object.entries(metadata)) {
        report += `- ${key}: ${value}\n`;
      }
      report += '\n';
    }

    if (result.findings.length > 0) {
      report += `## Detailed Findings\n\n`;
      for (const finding of result.findings) {
        report += `### ${this.getSeverityEmoji(finding.severity)} ${finding.title}\n`;
        report += `- **Severity**: ${finding.severity}\n`;
        report += `- **Location**: ${finding.location}\n`;
        report += `- **Description**: ${finding.description}\n`;
        report += `- **Remediation**: ${finding.remediation}\n\n`;
      }
    }

    if (result.summary.recommendations.length > 0) {
      report += `## Recommendations\n`;
      for (const rec of result.summary.recommendations) {
        report += `- ${rec}\n`;
      }
    }

    return report;
  }

  private formatValidationResult(result: ValidationResult): string {
    let report = `# Change Validation Result

## Status: ${result.passed ? '✅ PASSED' : '❌ FAILED'}

## Security Impact: ${result.securityImpact}

`;

    if (result.errors.length > 0) {
      report += `## Errors\n`;
      for (const error of result.errors) {
        report += `- ❌ ${error}\n`;
      }
    }

    if (result.warnings.length > 0) {
      report += `\n## Warnings\n`;
      for (const warning of result.warnings) {
        report += `- ⚠️ ${warning}\n`;
      }
    }

    return report;
  }

  private formatImpactAnalysis(impact: {
    serviceId: string;
    directDependents: string[];
    indirectDependents: string[];
    criticalPath: boolean;
    impactSummary: string;
  }): string {
    return `# Impact Analysis: ${impact.serviceId}

## Critical Path: ${impact.criticalPath ? '⚠️ YES' : '✅ NO'}

## Summary
${impact.impactSummary}

## Direct Dependents (${impact.directDependents.length})
${impact.directDependents.map(d => `- ${d}`).join('\n') || '- None'}

## Indirect Dependents (${impact.indirectDependents.length})
${impact.indirectDependents.map(d => `- ${d}`).join('\n') || '- None'}
`;
  }

  private generateOverallSummary(results: AuditResult[]) {
    let totalFindings = 0;
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;
    let infoCount = 0;
    const recommendations: string[] = [];

    for (const result of results) {
      totalFindings += result.findings.length;
      criticalCount += result.summary.criticalCount;
      highCount += result.summary.highCount;
      mediumCount += result.summary.mediumCount;
      lowCount += result.summary.lowCount;
      infoCount += result.summary.infoCount;
      recommendations.push(...result.summary.recommendations);
    }

    const riskScore = Math.min(100,
      criticalCount * 10 +
      highCount * 7 +
      mediumCount * 4 +
      lowCount * 1
    );

    return {
      totalFindings,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      infoCount,
      passedChecks: 0,
      failedChecks: totalFindings,
      skippedChecks: 0,
      riskScore,
      recommendations: [...new Set(recommendations)]
    };
  }

  private getRiskEmoji(score: number): string {
    if (score >= 70) return '🔴';
    if (score >= 40) return '🟠';
    if (score >= 20) return '🟡';
    return '🟢';
  }

  private getSeverityEmoji(severity: SeverityLevel): string {
    switch (severity) {
      case SeverityLevel.CRITICAL: return '🔴';
      case SeverityLevel.HIGH: return '🟠';
      case SeverityLevel.MEDIUM: return '🟡';
      case SeverityLevel.LOW: return '🟢';
      default: return 'ℹ️';
    }
  }

  /**
   * Set up event handlers for monitoring
   */
  private setupEventHandlers(): void {
    this.continuousMonitor.on('alert', (data) => {
      console.log('[SECURITY ALERT]', JSON.stringify(data, null, 2));
    });

    this.continuousMonitor.on('change', (change) => {
      console.log('[CHANGE DETECTED]', change.changeType, change.resourceId);
    });

    this.continuousMonitor.on('validation', (data) => {
      if (!data.result.passed) {
        console.log('[VALIDATION FAILED]', data.change.resourceId);
      }
    });
  }
}

// Export everything
export * from './types';
export { ConfigScanner } from './scanners/configScanner';
export { NetworkMapper } from './scanners/networkMapper';
export { ContainerScanner } from './scanners/containerScanner';
export { AuthScanner } from './scanners/authScanner';
export { LogAnalyzer } from './scanners/logAnalyzer';
export { HybridAIProcessor } from './analyzers/hybridAIProcessor';
export { ContinuousMonitor } from './analyzers/continuousMonitor';
export { DataSanitizer } from './utils/sanitizer';

export default SecurityAuditAgent;
