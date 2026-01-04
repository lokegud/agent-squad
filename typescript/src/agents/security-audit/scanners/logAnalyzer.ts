/**
 * Log Analysis Scanner
 * Pattern detection for unusual access, brute force, data exfiltration, IMSI concerns
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as readline from 'readline';
import { createReadStream } from 'fs';
import {
  LogFinding,
  LogPattern,
  SeverityLevel,
  LogAnalysisConfig,
  AuditResult,
  AuditStatus,
  ScanType
} from '../types';
import { v4 as uuidv4 } from 'uuid';

const execAsync = promisify(exec);

// Pre-defined security patterns
const DEFAULT_LOG_PATTERNS: LogPattern[] = [
  // Authentication attacks
  {
    name: 'brute_force_ssh',
    pattern: /Failed password for .* from (\d+\.\d+\.\d+\.\d+)/gi,
    severity: SeverityLevel.HIGH,
    description: 'SSH brute force attempt detected',
    category: 'brute_force'
  },
  {
    name: 'brute_force_generic',
    pattern: /(?:authentication failure|failed login|invalid password|access denied)/gi,
    severity: SeverityLevel.MEDIUM,
    description: 'Authentication failure detected',
    category: 'brute_force'
  },
  {
    name: 'invalid_user',
    pattern: /Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)/gi,
    severity: SeverityLevel.MEDIUM,
    description: 'Login attempt with invalid username',
    category: 'brute_force'
  },

  // Privilege escalation
  {
    name: 'sudo_attempt',
    pattern: /sudo:\s+\S+\s+:\s+.*COMMAND=/gi,
    severity: SeverityLevel.INFO,
    description: 'Sudo command execution',
    category: 'privilege_escalation'
  },
  {
    name: 'sudo_failed',
    pattern: /sudo:\s+\S+\s+:\s+.*authentication failure/gi,
    severity: SeverityLevel.HIGH,
    description: 'Failed sudo attempt',
    category: 'privilege_escalation'
  },
  {
    name: 'su_failed',
    pattern: /FAILED su for \S+ by \S+/gi,
    severity: SeverityLevel.HIGH,
    description: 'Failed su command',
    category: 'privilege_escalation'
  },

  // Data exfiltration indicators
  {
    name: 'large_data_transfer',
    pattern: /(?:sent|transferred|uploaded|downloaded)\s+(\d+)\s*(?:MB|GB|bytes)/gi,
    severity: SeverityLevel.MEDIUM,
    description: 'Large data transfer detected',
    category: 'data_exfil'
  },
  {
    name: 'base64_activity',
    pattern: /base64\s+(?:-d|--decode|encode)/gi,
    severity: SeverityLevel.MEDIUM,
    description: 'Base64 encoding/decoding activity',
    category: 'data_exfil'
  },
  {
    name: 'curl_wget_external',
    pattern: /(?:curl|wget)\s+(?:https?:\/\/)?(?:\d+\.\d+\.\d+\.\d+|[a-z0-9.-]+\.[a-z]{2,})/gi,
    severity: SeverityLevel.LOW,
    description: 'External data transfer command',
    category: 'data_exfil'
  },

  // Lateral movement
  {
    name: 'ssh_connection',
    pattern: /Accepted (?:publickey|password) for (\S+) from (\d+\.\d+\.\d+\.\d+)/gi,
    severity: SeverityLevel.INFO,
    description: 'Successful SSH connection',
    category: 'lateral_movement'
  },
  {
    name: 'ssh_reverse_tunnel',
    pattern: /remote forward\s+\S+\s+\S+/gi,
    severity: SeverityLevel.HIGH,
    description: 'SSH reverse tunnel detected',
    category: 'lateral_movement'
  },

  // Unusual access patterns
  {
    name: 'after_hours_access',
    pattern: /(?:0[0-4]|2[2-3]):\d{2}:\d{2}.*(?:login|session opened|accepted)/gi,
    severity: SeverityLevel.LOW,
    description: 'After-hours access detected',
    category: 'unusual_access'
  },
  {
    name: 'root_login',
    pattern: /(?:session opened for user root|root logged in|ROOT LOGIN)/gi,
    severity: SeverityLevel.MEDIUM,
    description: 'Root login detected',
    category: 'unusual_access'
  },

  // Container/Kubernetes security
  {
    name: 'container_escape',
    pattern: /(?:nsenter|docker exec.*--privileged|kubectl exec.*-it)/gi,
    severity: SeverityLevel.HIGH,
    description: 'Potential container escape attempt',
    category: 'unusual_access'
  },

  // Web application attacks
  {
    name: 'sql_injection',
    pattern: /(?:UNION\s+SELECT|OR\s+1=1|AND\s+1=1|--\s*$|;\s*DROP|;\s*DELETE)/gi,
    severity: SeverityLevel.CRITICAL,
    description: 'SQL injection attempt detected',
    category: 'unusual_access'
  },
  {
    name: 'xss_attempt',
    pattern: /<script[^>]*>|javascript:|on\w+\s*=/gi,
    severity: SeverityLevel.HIGH,
    description: 'XSS attempt detected',
    category: 'unusual_access'
  },
  {
    name: 'path_traversal',
    pattern: /\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\//gi,
    severity: SeverityLevel.HIGH,
    description: 'Path traversal attempt detected',
    category: 'unusual_access'
  },

  // IMSI/Mobile security (as mentioned in user requirements)
  {
    name: 'imsi_pattern',
    pattern: /\b\d{15}\b/g,
    severity: SeverityLevel.MEDIUM,
    description: 'Potential IMSI number detected',
    category: 'imsi_related'
  },
  {
    name: 'cell_tower',
    pattern: /(?:cell[_-]?(?:id|tower)|lac|mcc|mnc)[\s:=]+\d+/gi,
    severity: SeverityLevel.MEDIUM,
    description: 'Cell tower identification data',
    category: 'imsi_related'
  },
  {
    name: 'location_tracking',
    pattern: /(?:latitude|longitude|geolocation|gps[_-]?coord)/gi,
    severity: SeverityLevel.MEDIUM,
    description: 'Location tracking activity',
    category: 'imsi_related'
  }
];

// Common log file locations
const DEFAULT_LOG_SOURCES = [
  '/var/log/auth.log',
  '/var/log/secure',
  '/var/log/syslog',
  '/var/log/messages',
  '/var/log/nginx/access.log',
  '/var/log/nginx/error.log',
  '/var/log/apache2/access.log',
  '/var/log/apache2/error.log',
  '/var/log/httpd/access_log',
  '/var/log/httpd/error_log',
  '/var/log/audit/audit.log',
  '/var/log/docker.log',
  '/var/log/containers'
];

interface LogEvent {
  timestamp: Date;
  source: string;
  line: string;
  lineNumber: number;
}

interface PatternMatch {
  pattern: LogPattern;
  events: LogEvent[];
  sourceIps: Set<string>;
}

export class LogAnalyzer {
  private config: LogAnalysisConfig;
  private findings: LogFinding[] = [];
  private patternMatches: Map<string, PatternMatch> = new Map();
  private baselineStats: Map<string, number> = new Map();

  constructor(config?: Partial<LogAnalysisConfig>) {
    const now = new Date();
    const dayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);

    this.config = {
      scanType: ScanType.LOG_ANALYSIS,
      targets: config?.targets ?? [],
      logSources: config?.logSources ?? DEFAULT_LOG_SOURCES,
      timeRange: config?.timeRange ?? { start: dayAgo, end: now },
      patterns: config?.patterns ?? DEFAULT_LOG_PATTERNS,
      enableAnomalyDetection: config?.enableAnomalyDetection ?? true,
      baselineWindow: config?.baselineWindow ?? 7,
      imsiPatterns: config?.imsiPatterns ?? [/\b\d{15}\b/g],
      timeout: config?.timeout ?? 600000,
      parallelism: config?.parallelism ?? 4
    };
  }

  /**
   * Run a full log analysis scan
   */
  async scan(): Promise<AuditResult> {
    const startTime = new Date();
    this.findings = [];
    this.patternMatches.clear();

    try {
      // Phase 1: Collect and analyze logs
      await this.analyzeLogs();

      // Phase 2: Detect patterns
      await this.detectPatterns();

      // Phase 3: Anomaly detection
      if (this.config.enableAnomalyDetection) {
        await this.detectAnomalies();
      }

      // Phase 4: Correlate events
      await this.correlateEvents();

      const endTime = new Date();
      return this.generateReport(startTime, endTime);
    } catch (error) {
      return {
        auditId: uuidv4(),
        scanType: ScanType.LOG_ANALYSIS,
        status: AuditStatus.FAILED,
        startTime,
        endTime: new Date(),
        findings: this.findings,
        summary: this.generateSummary(),
        metadata: { error: String(error) }
      };
    }
  }

  /**
   * Analyze log files
   */
  private async analyzeLogs(): Promise<void> {
    const accessibleLogs = await this.findAccessibleLogs();

    for (const logPath of accessibleLogs) {
      await this.analyzeLogFile(logPath);
    }
  }

  /**
   * Find accessible log files
   */
  private async findAccessibleLogs(): Promise<string[]> {
    const accessible: string[] = [];

    for (const logPath of this.config.logSources) {
      try {
        const stats = await fs.stat(logPath);
        if (stats.isFile()) {
          accessible.push(logPath);
        } else if (stats.isDirectory()) {
          // Handle log directories (like /var/log/containers)
          const entries = await fs.readdir(logPath);
          for (const entry of entries) {
            if (entry.endsWith('.log')) {
              accessible.push(path.join(logPath, entry));
            }
          }
        }
      } catch {
        // Log not accessible
      }
    }

    // Also check Docker logs
    try {
      const { stdout } = await execAsync('docker ps -q 2>/dev/null || echo ""');
      const containerIds = stdout.split('\n').filter(Boolean);

      for (const id of containerIds) {
        try {
          const { stdout: logPath } = await execAsync(
            `docker inspect ${id} --format '{{.LogPath}}' 2>/dev/null`
          );
          if (logPath.trim()) {
            accessible.push(logPath.trim());
          }
        } catch {
          // Skip
        }
      }
    } catch {
      // Docker not available
    }

    return accessible;
  }

  /**
   * Analyze a single log file
   */
  private async analyzeLogFile(logPath: string): Promise<void> {
    try {
      const fileStream = createReadStream(logPath);
      const rl = readline.createInterface({
        input: fileStream,
        crlfDelay: Infinity
      });

      let lineNumber = 0;

      for await (const line of rl) {
        lineNumber++;

        // Check against all patterns
        for (const pattern of this.config.patterns) {
          if (pattern.pattern.test(line)) {
            const match = this.patternMatches.get(pattern.name) || {
              pattern,
              events: [],
              sourceIps: new Set<string>()
            };

            const timestamp = this.extractTimestamp(line) || new Date();

            // Only include events within our time range
            if (timestamp >= this.config.timeRange.start &&
                timestamp <= this.config.timeRange.end) {

              match.events.push({
                timestamp,
                source: logPath,
                line: line.substring(0, 500), // Truncate long lines
                lineNumber
              });

              // Extract source IP if present
              const ipMatch = line.match(/(\d+\.\d+\.\d+\.\d+)/);
              if (ipMatch) {
                match.sourceIps.add(ipMatch[1]);
              }

              this.patternMatches.set(pattern.name, match);
            }
          }
          // Reset regex lastIndex for global patterns
          pattern.pattern.lastIndex = 0;
        }
      }
    } catch {
      // Can't read log file
    }
  }

  /**
   * Extract timestamp from log line
   */
  private extractTimestamp(line: string): Date | null {
    // Common log timestamp formats
    const formats = [
      // Syslog format: Jan  1 12:00:00
      /^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})/,
      // ISO format: 2024-01-01T12:00:00
      /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})/,
      // Apache/Nginx format: [01/Jan/2024:12:00:00
      /\[(\d{2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})/,
      // Docker format: 2024-01-01 12:00:00
      /^(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})/
    ];

    for (const format of formats) {
      const match = line.match(format);
      if (match) {
        try {
          return new Date(match[0]);
        } catch {
          // Invalid date, try next format
        }
      }
    }

    return null;
  }

  /**
   * Detect security patterns and generate findings
   */
  private async detectPatterns(): Promise<void> {
    for (const [patternName, match] of this.patternMatches) {
      const { pattern, events, sourceIps } = match;

      // Skip if too few events (might be noise)
      if (events.length < this.getMinEventsThreshold(pattern.category)) {
        continue;
      }

      // Check for attack patterns
      if (pattern.category === 'brute_force' && events.length >= 5) {
        this.addFinding({
          id: uuidv4(),
          type: 'brute_force_attack',
          severity: events.length >= 20 ? SeverityLevel.CRITICAL : pattern.severity,
          title: `Brute force attack detected: ${events.length} attempts`,
          description: `${pattern.description}. ${events.length} events from ${sourceIps.size} unique IP(s)`,
          location: events[0].source,
          evidence: [
            `Total events: ${events.length}`,
            `Unique source IPs: ${sourceIps.size}`,
            `First seen: ${events[0].timestamp.toISOString()}`,
            `Last seen: ${events[events.length - 1].timestamp.toISOString()}`
          ],
          remediation: 'Implement rate limiting, fail2ban, or IP blocking. Consider implementing MFA.',
          logSource: events[0].source,
          patternType: 'brute_force',
          timeRange: {
            start: events[0].timestamp,
            end: events[events.length - 1].timestamp
          },
          eventCount: events.length,
          affectedResources: Array.from(sourceIps),
          iocIndicators: Array.from(sourceIps),
          detectedAt: new Date(),
          status: 'open'
        });
      }

      if (pattern.category === 'privilege_escalation' && events.length >= 3) {
        this.addFinding({
          id: uuidv4(),
          type: 'privilege_escalation',
          severity: pattern.severity,
          title: `Privilege escalation activity detected`,
          description: `${pattern.description}. ${events.length} events detected`,
          location: events[0].source,
          evidence: events.slice(0, 5).map(e => e.line),
          remediation: 'Review sudo and su configurations. Implement least privilege access.',
          logSource: events[0].source,
          patternType: 'privilege_escalation',
          timeRange: {
            start: events[0].timestamp,
            end: events[events.length - 1].timestamp
          },
          eventCount: events.length,
          affectedResources: [],
          detectedAt: new Date(),
          status: 'open'
        });
      }

      if (pattern.category === 'data_exfil') {
        this.addFinding({
          id: uuidv4(),
          type: 'potential_data_exfiltration',
          severity: pattern.severity,
          title: `Potential data exfiltration activity`,
          description: `${pattern.description}. ${events.length} suspicious events detected`,
          location: events[0].source,
          evidence: events.slice(0, 5).map(e => e.line),
          remediation: 'Review outbound network traffic. Implement DLP controls.',
          logSource: events[0].source,
          patternType: 'data_exfil',
          timeRange: {
            start: events[0].timestamp,
            end: events[events.length - 1].timestamp
          },
          eventCount: events.length,
          affectedResources: [],
          detectedAt: new Date(),
          status: 'open'
        });
      }

      if (pattern.category === 'imsi_related') {
        this.addFinding({
          id: uuidv4(),
          type: 'imsi_data_detected',
          severity: pattern.severity,
          title: `IMSI/Mobile data detected in logs`,
          description: `${pattern.description}. This may indicate mobile device tracking or IMSI catcher activity.`,
          location: events[0].source,
          evidence: events.slice(0, 5).map(e => '[REDACTED - potential IMSI data]'),
          remediation: 'Review if IMSI data handling is authorized. Implement data masking for sensitive identifiers.',
          logSource: events[0].source,
          patternType: 'imsi_related',
          timeRange: {
            start: events[0].timestamp,
            end: events[events.length - 1].timestamp
          },
          eventCount: events.length,
          affectedResources: [],
          detectedAt: new Date(),
          status: 'open'
        });
      }

      if (pattern.category === 'unusual_access' &&
          (patternName.includes('sql_injection') || patternName.includes('xss'))) {
        this.addFinding({
          id: uuidv4(),
          type: 'web_attack',
          severity: pattern.severity,
          title: `Web application attack detected: ${patternName}`,
          description: `${pattern.description}. ${events.length} attack attempts from ${sourceIps.size} IP(s)`,
          location: events[0].source,
          evidence: events.slice(0, 3).map(e => e.line.substring(0, 200)),
          remediation: 'Review WAF rules. Implement input validation and output encoding.',
          logSource: events[0].source,
          patternType: 'unusual_access',
          timeRange: {
            start: events[0].timestamp,
            end: events[events.length - 1].timestamp
          },
          eventCount: events.length,
          affectedResources: [],
          iocIndicators: Array.from(sourceIps),
          detectedAt: new Date(),
          status: 'open'
        });
      }
    }
  }

  /**
   * Detect anomalies in log patterns
   */
  private async detectAnomalies(): Promise<void> {
    // Build baseline from historical data
    await this.buildBaseline();

    // Compare current patterns against baseline
    const now = new Date();
    const hourOfDay = now.getHours();

    // Check for unusual activity hours
    const afterHoursEvents = this.patternMatches.get('after_hours_access');
    if (afterHoursEvents && afterHoursEvents.events.length > 0) {
      const baselineAfterHours = this.baselineStats.get('after_hours_avg') || 0;

      if (afterHoursEvents.events.length > baselineAfterHours * 2) {
        this.addFinding({
          id: uuidv4(),
          type: 'anomaly_after_hours',
          severity: SeverityLevel.MEDIUM,
          title: 'Unusual after-hours activity detected',
          description: `${afterHoursEvents.events.length} events detected during off-hours (baseline: ${baselineAfterHours.toFixed(1)})`,
          location: 'System logs',
          evidence: afterHoursEvents.events.slice(0, 5).map(e => e.line),
          remediation: 'Review after-hours access policies. Verify these are authorized activities.',
          logSource: afterHoursEvents.events[0].source,
          patternType: 'unusual_access',
          timeRange: {
            start: afterHoursEvents.events[0].timestamp,
            end: afterHoursEvents.events[afterHoursEvents.events.length - 1].timestamp
          },
          eventCount: afterHoursEvents.events.length,
          affectedResources: [],
          detectedAt: new Date(),
          status: 'open'
        });
      }
    }

    // Check for authentication failures spike
    const authFailures = this.patternMatches.get('brute_force_generic');
    if (authFailures) {
      const baselineAuthFailures = this.baselineStats.get('auth_failures_avg') || 10;

      if (authFailures.events.length > baselineAuthFailures * 3) {
        this.addFinding({
          id: uuidv4(),
          type: 'anomaly_auth_spike',
          severity: SeverityLevel.HIGH,
          title: 'Spike in authentication failures',
          description: `${authFailures.events.length} authentication failures detected (baseline: ${baselineAuthFailures.toFixed(1)})`,
          location: 'Authentication logs',
          evidence: [
            `Current failures: ${authFailures.events.length}`,
            `Baseline average: ${baselineAuthFailures.toFixed(1)}`,
            `Increase: ${((authFailures.events.length / baselineAuthFailures - 1) * 100).toFixed(0)}%`
          ],
          remediation: 'Investigate source of authentication failures. Consider implementing rate limiting.',
          logSource: authFailures.events[0].source,
          patternType: 'brute_force',
          timeRange: {
            start: authFailures.events[0].timestamp,
            end: authFailures.events[authFailures.events.length - 1].timestamp
          },
          eventCount: authFailures.events.length,
          affectedResources: Array.from(authFailures.sourceIps),
          detectedAt: new Date(),
          status: 'open'
        });
      }
    }
  }

  /**
   * Build baseline statistics from logs
   */
  private async buildBaseline(): Promise<void> {
    // In a real implementation, this would analyze historical logs
    // For now, we use reasonable defaults
    this.baselineStats.set('after_hours_avg', 5);
    this.baselineStats.set('auth_failures_avg', 10);
    this.baselineStats.set('sudo_commands_avg', 20);
    this.baselineStats.set('ssh_connections_avg', 15);
  }

  /**
   * Correlate events across different log sources
   */
  private async correlateEvents(): Promise<void> {
    // Look for attack chains: brute force -> successful login -> privilege escalation
    const bruteForce = this.patternMatches.get('brute_force_ssh');
    const successfulSSH = this.patternMatches.get('ssh_connection');
    const sudoAttempts = this.patternMatches.get('sudo_attempt');

    if (bruteForce && successfulSSH) {
      // Check if any successful logins came from brute force IPs
      const bruteForceIps = bruteForce.sourceIps;
      const suspiciousLogins = successfulSSH.events.filter(e => {
        const ipMatch = e.line.match(/(\d+\.\d+\.\d+\.\d+)/);
        return ipMatch && bruteForceIps.has(ipMatch[1]);
      });

      if (suspiciousLogins.length > 0) {
        this.addFinding({
          id: uuidv4(),
          type: 'attack_chain_detected',
          severity: SeverityLevel.CRITICAL,
          title: 'Attack chain: Brute force followed by successful login',
          description: `${suspiciousLogins.length} successful login(s) from IP addresses that previously attempted brute force attacks`,
          location: 'SSH logs',
          evidence: [
            `Brute force attempts: ${bruteForce.events.length}`,
            `Successful logins from attackers: ${suspiciousLogins.length}`,
            `Attacker IPs: ${Array.from(bruteForceIps).slice(0, 5).join(', ')}`
          ],
          remediation: 'Immediately investigate compromised accounts. Reset credentials and review for unauthorized changes.',
          logSource: successfulSSH.events[0].source,
          patternType: 'lateral_movement',
          timeRange: {
            start: bruteForce.events[0].timestamp,
            end: successfulSSH.events[successfulSSH.events.length - 1].timestamp
          },
          eventCount: suspiciousLogins.length,
          affectedResources: Array.from(bruteForceIps),
          iocIndicators: Array.from(bruteForceIps),
          detectedAt: new Date(),
          status: 'open'
        });
      }
    }
  }

  private getMinEventsThreshold(category: string): number {
    switch (category) {
      case 'brute_force': return 5;
      case 'privilege_escalation': return 2;
      case 'data_exfil': return 1;
      case 'lateral_movement': return 1;
      case 'unusual_access': return 1;
      case 'imsi_related': return 1;
      default: return 3;
    }
  }

  private addFinding(finding: LogFinding): void {
    const exists = this.findings.some(
      f => f.type === finding.type &&
           f.logSource === finding.logSource &&
           f.patternType === finding.patternType
    );
    if (!exists) {
      this.findings.push(finding);
    }
  }

  private generateSummary() {
    return {
      totalFindings: this.findings.length,
      criticalCount: this.findings.filter(f => f.severity === SeverityLevel.CRITICAL).length,
      highCount: this.findings.filter(f => f.severity === SeverityLevel.HIGH).length,
      mediumCount: this.findings.filter(f => f.severity === SeverityLevel.MEDIUM).length,
      lowCount: this.findings.filter(f => f.severity === SeverityLevel.LOW).length,
      infoCount: this.findings.filter(f => f.severity === SeverityLevel.INFO).length,
      passedChecks: 0,
      failedChecks: this.findings.length,
      skippedChecks: 0,
      riskScore: this.calculateRiskScore(),
      recommendations: this.generateRecommendations()
    };
  }

  private calculateRiskScore(): number {
    let score = 0;
    for (const finding of this.findings) {
      switch (finding.severity) {
        case SeverityLevel.CRITICAL: score += 10; break;
        case SeverityLevel.HIGH: score += 7; break;
        case SeverityLevel.MEDIUM: score += 4; break;
        case SeverityLevel.LOW: score += 1; break;
      }
    }
    return Math.min(100, score);
  }

  private generateRecommendations(): string[] {
    const recommendations: string[] = [];

    if (this.findings.some(f => f.patternType === 'brute_force')) {
      recommendations.push('Implement fail2ban or similar rate limiting');
      recommendations.push('Enable MFA for all accounts');
    }
    if (this.findings.some(f => f.patternType === 'privilege_escalation')) {
      recommendations.push('Review sudo configurations and implement least privilege');
    }
    if (this.findings.some(f => f.patternType === 'data_exfil')) {
      recommendations.push('Implement DLP controls and monitor outbound traffic');
    }
    if (this.findings.some(f => f.patternType === 'imsi_related')) {
      recommendations.push('Review handling of mobile device identifiers');
      recommendations.push('Implement data masking for IMSI and similar PII');
    }
    if (this.findings.some(f => f.type === 'attack_chain_detected')) {
      recommendations.push('URGENT: Investigate potential compromise immediately');
    }

    return recommendations;
  }

  private generateReport(startTime: Date, endTime: Date): AuditResult {
    return {
      auditId: uuidv4(),
      scanType: ScanType.LOG_ANALYSIS,
      status: AuditStatus.COMPLETED,
      startTime,
      endTime,
      duration: endTime.getTime() - startTime.getTime(),
      findings: this.findings,
      summary: this.generateSummary(),
      metadata: {
        logSourcesAnalyzed: this.config.logSources.length,
        patternsChecked: this.config.patterns.length,
        timeRangeAnalyzed: {
          start: this.config.timeRange.start.toISOString(),
          end: this.config.timeRange.end.toISOString()
        },
        patternMatchSummary: Object.fromEntries(
          Array.from(this.patternMatches.entries()).map(([name, match]) => [
            name,
            { events: match.events.length, uniqueIps: match.sourceIps.size }
          ])
        )
      }
    };
  }
}

export default LogAnalyzer;
