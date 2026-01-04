/**
 * Continuous Security Monitoring System
 * - Change validator (validates security before deployments)
 * - Dependency tracker (what breaks if X changes)
 * - Real-time security event monitoring
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs/promises';
import * as path from 'path';
import { EventEmitter } from 'events';
import {
  ChangeEvent,
  ValidationResult,
  DependencyMap,
  ServiceDependency,
  SecurityFinding,
  SeverityLevel,
  MonitoringConfig,
  AlertThreshold,
  NotificationChannel
} from '../types';
import { v4 as uuidv4 } from 'uuid';
import { ConfigScanner } from '../scanners/configScanner';
import { ContainerScanner } from '../scanners/containerScanner';

const execAsync = promisify(exec);

interface MonitorEvent {
  type: 'change' | 'alert' | 'validation' | 'dependency_update';
  timestamp: Date;
  data: Record<string, unknown>;
}

interface ValidationCheck {
  name: string;
  check: (change: ChangeEvent) => Promise<{ passed: boolean; message: string }>;
  severity: SeverityLevel;
}

export class ContinuousMonitor extends EventEmitter {
  private config: MonitoringConfig;
  private dependencyMap: DependencyMap;
  private changeHistory: ChangeEvent[] = [];
  private validationChecks: ValidationCheck[] = [];
  private isRunning: boolean = false;
  private monitorInterval?: NodeJS.Timeout;

  constructor(config?: Partial<MonitoringConfig>) {
    super();

    this.config = {
      enabled: config?.enabled ?? true,
      intervalSeconds: config?.intervalSeconds ?? 60,
      alertThresholds: config?.alertThresholds ?? [
        { metric: 'critical_findings', operator: 'gt', value: 0, severity: SeverityLevel.CRITICAL, cooldownSeconds: 300 },
        { metric: 'new_exposed_ports', operator: 'gt', value: 0, severity: SeverityLevel.HIGH, cooldownSeconds: 600 },
        { metric: 'privileged_containers', operator: 'gt', value: 0, severity: SeverityLevel.HIGH, cooldownSeconds: 600 },
        { metric: 'failed_validations', operator: 'gt', value: 3, severity: SeverityLevel.MEDIUM, cooldownSeconds: 900 }
      ],
      notificationChannels: config?.notificationChannels ?? []
    };

    this.dependencyMap = {
      services: [],
      lastUpdated: new Date()
    };

    this.initializeValidationChecks();
  }

  /**
   * Initialize built-in validation checks
   */
  private initializeValidationChecks(): void {
    this.validationChecks = [
      // Security policy validation
      {
        name: 'no_privileged_containers',
        check: async (change) => {
          if (change.changeType !== 'container') return { passed: true, message: 'N/A' };

          const newState = change.newState as Record<string, unknown>;
          if (newState.privileged === true) {
            return {
              passed: false,
              message: 'Privileged containers are not allowed in production'
            };
          }
          return { passed: true, message: 'Container is not privileged' };
        },
        severity: SeverityLevel.CRITICAL
      },

      // Network exposure validation
      {
        name: 'no_public_database_ports',
        check: async (change) => {
          if (change.changeType !== 'network') return { passed: true, message: 'N/A' };

          const newState = change.newState as Record<string, unknown>;
          const dbPorts = [3306, 5432, 27017, 6379, 9200];
          const exposedPort = newState.port as number;
          const bindAddress = newState.bindAddress as string;

          if (dbPorts.includes(exposedPort) &&
              (bindAddress === '0.0.0.0' || bindAddress === '::')) {
            return {
              passed: false,
              message: `Database port ${exposedPort} should not be publicly exposed`
            };
          }
          return { passed: true, message: 'Port exposure is acceptable' };
        },
        severity: SeverityLevel.CRITICAL
      },

      // Secrets validation
      {
        name: 'no_hardcoded_secrets',
        check: async (change) => {
          if (change.changeType !== 'config') return { passed: true, message: 'N/A' };

          const newState = change.newState as Record<string, unknown>;
          const content = JSON.stringify(newState);

          const secretPatterns = [
            /password\s*[=:]\s*['"]?[^${\s][^\s'"]+/gi,
            /api[_-]?key\s*[=:]\s*['"]?[A-Za-z0-9]{20,}/gi,
            /secret\s*[=:]\s*['"]?[^${\s][^\s'"]+/gi
          ];

          for (const pattern of secretPatterns) {
            if (pattern.test(content)) {
              return {
                passed: false,
                message: 'Hardcoded secrets detected in configuration'
              };
            }
          }
          return { passed: true, message: 'No hardcoded secrets found' };
        },
        severity: SeverityLevel.HIGH
      },

      // Auth configuration validation
      {
        name: 'strong_auth_required',
        check: async (change) => {
          if (change.changeType !== 'auth') return { passed: true, message: 'N/A' };

          const newState = change.newState as Record<string, unknown>;

          if (newState.authEnabled === false) {
            return {
              passed: false,
              message: 'Authentication cannot be disabled'
            };
          }
          if (newState.mfaEnabled === false && newState.serviceType === 'production') {
            return {
              passed: false,
              message: 'MFA should be enabled for production services'
            };
          }
          return { passed: true, message: 'Authentication configuration is acceptable' };
        },
        severity: SeverityLevel.HIGH
      },

      // Volume mount validation
      {
        name: 'no_sensitive_mounts',
        check: async (change) => {
          if (change.changeType !== 'container') return { passed: true, message: 'N/A' };

          const newState = change.newState as Record<string, unknown>;
          const volumes = newState.volumes as Array<{ source: string }> || [];

          const sensitivePaths = [
            '/var/run/docker.sock',
            '/etc/shadow',
            '/etc/passwd',
            '/root'
          ];

          for (const volume of volumes) {
            if (sensitivePaths.some(p => volume.source?.startsWith(p))) {
              return {
                passed: false,
                message: `Mounting sensitive path ${volume.source} is not allowed`
              };
            }
          }
          return { passed: true, message: 'Volume mounts are acceptable' };
        },
        severity: SeverityLevel.CRITICAL
      },

      // Image security validation
      {
        name: 'no_latest_tag',
        check: async (change) => {
          if (change.changeType !== 'deployment') return { passed: true, message: 'N/A' };

          const newState = change.newState as Record<string, unknown>;
          const image = newState.image as string || '';

          if (image.endsWith(':latest') || !image.includes(':')) {
            return {
              passed: false,
              message: 'Use specific image tags instead of :latest for reproducibility'
            };
          }
          return { passed: true, message: 'Image tag is specific' };
        },
        severity: SeverityLevel.MEDIUM
      }
    ];
  }

  /**
   * Start continuous monitoring
   */
  async start(): Promise<void> {
    if (this.isRunning) return;

    this.isRunning = true;
    this.emit('started', { timestamp: new Date() });

    // Initial scan
    await this.runSecurityScan();

    // Build initial dependency map
    await this.buildDependencyMap();

    // Start periodic monitoring
    this.monitorInterval = setInterval(
      () => this.runMonitoringCycle(),
      this.config.intervalSeconds * 1000
    );
  }

  /**
   * Stop continuous monitoring
   */
  stop(): void {
    this.isRunning = false;
    if (this.monitorInterval) {
      clearInterval(this.monitorInterval);
      this.monitorInterval = undefined;
    }
    this.emit('stopped', { timestamp: new Date() });
  }

  /**
   * Validate a change before deployment
   */
  async validateChange(change: ChangeEvent): Promise<ValidationResult> {
    const errors: string[] = [];
    const warnings: string[] = [];
    let maxSeverity = SeverityLevel.INFO;

    for (const check of this.validationChecks) {
      try {
        const result = await check.check(change);

        if (!result.passed) {
          if (check.severity === SeverityLevel.CRITICAL ||
              check.severity === SeverityLevel.HIGH) {
            errors.push(`${check.name}: ${result.message}`);
          } else {
            warnings.push(`${check.name}: ${result.message}`);
          }

          if (this.severityToNumber(check.severity) > this.severityToNumber(maxSeverity)) {
            maxSeverity = check.severity;
          }
        }
      } catch (error) {
        warnings.push(`${check.name}: Check failed with error`);
      }
    }

    const validationResult: ValidationResult = {
      passed: errors.length === 0,
      errors,
      warnings,
      securityImpact: maxSeverity
    };

    // Store change with validation result
    change.validated = validationResult.passed;
    change.validationResult = validationResult;
    this.changeHistory.push(change);

    // Emit validation event
    this.emit('validation', {
      change,
      result: validationResult
    });

    // Send alerts for failed validations
    if (!validationResult.passed) {
      await this.sendAlert({
        type: 'validation_failed',
        change,
        result: validationResult
      });
    }

    return validationResult;
  }

  /**
   * Add a custom validation check
   */
  addValidationCheck(check: ValidationCheck): void {
    this.validationChecks.push(check);
  }

  /**
   * Get impact analysis for a service change
   */
  async analyzeImpact(serviceId: string): Promise<ImpactAnalysis> {
    const service = this.dependencyMap.services.find(s => s.serviceId === serviceId);

    if (!service) {
      return {
        serviceId,
        directDependents: [],
        indirectDependents: [],
        criticalPath: false,
        impactSummary: 'Service not found in dependency map'
      };
    }

    // Get all dependent services (direct and indirect)
    const directDependents = service.dependents;
    const indirectDependents = this.getIndirectDependents(serviceId, new Set());

    // Check if service is on critical path
    const criticalPath = service.criticalityScore > 0.7 ||
                         directDependents.length > 3 ||
                         indirectDependents.size > 5;

    const impactSummary = this.generateImpactSummary(
      service,
      directDependents,
      Array.from(indirectDependents)
    );

    return {
      serviceId,
      directDependents,
      indirectDependents: Array.from(indirectDependents),
      criticalPath,
      impactSummary
    };
  }

  /**
   * Get what breaks if a service fails
   */
  getAffectedServices(serviceId: string): string[] {
    const affected = new Set<string>();
    this.collectAffectedServices(serviceId, affected);
    return Array.from(affected);
  }

  /**
   * Build dependency map from running services
   */
  async buildDependencyMap(): Promise<DependencyMap> {
    const services: ServiceDependency[] = [];

    try {
      // Get Docker container dependencies
      await this.mapDockerDependencies(services);

      // Get Kubernetes service dependencies
      await this.mapKubernetesDependencies(services);

      // Get network connections
      await this.mapNetworkDependencies(services);

    } catch (error) {
      // Continue with partial map
    }

    this.dependencyMap = {
      services,
      lastUpdated: new Date()
    };

    return this.dependencyMap;
  }

  /**
   * Run a monitoring cycle
   */
  private async runMonitoringCycle(): Promise<void> {
    try {
      // Check for changes
      await this.detectChanges();

      // Run security scan
      const findings = await this.runSecurityScan();

      // Check thresholds and send alerts
      await this.checkAlertThresholds(findings);

      // Update dependency map periodically (every 10 cycles)
      if (Math.random() < 0.1) {
        await this.buildDependencyMap();
      }

    } catch (error) {
      this.emit('error', { error: String(error), timestamp: new Date() });
    }
  }

  /**
   * Detect changes in the environment
   */
  private async detectChanges(): Promise<void> {
    // Detect Docker container changes
    try {
      const { stdout } = await execAsync(
        'docker events --since "60s" --until "now" --format "{{json .}}" 2>/dev/null || echo ""'
      );

      const events = stdout.split('\n').filter(Boolean);

      for (const eventJson of events) {
        try {
          const event = JSON.parse(eventJson);

          const change: ChangeEvent = {
            id: uuidv4(),
            timestamp: new Date(event.time * 1000),
            changeType: 'container',
            resourceId: event.Actor?.ID || '',
            resourceType: event.Type || 'container',
            previousState: {},
            newState: { action: event.Action, attributes: event.Actor?.Attributes },
            validated: false
          };

          // Auto-validate certain changes
          if (['start', 'create'].includes(event.Action)) {
            await this.validateChange(change);
          }

          this.emit('change', change);
        } catch {
          // Skip invalid events
        }
      }
    } catch {
      // Docker events not available
    }
  }

  /**
   * Run security scan and return findings
   */
  private async runSecurityScan(): Promise<SecurityFinding[]> {
    const allFindings: SecurityFinding[] = [];

    try {
      // Quick config scan
      const configScanner = new ConfigScanner({
        targets: [process.cwd()],
        maxDepth: 2
      });
      const configResult = await configScanner.scan();
      allFindings.push(...configResult.findings);

      // Quick container scan
      const containerScanner = new ContainerScanner();
      const containerResult = await containerScanner.scan();
      allFindings.push(...containerResult.findings);

    } catch {
      // Continue with partial results
    }

    return allFindings;
  }

  /**
   * Check alert thresholds
   */
  private async checkAlertThresholds(findings: SecurityFinding[]): Promise<void> {
    const metrics: Record<string, number> = {
      critical_findings: findings.filter(f => f.severity === SeverityLevel.CRITICAL).length,
      high_findings: findings.filter(f => f.severity === SeverityLevel.HIGH).length,
      new_exposed_ports: findings.filter(f => f.type.includes('exposed_port')).length,
      privileged_containers: findings.filter(f => f.type.includes('privileged')).length,
      failed_validations: this.changeHistory.filter(c => !c.validated).length
    };

    for (const threshold of this.config.alertThresholds) {
      const value = metrics[threshold.metric] || 0;
      const triggered = this.evaluateThreshold(value, threshold);

      if (triggered) {
        await this.sendAlert({
          type: 'threshold_exceeded',
          threshold,
          currentValue: value,
          findings: findings.filter(f => this.matchesThreshold(f, threshold))
        });
      }
    }
  }

  private evaluateThreshold(value: number, threshold: AlertThreshold): boolean {
    switch (threshold.operator) {
      case 'gt': return value > threshold.value;
      case 'gte': return value >= threshold.value;
      case 'lt': return value < threshold.value;
      case 'lte': return value <= threshold.value;
      case 'eq': return value === threshold.value;
      default: return false;
    }
  }

  private matchesThreshold(finding: SecurityFinding, threshold: AlertThreshold): boolean {
    if (threshold.metric === 'critical_findings') {
      return finding.severity === SeverityLevel.CRITICAL;
    }
    if (threshold.metric === 'high_findings') {
      return finding.severity === SeverityLevel.HIGH;
    }
    return false;
  }

  /**
   * Send alert through configured channels
   */
  private async sendAlert(alertData: Record<string, unknown>): Promise<void> {
    for (const channel of this.config.notificationChannels) {
      try {
        await this.sendToChannel(channel, alertData);
      } catch {
        // Log error but continue with other channels
      }
    }

    this.emit('alert', alertData);
  }

  private async sendToChannel(
    channel: NotificationChannel,
    data: Record<string, unknown>
  ): Promise<void> {
    switch (channel.type) {
      case 'webhook':
        await execAsync(`curl -s -X POST "${channel.config.url}" \
          -H "Content-Type: application/json" \
          -d '${JSON.stringify(data)}'`);
        break;

      case 'slack':
        await execAsync(`curl -s -X POST "${channel.config.webhookUrl}" \
          -H "Content-Type: application/json" \
          -d '${JSON.stringify({
            text: `Security Alert: ${JSON.stringify(data, null, 2)}`
          })}'`);
        break;

      // Add more channel types as needed
    }
  }

  /**
   * Dependency mapping helpers
   */
  private async mapDockerDependencies(services: ServiceDependency[]): Promise<void> {
    try {
      const { stdout } = await execAsync(
        'docker ps --format "{{.Names}}:{{.Networks}}" 2>/dev/null || echo ""'
      );

      const containers = stdout.split('\n').filter(Boolean);
      const networkMap: Map<string, string[]> = new Map();

      for (const line of containers) {
        const [name, networks] = line.split(':');
        for (const network of networks.split(',')) {
          const existing = networkMap.get(network) || [];
          existing.push(name);
          networkMap.set(network, existing);
        }

        services.push({
          serviceId: name,
          serviceName: name,
          dependencies: [],
          dependents: [],
          criticalityScore: 0.5,
          impactOnFailure: []
        });
      }

      // Build dependencies based on network connections
      for (const [network, containersInNetwork] of networkMap) {
        for (const container of containersInNetwork) {
          const service = services.find(s => s.serviceId === container);
          if (service) {
            service.dependencies = containersInNetwork.filter(c => c !== container);
          }
        }
      }
    } catch {
      // Docker not available
    }
  }

  private async mapKubernetesDependencies(services: ServiceDependency[]): Promise<void> {
    try {
      const { stdout } = await execAsync(
        'kubectl get services -A -o json 2>/dev/null || echo "{}"'
      );

      const k8sServices = JSON.parse(stdout);

      if (k8sServices.items) {
        for (const svc of k8sServices.items) {
          const id = `${svc.metadata.namespace}/${svc.metadata.name}`;

          services.push({
            serviceId: id,
            serviceName: svc.metadata.name,
            dependencies: [],
            dependents: [],
            criticalityScore: svc.metadata.labels?.critical === 'true' ? 0.9 : 0.5,
            impactOnFailure: []
          });
        }
      }
    } catch {
      // Kubernetes not available
    }
  }

  private async mapNetworkDependencies(services: ServiceDependency[]): Promise<void> {
    try {
      const { stdout } = await execAsync(
        'ss -tnp 2>/dev/null | grep ESTAB || echo ""'
      );

      // Parse connections and update dependencies
      // This is a simplified version
    } catch {
      // Network tools not available
    }
  }

  private getIndirectDependents(
    serviceId: string,
    visited: Set<string>
  ): Set<string> {
    if (visited.has(serviceId)) return new Set();
    visited.add(serviceId);

    const service = this.dependencyMap.services.find(s => s.serviceId === serviceId);
    if (!service) return new Set();

    const indirect = new Set<string>();

    for (const dependent of service.dependents) {
      indirect.add(dependent);
      const subDeps = this.getIndirectDependents(dependent, visited);
      subDeps.forEach(d => indirect.add(d));
    }

    return indirect;
  }

  private collectAffectedServices(serviceId: string, affected: Set<string>): void {
    if (affected.has(serviceId)) return;

    const service = this.dependencyMap.services.find(s => s.serviceId === serviceId);
    if (!service) return;

    affected.add(serviceId);

    for (const dependent of service.dependents) {
      this.collectAffectedServices(dependent, affected);
    }
  }

  private generateImpactSummary(
    service: ServiceDependency,
    directDependents: string[],
    indirectDependents: string[]
  ): string {
    const parts: string[] = [];

    if (directDependents.length > 0) {
      parts.push(`${directDependents.length} services directly depend on this service`);
    }
    if (indirectDependents.length > 0) {
      parts.push(`${indirectDependents.length} additional services may be affected indirectly`);
    }
    if (service.criticalityScore > 0.7) {
      parts.push('This is a CRITICAL service');
    }

    return parts.join('. ') || 'Minimal impact expected';
  }

  private severityToNumber(severity: SeverityLevel): number {
    const map: Record<SeverityLevel, number> = {
      [SeverityLevel.CRITICAL]: 5,
      [SeverityLevel.HIGH]: 4,
      [SeverityLevel.MEDIUM]: 3,
      [SeverityLevel.LOW]: 2,
      [SeverityLevel.INFO]: 1
    };
    return map[severity] || 0;
  }

  /**
   * Get monitoring status
   */
  getStatus(): MonitorStatus {
    return {
      isRunning: this.isRunning,
      lastScan: this.changeHistory.length > 0
        ? this.changeHistory[this.changeHistory.length - 1].timestamp
        : undefined,
      totalChanges: this.changeHistory.length,
      failedValidations: this.changeHistory.filter(c => !c.validated).length,
      servicesMonitored: this.dependencyMap.services.length
    };
  }
}

interface ImpactAnalysis {
  serviceId: string;
  directDependents: string[];
  indirectDependents: string[];
  criticalPath: boolean;
  impactSummary: string;
}

interface MonitorStatus {
  isRunning: boolean;
  lastScan?: Date;
  totalChanges: number;
  failedValidations: number;
  servicesMonitored: number;
}

export default ContinuousMonitor;
