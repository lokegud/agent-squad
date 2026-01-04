/**
 * Container Security Scanner
 * Checks Docker configs, privileged containers, volume mounts, capabilities
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs/promises';
import * as path from 'path';
import {
  ContainerFinding,
  ContainerInfo,
  VolumeMount,
  PortMapping,
  SeverityLevel,
  ContainerSecurityConfig,
  AuditResult,
  AuditStatus,
  ScanType
} from '../types';
import { v4 as uuidv4 } from 'uuid';

const execAsync = promisify(exec);

// Dangerous capabilities that should be avoided
const DANGEROUS_CAPABILITIES = [
  'CAP_SYS_ADMIN',
  'CAP_NET_ADMIN',
  'CAP_SYS_PTRACE',
  'CAP_SYS_MODULE',
  'CAP_DAC_OVERRIDE',
  'CAP_DAC_READ_SEARCH',
  'CAP_SETUID',
  'CAP_SETGID',
  'CAP_NET_RAW',
  'CAP_SYS_RAWIO',
  'CAP_MKNOD',
  'CAP_CHOWN'
];

// Sensitive host paths that shouldn't be mounted
const SENSITIVE_PATHS = [
  '/etc/shadow',
  '/etc/passwd',
  '/etc/sudoers',
  '/root',
  '/var/run/docker.sock',
  '/proc',
  '/sys',
  '/dev',
  '/.ssh',
  '/var/log',
  '/etc/kubernetes',
  '/var/lib/kubelet'
];

// Environment variable patterns that indicate secrets
const SECRET_ENV_PATTERNS = [
  /password/i,
  /passwd/i,
  /secret/i,
  /api[_-]?key/i,
  /token/i,
  /auth/i,
  /credential/i,
  /private[_-]?key/i,
  /access[_-]?key/i
];

export class ContainerScanner {
  private config: ContainerSecurityConfig;
  private findings: ContainerFinding[] = [];
  private containers: ContainerInfo[] = [];

  constructor(config?: Partial<ContainerSecurityConfig>) {
    this.config = {
      scanType: ScanType.CONTAINER_SECURITY,
      targets: config?.targets ?? [],
      checkPrivileged: config?.checkPrivileged ?? true,
      checkVolumes: config?.checkVolumes ?? true,
      checkNetwork: config?.checkNetwork ?? true,
      checkCapabilities: config?.checkCapabilities ?? true,
      checkSecrets: config?.checkSecrets ?? true,
      checkImages: config?.checkImages ?? true,
      timeout: config?.timeout ?? 300000,
      parallelism: config?.parallelism ?? 4
    };
  }

  /**
   * Run a full container security scan
   */
  async scan(): Promise<AuditResult> {
    const startTime = new Date();
    this.findings = [];
    this.containers = [];

    try {
      // Check if Docker is available
      const dockerAvailable = await this.isDockerAvailable();
      if (!dockerAvailable) {
        return {
          auditId: uuidv4(),
          scanType: ScanType.CONTAINER_SECURITY,
          status: AuditStatus.COMPLETED,
          startTime,
          endTime: new Date(),
          findings: [],
          summary: this.generateSummary(),
          metadata: { message: 'Docker not available on this system' }
        };
      }

      // Phase 1: Discover containers
      await this.discoverContainers();

      // Phase 2: Run security checks
      const checkPromises: Promise<void>[] = [];

      if (this.config.checkPrivileged) {
        checkPromises.push(this.checkPrivilegedContainers());
      }
      if (this.config.checkVolumes) {
        checkPromises.push(this.checkVolumeMounts());
      }
      if (this.config.checkNetwork) {
        checkPromises.push(this.checkNetworkConfiguration());
      }
      if (this.config.checkCapabilities) {
        checkPromises.push(this.checkCapabilities());
      }
      if (this.config.checkSecrets) {
        checkPromises.push(this.checkSecretsExposure());
      }
      if (this.config.checkImages) {
        checkPromises.push(this.checkImageSecurity());
      }

      // Additional checks
      checkPromises.push(this.checkDockerDaemonConfig());
      checkPromises.push(this.checkDockerComposeFiles());

      await Promise.all(checkPromises);

      const endTime = new Date();
      return this.generateReport(startTime, endTime);
    } catch (error) {
      return {
        auditId: uuidv4(),
        scanType: ScanType.CONTAINER_SECURITY,
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
   * Check if Docker is available
   */
  private async isDockerAvailable(): Promise<boolean> {
    try {
      await execAsync('docker version --format "{{.Server.Version}}" 2>/dev/null');
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Discover all running containers
   */
  private async discoverContainers(): Promise<void> {
    try {
      const { stdout } = await execAsync(
        'docker ps -a --format "{{.ID}}" 2>/dev/null || echo ""'
      );

      const containerIds = stdout.split('\n').filter(Boolean);

      for (const id of containerIds) {
        const container = await this.inspectContainer(id);
        if (container) {
          this.containers.push(container);
        }
      }
    } catch {
      // Docker not available or permission denied
    }
  }

  /**
   * Inspect a container and return its info
   */
  private async inspectContainer(id: string): Promise<ContainerInfo | null> {
    try {
      const { stdout } = await execAsync(
        `docker inspect ${id} --format '{{json .}}' 2>/dev/null`
      );

      const info = JSON.parse(stdout);

      // Extract volumes
      const volumes: VolumeMount[] = [];
      if (info.Mounts) {
        for (const mount of info.Mounts) {
          volumes.push({
            source: mount.Source,
            destination: mount.Destination,
            mode: mount.RW ? 'rw' : 'ro',
            type: mount.Type,
            sensitive: SENSITIVE_PATHS.some(p => mount.Source?.startsWith(p))
          });
        }
      }

      // Extract ports
      const ports: PortMapping[] = [];
      if (info.NetworkSettings?.Ports) {
        for (const [containerPort, hostBindings] of Object.entries(info.NetworkSettings.Ports)) {
          const [port, protocol] = containerPort.split('/');
          if (hostBindings) {
            for (const binding of hostBindings as Array<{ HostIp: string; HostPort: string }>) {
              ports.push({
                containerPort: parseInt(port, 10),
                hostPort: parseInt(binding.HostPort, 10),
                hostIp: binding.HostIp,
                protocol: protocol || 'tcp'
              });
            }
          }
        }
      }

      // Extract environment variables
      const environment: Array<{ key: string; value: string; sensitive: boolean }> = [];
      if (info.Config?.Env) {
        for (const env of info.Config.Env) {
          const [key, ...valueParts] = env.split('=');
          const value = valueParts.join('=');
          const sensitive = SECRET_ENV_PATTERNS.some(p => p.test(key));
          environment.push({ key, value, sensitive });
        }
      }

      return {
        id: info.Id?.substring(0, 12) || id,
        name: info.Name?.replace(/^\//, '') || '',
        image: info.Config?.Image || '',
        tag: info.Config?.Image?.split(':')[1] || 'latest',
        status: info.State?.Status || '',
        created: new Date(info.Created),
        privileged: info.HostConfig?.Privileged || false,
        capabilities: [
          ...(info.HostConfig?.CapAdd || []),
          ...(info.HostConfig?.CapDrop?.map((c: string) => `-${c}`) || [])
        ],
        volumes,
        networkMode: info.HostConfig?.NetworkMode || '',
        ports,
        environment,
        labels: info.Config?.Labels || {}
      };
    } catch {
      return null;
    }
  }

  /**
   * Check for privileged containers
   */
  private async checkPrivilegedContainers(): Promise<void> {
    for (const container of this.containers) {
      if (container.privileged) {
        this.addFinding({
          id: uuidv4(),
          type: 'privileged_container',
          severity: SeverityLevel.CRITICAL,
          title: `Privileged container detected: ${container.name}`,
          description: `Container ${container.name} (${container.id}) is running in privileged mode, which gives it full access to the host system`,
          location: container.name,
          evidence: [`Container ID: ${container.id}`, `Image: ${container.image}`, 'Privileged: true'],
          remediation: 'Remove privileged mode and use specific capabilities instead. If root access is needed, use a minimal set of capabilities.',
          containerId: container.id,
          containerName: container.name,
          imageName: container.image,
          imageTag: container.tag,
          riskCategory: 'privileged',
          detectedAt: new Date(),
          status: 'open'
        });
      }
    }
  }

  /**
   * Check volume mounts for security issues
   */
  private async checkVolumeMounts(): Promise<void> {
    for (const container of this.containers) {
      for (const volume of container.volumes) {
        // Check Docker socket mount
        if (volume.source === '/var/run/docker.sock') {
          this.addFinding({
            id: uuidv4(),
            type: 'docker_socket_mount',
            severity: SeverityLevel.CRITICAL,
            title: `Docker socket mounted in container: ${container.name}`,
            description: 'Mounting the Docker socket gives the container full control over the Docker daemon, equivalent to root access on the host',
            location: container.name,
            evidence: [`Source: ${volume.source}`, `Destination: ${volume.destination}`, `Mode: ${volume.mode}`],
            remediation: 'Remove the Docker socket mount. Use Docker-in-Docker (dind) with proper isolation or a Docker API proxy with limited permissions.',
            containerId: container.id,
            containerName: container.name,
            imageName: container.image,
            imageTag: container.tag,
            riskCategory: 'volumes',
            detectedAt: new Date(),
            status: 'open'
          });
        }

        // Check sensitive path mounts
        if (volume.sensitive && volume.source !== '/var/run/docker.sock') {
          this.addFinding({
            id: uuidv4(),
            type: 'sensitive_volume_mount',
            severity: SeverityLevel.HIGH,
            title: `Sensitive path mounted in container: ${container.name}`,
            description: `Container has access to sensitive host path: ${volume.source}`,
            location: container.name,
            evidence: [`Source: ${volume.source}`, `Destination: ${volume.destination}`, `Mode: ${volume.mode}`],
            remediation: 'Review if this mount is necessary. Use read-only mounts where possible. Consider using secrets management instead.',
            containerId: container.id,
            containerName: container.name,
            imageName: container.image,
            imageTag: container.tag,
            riskCategory: 'volumes',
            detectedAt: new Date(),
            status: 'open'
          });
        }

        // Check writable mounts of host paths
        if (volume.type === 'bind' && volume.mode === 'rw') {
          this.addFinding({
            id: uuidv4(),
            type: 'writable_bind_mount',
            severity: SeverityLevel.MEDIUM,
            title: `Writable bind mount in container: ${container.name}`,
            description: `Container has read-write access to host path: ${volume.source}`,
            location: container.name,
            evidence: [`Source: ${volume.source}`, `Destination: ${volume.destination}`, `Mode: ${volume.mode}`],
            remediation: 'Use read-only mounts (ro) where possible. Use named volumes instead of bind mounts when feasible.',
            containerId: container.id,
            containerName: container.name,
            imageName: container.image,
            imageTag: container.tag,
            riskCategory: 'volumes',
            detectedAt: new Date(),
            status: 'open'
          });
        }
      }
    }
  }

  /**
   * Check network configuration
   */
  private async checkNetworkConfiguration(): Promise<void> {
    for (const container of this.containers) {
      // Check for host network mode
      if (container.networkMode === 'host') {
        this.addFinding({
          id: uuidv4(),
          type: 'host_network_mode',
          severity: SeverityLevel.HIGH,
          title: `Container using host network: ${container.name}`,
          description: 'Container is using host network mode, which bypasses container network isolation',
          location: container.name,
          evidence: [`Network mode: host`],
          remediation: 'Use bridge or custom network mode. Only use host network if absolutely necessary for performance.',
          containerId: container.id,
          containerName: container.name,
          imageName: container.image,
          imageTag: container.tag,
          riskCategory: 'network',
          detectedAt: new Date(),
          status: 'open'
        });
      }

      // Check for ports exposed on all interfaces
      for (const port of container.ports) {
        if (port.hostIp === '0.0.0.0' || port.hostIp === '') {
          this.addFinding({
            id: uuidv4(),
            type: 'port_exposed_all_interfaces',
            severity: SeverityLevel.MEDIUM,
            title: `Container port exposed on all interfaces: ${container.name}`,
            description: `Port ${port.containerPort} is exposed on all network interfaces`,
            location: container.name,
            evidence: [`Container port: ${port.containerPort}`, `Host port: ${port.hostPort}`, `Host IP: ${port.hostIp || '0.0.0.0'}`],
            remediation: 'Bind ports to specific interfaces (e.g., 127.0.0.1:8080:8080) or use a reverse proxy.',
            containerId: container.id,
            containerName: container.name,
            imageName: container.image,
            imageTag: container.tag,
            riskCategory: 'network',
            detectedAt: new Date(),
            status: 'open'
          });
        }
      }
    }
  }

  /**
   * Check container capabilities
   */
  private async checkCapabilities(): Promise<void> {
    for (const container of this.containers) {
      const dangerousCaps = container.capabilities.filter(cap =>
        DANGEROUS_CAPABILITIES.includes(cap.replace(/^-/, ''))
      );

      if (dangerousCaps.length > 0) {
        const addedCaps = dangerousCaps.filter(c => !c.startsWith('-'));

        if (addedCaps.length > 0) {
          this.addFinding({
            id: uuidv4(),
            type: 'dangerous_capabilities',
            severity: addedCaps.includes('CAP_SYS_ADMIN') ? SeverityLevel.CRITICAL : SeverityLevel.HIGH,
            title: `Dangerous capabilities added to container: ${container.name}`,
            description: `Container has been granted dangerous capabilities: ${addedCaps.join(', ')}`,
            location: container.name,
            evidence: addedCaps.map(c => `Capability: ${c}`),
            remediation: 'Remove unnecessary capabilities. Use the principle of least privilege.',
            containerId: container.id,
            containerName: container.name,
            imageName: container.image,
            imageTag: container.tag,
            riskCategory: 'capabilities',
            detectedAt: new Date(),
            status: 'open'
          });
        }
      }
    }
  }

  /**
   * Check for secrets exposure in environment variables
   */
  private async checkSecretsExposure(): Promise<void> {
    for (const container of this.containers) {
      const sensitiveEnvVars = container.environment.filter(env => env.sensitive);

      if (sensitiveEnvVars.length > 0) {
        this.addFinding({
          id: uuidv4(),
          type: 'secrets_in_environment',
          severity: SeverityLevel.HIGH,
          title: `Secrets detected in environment variables: ${container.name}`,
          description: `Container has sensitive-looking environment variables which may contain secrets`,
          location: container.name,
          evidence: sensitiveEnvVars.map(env => `Variable: ${env.key}`),
          remediation: 'Use Docker secrets or a secrets manager (Vault, AWS Secrets Manager) instead of environment variables for sensitive data.',
          containerId: container.id,
          containerName: container.name,
          imageName: container.image,
          imageTag: container.tag,
          riskCategory: 'secrets',
          detectedAt: new Date(),
          status: 'open'
        });
      }
    }
  }

  /**
   * Check image security
   */
  private async checkImageSecurity(): Promise<void> {
    for (const container of this.containers) {
      // Check for latest tag
      if (container.tag === 'latest' || !container.image.includes(':')) {
        this.addFinding({
          id: uuidv4(),
          type: 'latest_tag_usage',
          severity: SeverityLevel.MEDIUM,
          title: `Container using 'latest' tag: ${container.name}`,
          description: 'Container is using the latest tag which makes builds non-reproducible and may introduce unexpected changes',
          location: container.name,
          evidence: [`Image: ${container.image}`],
          remediation: 'Use specific image tags or digests for reproducibility and security.',
          containerId: container.id,
          containerName: container.name,
          imageName: container.image,
          imageTag: container.tag,
          riskCategory: 'image',
          detectedAt: new Date(),
          status: 'open'
        });
      }

      // Check if running as root
      try {
        const { stdout } = await execAsync(
          `docker inspect ${container.id} --format '{{.Config.User}}' 2>/dev/null`
        );
        const user = stdout.trim();

        if (!user || user === 'root' || user === '0') {
          this.addFinding({
            id: uuidv4(),
            type: 'running_as_root',
            severity: SeverityLevel.MEDIUM,
            title: `Container running as root: ${container.name}`,
            description: 'Container is running as root user, which increases the impact of container escapes',
            location: container.name,
            evidence: [`User: ${user || 'root (default)'}`],
            remediation: 'Create a non-root user in the Dockerfile and use USER directive to run as that user.',
            containerId: container.id,
            containerName: container.name,
            imageName: container.image,
            imageTag: container.tag,
            riskCategory: 'image',
            detectedAt: new Date(),
            status: 'open'
          });
        }
      } catch {
        // Skip if we can't inspect
      }
    }
  }

  /**
   * Check Docker daemon configuration
   */
  private async checkDockerDaemonConfig(): Promise<void> {
    try {
      const { stdout } = await execAsync('docker info --format "{{json .}}" 2>/dev/null');
      const info = JSON.parse(stdout);

      // Check if live restore is disabled
      if (!info.LiveRestoreEnabled) {
        this.addFinding({
          id: uuidv4(),
          type: 'live_restore_disabled',
          severity: SeverityLevel.LOW,
          title: 'Docker live restore is disabled',
          description: 'Live restore allows containers to keep running if the daemon crashes',
          location: 'Docker daemon',
          evidence: ['LiveRestoreEnabled: false'],
          remediation: 'Enable live restore in Docker daemon configuration',
          containerId: 'daemon',
          containerName: 'Docker daemon',
          imageName: '',
          imageTag: '',
          riskCategory: 'image',
          detectedAt: new Date(),
          status: 'open'
        });
      }

      // Check for user namespace remapping
      if (!info.SecurityOptions?.includes('name=userns')) {
        this.addFinding({
          id: uuidv4(),
          type: 'no_user_namespace',
          severity: SeverityLevel.MEDIUM,
          title: 'User namespace remapping not enabled',
          description: 'User namespace remapping provides an additional layer of isolation by mapping container root to a non-root host user',
          location: 'Docker daemon',
          evidence: ['User namespace: not enabled'],
          remediation: 'Enable user namespace remapping in Docker daemon configuration',
          containerId: 'daemon',
          containerName: 'Docker daemon',
          imageName: '',
          imageTag: '',
          riskCategory: 'image',
          detectedAt: new Date(),
          status: 'open'
        });
      }
    } catch {
      // Can't get Docker info
    }
  }

  /**
   * Check docker-compose files for security issues
   */
  private async checkDockerComposeFiles(): Promise<void> {
    const composeFiles = [
      'docker-compose.yml',
      'docker-compose.yaml',
      'compose.yml',
      'compose.yaml'
    ];

    for (const file of composeFiles) {
      try {
        const content = await fs.readFile(file, 'utf-8');
        await this.analyzeComposeFile(file, content);
      } catch {
        // File doesn't exist or can't be read
      }
    }
  }

  private async analyzeComposeFile(filePath: string, content: string): Promise<void> {
    // Check for privileged mode
    if (/privileged:\s*true/i.test(content)) {
      this.addFinding({
        id: uuidv4(),
        type: 'compose_privileged',
        severity: SeverityLevel.CRITICAL,
        title: `Privileged mode in docker-compose: ${filePath}`,
        description: 'Docker compose file contains privileged: true',
        location: filePath,
        evidence: ['privileged: true found in compose file'],
        remediation: 'Remove privileged mode and use specific capabilities instead',
        containerId: 'compose',
        containerName: filePath,
        imageName: '',
        imageTag: '',
        riskCategory: 'privileged',
        detectedAt: new Date(),
        status: 'open'
      });
    }

    // Check for Docker socket mount
    if (/\/var\/run\/docker\.sock/.test(content)) {
      this.addFinding({
        id: uuidv4(),
        type: 'compose_docker_socket',
        severity: SeverityLevel.CRITICAL,
        title: `Docker socket mount in docker-compose: ${filePath}`,
        description: 'Docker compose file mounts the Docker socket',
        location: filePath,
        evidence: ['/var/run/docker.sock mount found'],
        remediation: 'Remove Docker socket mount or use a restricted Docker API proxy',
        containerId: 'compose',
        containerName: filePath,
        imageName: '',
        imageTag: '',
        riskCategory: 'volumes',
        detectedAt: new Date(),
        status: 'open'
      });
    }

    // Check for hardcoded secrets
    const secretPatterns = [
      /password:\s*['"]?[^${\s][^\s'"]+/gi,
      /api[_-]?key:\s*['"]?[^${\s][^\s'"]+/gi,
      /secret:\s*['"]?[^${\s][^\s'"]+/gi
    ];

    for (const pattern of secretPatterns) {
      if (pattern.test(content)) {
        this.addFinding({
          id: uuidv4(),
          type: 'compose_hardcoded_secret',
          severity: SeverityLevel.HIGH,
          title: `Hardcoded secrets in docker-compose: ${filePath}`,
          description: 'Docker compose file appears to contain hardcoded secrets',
          location: filePath,
          evidence: ['Hardcoded credential patterns detected'],
          remediation: 'Use environment variables, .env files, or Docker secrets instead of hardcoded values',
          containerId: 'compose',
          containerName: filePath,
          imageName: '',
          imageTag: '',
          riskCategory: 'secrets',
          detectedAt: new Date(),
          status: 'open'
        });
        break;
      }
    }
  }

  private addFinding(finding: ContainerFinding): void {
    const exists = this.findings.some(
      f => f.containerId === finding.containerId && f.type === finding.type
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

    if (this.findings.some(f => f.riskCategory === 'privileged')) {
      recommendations.push('Remove privileged mode from all containers');
    }
    if (this.findings.some(f => f.riskCategory === 'volumes')) {
      recommendations.push('Review and minimize volume mounts, especially sensitive paths');
    }
    if (this.findings.some(f => f.riskCategory === 'secrets')) {
      recommendations.push('Implement a secrets management solution for container credentials');
    }
    if (this.findings.some(f => f.riskCategory === 'network')) {
      recommendations.push('Review network exposure and use custom networks for isolation');
    }
    if (this.findings.some(f => f.riskCategory === 'image')) {
      recommendations.push('Use specific image tags and run containers as non-root users');
    }

    return recommendations;
  }

  private generateReport(startTime: Date, endTime: Date): AuditResult {
    return {
      auditId: uuidv4(),
      scanType: ScanType.CONTAINER_SECURITY,
      status: AuditStatus.COMPLETED,
      startTime,
      endTime,
      duration: endTime.getTime() - startTime.getTime(),
      findings: this.findings,
      summary: this.generateSummary(),
      metadata: {
        containersScanned: this.containers.length,
        containerInfo: this.containers.map(c => ({
          id: c.id,
          name: c.name,
          image: c.image
        }))
      }
    };
  }

  /**
   * Get discovered containers
   */
  getContainers(): ContainerInfo[] {
    return this.containers;
  }
}

export default ContainerScanner;
