/**
 * Network Topology Mapper
 * Documents network topology, identifies unnecessary exposure
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs/promises';
import * as dns from 'dns';
import {
  NetworkFinding,
  NetworkTopology,
  NetworkNode,
  NetworkEdge,
  NetworkZone,
  PortInfo,
  SeverityLevel,
  NetworkMappingConfig,
  AuditResult,
  AuditStatus,
  ScanType
} from '../types';
import { v4 as uuidv4 } from 'uuid';

const execAsync = promisify(exec);
const dnsLookup = promisify(dns.lookup);

// Well-known ports and their services
const WELL_KNOWN_PORTS: Record<number, { service: string; risk: string; expectedExposure: string }> = {
  20: { service: 'FTP Data', risk: 'Unencrypted file transfer', expectedExposure: 'internal' },
  21: { service: 'FTP Control', risk: 'Unencrypted file transfer', expectedExposure: 'internal' },
  22: { service: 'SSH', risk: 'Remote access', expectedExposure: 'internal' },
  23: { service: 'Telnet', risk: 'Unencrypted remote access', expectedExposure: 'internal' },
  25: { service: 'SMTP', risk: 'Email relay', expectedExposure: 'internal' },
  53: { service: 'DNS', risk: 'Name resolution', expectedExposure: 'internal' },
  80: { service: 'HTTP', risk: 'Unencrypted web traffic', expectedExposure: 'public' },
  110: { service: 'POP3', risk: 'Unencrypted email', expectedExposure: 'internal' },
  143: { service: 'IMAP', risk: 'Unencrypted email', expectedExposure: 'internal' },
  443: { service: 'HTTPS', risk: 'Web traffic', expectedExposure: 'public' },
  445: { service: 'SMB', risk: 'File sharing', expectedExposure: 'internal' },
  1433: { service: 'MSSQL', risk: 'Database access', expectedExposure: 'internal' },
  1521: { service: 'Oracle', risk: 'Database access', expectedExposure: 'internal' },
  2375: { service: 'Docker API (unencrypted)', risk: 'Container management', expectedExposure: 'internal' },
  2376: { service: 'Docker API (TLS)', risk: 'Container management', expectedExposure: 'internal' },
  3306: { service: 'MySQL', risk: 'Database access', expectedExposure: 'internal' },
  3389: { service: 'RDP', risk: 'Remote desktop', expectedExposure: 'internal' },
  5432: { service: 'PostgreSQL', risk: 'Database access', expectedExposure: 'internal' },
  5672: { service: 'RabbitMQ', risk: 'Message queue', expectedExposure: 'internal' },
  5900: { service: 'VNC', risk: 'Remote desktop', expectedExposure: 'internal' },
  6379: { service: 'Redis', risk: 'Cache/data store', expectedExposure: 'internal' },
  8080: { service: 'HTTP Alt', risk: 'Web service', expectedExposure: 'internal' },
  8443: { service: 'HTTPS Alt', risk: 'Web service', expectedExposure: 'internal' },
  9000: { service: 'Various', risk: 'Application service', expectedExposure: 'internal' },
  9090: { service: 'Prometheus', risk: 'Metrics exposure', expectedExposure: 'internal' },
  9200: { service: 'Elasticsearch', risk: 'Search engine', expectedExposure: 'internal' },
  11211: { service: 'Memcached', risk: 'Cache access', expectedExposure: 'internal' },
  27017: { service: 'MongoDB', risk: 'Database access', expectedExposure: 'internal' }
};

export class NetworkMapper {
  private config: NetworkMappingConfig;
  private findings: NetworkFinding[] = [];
  private topology: NetworkTopology;

  constructor(config?: Partial<NetworkMappingConfig>) {
    this.config = {
      scanType: ScanType.NETWORK_MAPPING,
      targets: config?.targets ?? ['localhost'],
      discoverHosts: config?.discoverHosts ?? true,
      scanPorts: config?.scanPorts ?? true,
      portRange: config?.portRange ?? { start: 1, end: 65535 },
      detectServices: config?.detectServices ?? true,
      mapTopology: config?.mapTopology ?? true,
      maxDepth: config?.maxDepth ?? 3,
      timeout: config?.timeout ?? 600000,
      parallelism: config?.parallelism ?? 10
    };

    this.topology = {
      nodes: [],
      edges: [],
      zones: []
    };
  }

  /**
   * Run a full network mapping scan
   */
  async scan(): Promise<AuditResult> {
    const startTime = new Date();
    this.findings = [];
    this.topology = { nodes: [], edges: [], zones: [] };

    try {
      // Phase 1: Discover hosts
      if (this.config.discoverHosts) {
        await this.discoverHosts();
      }

      // Phase 2: Scan ports on discovered hosts
      if (this.config.scanPorts) {
        await this.scanAllPorts();
      }

      // Phase 3: Detect services
      if (this.config.detectServices) {
        await this.detectServices();
      }

      // Phase 4: Map topology and connections
      if (this.config.mapTopology) {
        await this.mapConnections();
      }

      // Phase 5: Analyze for security issues
      await this.analyzeExposure();

      const endTime = new Date();
      return this.generateReport(startTime, endTime);
    } catch (error) {
      return {
        auditId: uuidv4(),
        scanType: ScanType.NETWORK_MAPPING,
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
   * Discover hosts on the network
   */
  private async discoverHosts(): Promise<void> {
    // Get local network interfaces
    const interfaces = await this.getNetworkInterfaces();

    for (const iface of interfaces) {
      const node: NetworkNode = {
        id: uuidv4(),
        hostname: 'localhost',
        ipAddress: iface.address,
        type: 'server',
        ports: [],
        metadata: {
          interface: iface.name,
          netmask: iface.netmask
        }
      };
      this.topology.nodes.push(node);
    }

    // Try to discover Docker networks
    await this.discoverDockerNetworks();

    // Try to discover Kubernetes services
    await this.discoverKubernetesServices();
  }

  /**
   * Get network interfaces
   */
  private async getNetworkInterfaces(): Promise<NetworkInterface[]> {
    const interfaces: NetworkInterface[] = [];

    try {
      const { stdout } = await execAsync(
        "ip -j addr show 2>/dev/null || ifconfig -a 2>/dev/null | grep 'inet ' || echo '[]'"
      );

      // Try to parse JSON (Linux ip command)
      try {
        const parsed = JSON.parse(stdout);
        for (const iface of parsed) {
          if (iface.addr_info) {
            for (const addr of iface.addr_info) {
              if (addr.family === 'inet' && addr.local !== '127.0.0.1') {
                interfaces.push({
                  name: iface.ifname,
                  address: addr.local,
                  netmask: this.cidrToNetmask(addr.prefixlen)
                });
              }
            }
          }
        }
      } catch {
        // Parse ifconfig output
        const lines = stdout.split('\n');
        for (const line of lines) {
          const match = line.match(/inet\s+(\d+\.\d+\.\d+\.\d+)/);
          if (match && match[1] !== '127.0.0.1') {
            interfaces.push({
              name: 'unknown',
              address: match[1],
              netmask: '255.255.255.0'
            });
          }
        }
      }
    } catch {
      // Default to localhost if we can't get interfaces
      interfaces.push({
        name: 'lo',
        address: '127.0.0.1',
        netmask: '255.0.0.0'
      });
    }

    return interfaces;
  }

  /**
   * Discover Docker networks and containers
   */
  private async discoverDockerNetworks(): Promise<void> {
    try {
      const { stdout } = await execAsync(
        'docker network ls --format "{{.Name}}" 2>/dev/null || echo ""'
      );

      const networks = stdout.split('\n').filter(Boolean);

      for (const network of networks) {
        const { stdout: inspectOutput } = await execAsync(
          `docker network inspect ${network} --format '{{json .}}' 2>/dev/null || echo '{}'`
        );

        try {
          const networkInfo = JSON.parse(inspectOutput);

          // Create a zone for this Docker network
          const zone: NetworkZone = {
            id: uuidv4(),
            name: `docker-${network}`,
            type: network === 'bridge' ? 'private' : 'restricted',
            nodes: []
          };

          // Add containers in this network
          if (networkInfo.Containers) {
            for (const [containerId, container] of Object.entries(networkInfo.Containers)) {
              const containerInfo = container as { Name: string; IPv4Address: string };
              const node: NetworkNode = {
                id: containerId.substring(0, 12),
                hostname: containerInfo.Name,
                ipAddress: containerInfo.IPv4Address?.split('/')[0] || '',
                type: 'container',
                ports: [],
                metadata: { network }
              };

              this.topology.nodes.push(node);
              zone.nodes.push(node.id);
            }
          }

          this.topology.zones.push(zone);
        } catch {
          // Skip invalid JSON
        }
      }
    } catch {
      // Docker not available
    }
  }

  /**
   * Discover Kubernetes services
   */
  private async discoverKubernetesServices(): Promise<void> {
    try {
      const { stdout } = await execAsync(
        'kubectl get services -A -o json 2>/dev/null || echo "{}"'
      );

      const services = JSON.parse(stdout);

      if (services.items) {
        for (const service of services.items) {
          const node: NetworkNode = {
            id: uuidv4(),
            hostname: `${service.metadata.name}.${service.metadata.namespace}`,
            ipAddress: service.spec.clusterIP || '',
            type: 'service',
            ports: (service.spec.ports || []).map((port: { port: number; targetPort: number; protocol: string }) => ({
              port: port.port,
              protocol: port.protocol?.toLowerCase() || 'tcp',
              state: 'open' as const,
              service: service.metadata.name,
              exposed: service.spec.type === 'LoadBalancer' || service.spec.type === 'NodePort'
            })),
            metadata: {
              namespace: service.metadata.namespace,
              type: service.spec.type
            }
          };

          this.topology.nodes.push(node);

          // Check for exposed services
          if (service.spec.type === 'LoadBalancer' || service.spec.type === 'NodePort') {
            this.addFinding({
              id: uuidv4(),
              type: 'k8s_exposed_service',
              severity: SeverityLevel.MEDIUM,
              title: `Kubernetes service exposed externally: ${service.metadata.name}`,
              description: `Service ${service.metadata.name} in namespace ${service.metadata.namespace} is exposed via ${service.spec.type}`,
              location: `${service.metadata.namespace}/${service.metadata.name}`,
              evidence: [`Type: ${service.spec.type}`, `Ports: ${JSON.stringify(service.spec.ports)}`],
              remediation: 'Review if external exposure is necessary. Consider using ClusterIP with an ingress controller instead.',
              sourceHost: service.spec.clusterIP || '',
              port: service.spec.ports?.[0]?.port || 0,
              protocol: 'tcp',
              exposureType: 'public',
              serviceIdentified: service.metadata.name,
              detectedAt: new Date(),
              status: 'open'
            });
          }
        }
      }
    } catch {
      // Kubernetes not available
    }
  }

  /**
   * Scan ports on all discovered hosts
   */
  private async scanAllPorts(): Promise<void> {
    for (const node of this.topology.nodes) {
      if (node.ipAddress && node.ipAddress !== '127.0.0.1') {
        await this.scanNodePorts(node);
      }
    }

    // Also scan localhost
    await this.scanLocalPorts();
  }

  /**
   * Scan local listening ports
   */
  private async scanLocalPorts(): Promise<void> {
    try {
      const { stdout } = await execAsync(
        'ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || echo ""'
      );

      const lines = stdout.split('\n');
      const localNode = this.topology.nodes.find(n => n.hostname === 'localhost') || {
        id: 'localhost',
        hostname: 'localhost',
        ipAddress: '127.0.0.1',
        type: 'server' as const,
        ports: []
      };

      for (const line of lines) {
        if (!line.includes('LISTEN')) continue;

        // Parse the listening address and port
        const match = line.match(/(\*|0\.0\.0\.0|127\.0\.0\.1|::|\[::\]):(\d+)/);
        if (match) {
          const bindAddress = match[1];
          const port = parseInt(match[2], 10);

          const portInfo: PortInfo = {
            port,
            protocol: 'tcp',
            state: 'open',
            service: WELL_KNOWN_PORTS[port]?.service,
            exposed: bindAddress === '*' || bindAddress === '0.0.0.0' || bindAddress === '::' || bindAddress === '[::]'
          };

          localNode.ports.push(portInfo);
        }
      }

      if (!this.topology.nodes.find(n => n.id === 'localhost')) {
        this.topology.nodes.push(localNode as NetworkNode);
      }
    } catch {
      // Commands not available
    }
  }

  /**
   * Scan ports on a specific node
   */
  private async scanNodePorts(node: NetworkNode): Promise<void> {
    // For non-local nodes, we'd need nmap or similar
    // This is a placeholder for actual port scanning
    // In production, you'd use a proper scanner or agent on each host

    try {
      // Try to get port info from Docker if it's a container
      if (node.type === 'container') {
        const { stdout } = await execAsync(
          `docker inspect ${node.id} --format '{{json .NetworkSettings.Ports}}' 2>/dev/null || echo '{}'`
        );

        const ports = JSON.parse(stdout);
        for (const [containerPort, hostBindings] of Object.entries(ports)) {
          const [portNum, protocol] = containerPort.split('/');
          const binding = hostBindings as Array<{ HostIp: string; HostPort: string }> | null;

          node.ports.push({
            port: parseInt(portNum, 10),
            protocol: protocol as 'tcp' | 'udp',
            state: 'open',
            exposed: binding !== null && binding.length > 0
          });
        }
      }
    } catch {
      // Skip if we can't inspect
    }
  }

  /**
   * Detect services running on open ports
   */
  private async detectServices(): Promise<void> {
    for (const node of this.topology.nodes) {
      for (const port of node.ports) {
        if (!port.service && WELL_KNOWN_PORTS[port.port]) {
          port.service = WELL_KNOWN_PORTS[port.port].service;
        }
      }
    }
  }

  /**
   * Map network connections between nodes
   */
  private async mapConnections(): Promise<void> {
    try {
      // Get established connections
      const { stdout } = await execAsync(
        'ss -tnp 2>/dev/null || netstat -tnp 2>/dev/null || echo ""'
      );

      const lines = stdout.split('\n');

      for (const line of lines) {
        if (!line.includes('ESTAB')) continue;

        // Parse source and destination
        const parts = line.split(/\s+/);
        const localAddr = parts[3] || '';
        const remoteAddr = parts[4] || '';

        if (localAddr && remoteAddr) {
          const [localIp, localPort] = this.parseAddress(localAddr);
          const [remoteIp, remotePort] = this.parseAddress(remoteAddr);

          if (localIp && remoteIp) {
            const edge: NetworkEdge = {
              source: localIp,
              target: remoteIp,
              port: parseInt(remotePort, 10),
              protocol: 'tcp',
              encrypted: this.isLikelyEncrypted(parseInt(remotePort, 10)),
              bidirectional: false
            };

            this.topology.edges.push(edge);
          }
        }
      }
    } catch {
      // Commands not available
    }
  }

  /**
   * Analyze network exposure and generate findings
   */
  private async analyzeExposure(): Promise<void> {
    for (const node of this.topology.nodes) {
      for (const port of node.ports) {
        if (!port.exposed) continue;

        const portInfo = WELL_KNOWN_PORTS[port.port];

        // Check if port should be internal-only but is exposed
        if (portInfo && portInfo.expectedExposure === 'internal') {
          const severity = this.getExposureSeverity(port.port);

          this.addFinding({
            id: uuidv4(),
            type: 'unnecessary_exposure',
            severity,
            title: `${portInfo.service} unnecessarily exposed`,
            description: `Port ${port.port} (${portInfo.service}) is exposed externally but should typically be internal-only. Risk: ${portInfo.risk}`,
            location: `${node.hostname}:${port.port}`,
            evidence: [`Port: ${port.port}`, `Service: ${portInfo.service}`, `Bound to: 0.0.0.0`],
            remediation: `Bind ${portInfo.service} to localhost (127.0.0.1) or use a firewall to restrict access. If external access is needed, use a VPN or SSH tunnel.`,
            sourceHost: node.ipAddress,
            port: port.port,
            protocol: port.protocol,
            exposureType: 'external',
            serviceIdentified: portInfo.service,
            detectedAt: new Date(),
            status: 'open'
          });
        }

        // Check for unencrypted protocols exposed externally
        if (this.isUnencryptedProtocol(port.port)) {
          this.addFinding({
            id: uuidv4(),
            type: 'unencrypted_exposure',
            severity: SeverityLevel.HIGH,
            title: `Unencrypted protocol exposed: ${port.service || port.port}`,
            description: `Port ${port.port} uses an unencrypted protocol and is exposed externally`,
            location: `${node.hostname}:${port.port}`,
            evidence: [`Port: ${port.port}`, `Protocol: ${port.service || 'unknown'}`],
            remediation: 'Use encrypted alternatives (HTTPS instead of HTTP, SFTP instead of FTP, SSH instead of Telnet)',
            sourceHost: node.ipAddress,
            port: port.port,
            protocol: port.protocol,
            exposureType: 'external',
            serviceIdentified: port.service,
            detectedAt: new Date(),
            status: 'open'
          });
        }
      }
    }

    // Check for missing zones/segmentation
    await this.analyzeSegmentation();
  }

  /**
   * Analyze network segmentation
   */
  private async analyzeSegmentation(): Promise<void> {
    // Check if databases are in the same zone as web servers
    const dbNodes = this.topology.nodes.filter(n =>
      n.ports.some(p => [3306, 5432, 27017, 6379, 9200].includes(p.port))
    );

    const webNodes = this.topology.nodes.filter(n =>
      n.ports.some(p => [80, 443, 8080, 8443].includes(p.port))
    );

    // If both exist and no zones defined, suggest segmentation
    if (dbNodes.length > 0 && webNodes.length > 0 && this.topology.zones.length === 0) {
      this.addFinding({
        id: uuidv4(),
        type: 'missing_segmentation',
        severity: SeverityLevel.MEDIUM,
        title: 'Network segmentation not detected',
        description: 'Database and web services appear to be on the same network without segmentation',
        location: 'Network topology',
        evidence: [
          `Database nodes: ${dbNodes.map(n => n.hostname).join(', ')}`,
          `Web nodes: ${webNodes.map(n => n.hostname).join(', ')}`
        ],
        remediation: 'Implement network segmentation using VLANs, subnets, or network policies to isolate database tier from web tier',
        sourceHost: '',
        port: 0,
        protocol: '',
        exposureType: 'internal',
        detectedAt: new Date(),
        status: 'open'
      });
    }
  }

  private parseAddress(addr: string): [string, string] {
    // Handle IPv4 and IPv6 addresses
    if (addr.includes('[')) {
      // IPv6: [::1]:22
      const match = addr.match(/\[([^\]]+)\]:(\d+)/);
      return match ? [match[1], match[2]] : ['', ''];
    } else {
      // IPv4: 192.168.1.1:22
      const parts = addr.split(':');
      return [parts[0], parts[1] || ''];
    }
  }

  private getExposureSeverity(port: number): SeverityLevel {
    // Critical: Management interfaces, databases, Docker
    const critical = [2375, 22, 23, 3389, 5900];
    if (critical.includes(port)) return SeverityLevel.CRITICAL;

    // High: Databases, caches
    const high = [3306, 5432, 27017, 6379, 9200, 11211];
    if (high.includes(port)) return SeverityLevel.HIGH;

    return SeverityLevel.MEDIUM;
  }

  private isUnencryptedProtocol(port: number): boolean {
    const unencrypted = [20, 21, 23, 25, 80, 110, 143, 5672];
    return unencrypted.includes(port);
  }

  private isLikelyEncrypted(port: number): boolean {
    const encrypted = [22, 443, 465, 993, 995, 2376, 5671, 8443];
    return encrypted.includes(port);
  }

  private cidrToNetmask(cidr: number): string {
    const mask = [];
    for (let i = 0; i < 4; i++) {
      const bits = Math.min(8, Math.max(0, cidr - i * 8));
      mask.push(256 - Math.pow(2, 8 - bits));
    }
    return mask.join('.');
  }

  private addFinding(finding: NetworkFinding): void {
    const exists = this.findings.some(
      f => f.location === finding.location && f.type === finding.type
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

    if (this.findings.some(f => f.type === 'unnecessary_exposure')) {
      recommendations.push('Review and restrict exposed services to necessary interfaces only');
    }
    if (this.findings.some(f => f.type === 'unencrypted_exposure')) {
      recommendations.push('Migrate all external-facing services to encrypted protocols');
    }
    if (this.findings.some(f => f.type === 'missing_segmentation')) {
      recommendations.push('Implement network segmentation between service tiers');
    }

    return recommendations;
  }

  private generateReport(startTime: Date, endTime: Date): AuditResult {
    return {
      auditId: uuidv4(),
      scanType: ScanType.NETWORK_MAPPING,
      status: AuditStatus.COMPLETED,
      startTime,
      endTime,
      duration: endTime.getTime() - startTime.getTime(),
      findings: this.findings,
      summary: this.generateSummary(),
      metadata: {
        topology: this.topology,
        nodesDiscovered: this.topology.nodes.length,
        zonesIdentified: this.topology.zones.length,
        connectionsMappped: this.topology.edges.length
      }
    };
  }

  /**
   * Get the discovered network topology
   */
  getTopology(): NetworkTopology {
    return this.topology;
  }
}

interface NetworkInterface {
  name: string;
  address: string;
  netmask: string;
}

export default NetworkMapper;
