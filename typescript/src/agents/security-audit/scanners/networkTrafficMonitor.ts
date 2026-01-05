/**
 * Network Traffic Monitor
 *
 * Monitors outbound connections to detect:
 * - Applications "phoning home" to external servers
 * - Suspicious destinations (known C2, unusual geolocations)
 * - Data exfiltration patterns
 * - Unexpected network activity from processes
 *
 * Uses: netstat, ss, conntrack, and optionally eBPF/tcpdump
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import { EventEmitter } from 'events';
import * as fs from 'fs/promises';
import * as dns from 'dns/promises';
import { AgentEventBus, eventBus, SourceLogger } from '../utils/eventBus';
import { v4 as uuidv4 } from 'uuid';

const execAsync = promisify(exec);

// ============================================================================
// Types
// ============================================================================

export interface NetworkMonitorConfig {
  /** Monitoring interval in ms */
  interval: number;
  /** Track connections by process */
  trackProcesses: boolean;
  /** Alert on connections to these countries (ISO codes) */
  suspiciousCountries?: string[];
  /** Alert on connections to these IP ranges */
  suspiciousIpRanges?: string[];
  /** Known C2/malware domains to watch for */
  knownBadDomains?: string[];
  /** Known C2/malware IPs */
  knownBadIps?: string[];
  /** Whitelist - never alert on these destinations */
  whitelistedDestinations?: string[];
  /** Whitelist - never alert on connections from these processes */
  whitelistedProcesses?: string[];
  /** Alert on any new outbound connection (noisy but thorough) */
  alertOnNewConnections: boolean;
  /** Track data volume per connection */
  trackDataVolume: boolean;
  /** Threshold for data exfil alert (bytes per minute) */
  dataExfilThreshold?: number;
  /** DNS monitoring - track lookups */
  monitorDns: boolean;
  /** Path to save connection history */
  historyPath?: string;
  /** Max history entries to keep */
  maxHistoryEntries?: number;
  /** GeoIP database path (MaxMind format) */
  geoipDbPath?: string;
}

export interface NetworkConnection {
  id: string;
  timestamp: Date;
  protocol: 'tcp' | 'udp' | 'tcp6' | 'udp6';
  localAddress: string;
  localPort: number;
  remoteAddress: string;
  remotePort: number;
  state: string;
  process?: {
    pid: number;
    name: string;
    cmdline?: string;
    user?: string;
  };
  direction: 'inbound' | 'outbound' | 'unknown';
  resolved?: {
    hostname?: string;
    country?: string;
    org?: string;
    asn?: string;
  };
  bytesIn?: number;
  bytesOut?: number;
  duration?: number;
  flags?: string[];
}

export interface PhoneHomeAlert {
  id: string;
  timestamp: Date;
  severity: 'info' | 'warning' | 'critical';
  type: 'new_connection' | 'suspicious_destination' | 'known_bad' | 'data_exfil' | 'unusual_port' | 'dns_suspicious';
  connection: NetworkConnection;
  reason: string;
  details: Record<string, unknown>;
  recommendations: string[];
}

export interface DnsQuery {
  timestamp: Date;
  query: string;
  type: string;
  response?: string[];
  process?: {
    pid: number;
    name: string;
  };
  suspicious: boolean;
  reason?: string;
}

// ============================================================================
// Known bad indicators (basic set - should be updated from threat feeds)
// ============================================================================

const DEFAULT_BAD_DOMAINS = [
  // Common DGA patterns
  /^[a-z0-9]{20,}\.(com|net|org|info|xyz|top)$/i,
  // Known malware domains (examples - real list would come from threat intel)
  /\.onion\./i,
  /pastebin\.com/i,
  /raw\.githubusercontent\.com/i,  // Often used for malware hosting
];

const DEFAULT_SUSPICIOUS_PORTS = [
  4444,   // Metasploit default
  5555,   // Android debug / common backdoor
  6666, 6667, 6668, 6669,  // IRC (C2)
  8080, 8443,  // Alt HTTP (not inherently bad but watch)
  1337,   // "leet" port
  31337,  // Back Orifice
  12345, 12346,  // NetBus
  27374,  // SubSeven
  1234,   // Common test backdoor
];

const DEFAULT_SUSPICIOUS_COUNTRIES = [
  // Countries often associated with APTs - adjust based on your threat model
  // This is a sensitive list - customize for your needs
];

// ============================================================================
// Network Monitor Implementation
// ============================================================================

export class NetworkTrafficMonitor extends EventEmitter {
  private config: NetworkMonitorConfig;
  private logger: SourceLogger;
  private bus: AgentEventBus;
  private running: boolean = false;
  private intervalHandle?: NodeJS.Timeout;

  private connectionHistory: Map<string, NetworkConnection> = new Map();
  private seenConnections: Set<string> = new Set();  // For new connection detection
  private connectionBaseline: Map<string, number> = new Map();  // process -> typical connection count
  private dnsHistory: DnsQuery[] = [];
  private alerts: PhoneHomeAlert[] = [];

  constructor(config?: Partial<NetworkMonitorConfig>, bus?: AgentEventBus) {
    super();

    this.bus = bus || eventBus;
    this.logger = this.bus.createLogger('NetworkTrafficMonitor');

    this.config = {
      interval: config?.interval ?? 5000,  // 5 seconds
      trackProcesses: config?.trackProcesses ?? true,
      suspiciousCountries: config?.suspiciousCountries ?? DEFAULT_SUSPICIOUS_COUNTRIES,
      suspiciousIpRanges: config?.suspiciousIpRanges ?? [],
      knownBadDomains: config?.knownBadDomains ?? [],
      knownBadIps: config?.knownBadIps ?? [],
      whitelistedDestinations: config?.whitelistedDestinations ?? [
        '127.0.0.1', '::1', 'localhost',
        '*.google.com', '*.googleapis.com',
        '*.microsoft.com', '*.windows.com',
        '*.ubuntu.com', '*.debian.org',
        '*.github.com', '*.githubusercontent.com',
      ],
      whitelistedProcesses: config?.whitelistedProcesses ?? [
        'systemd-resolve', 'systemd-timesyncd',
        'snapd', 'packagekitd',
      ],
      alertOnNewConnections: config?.alertOnNewConnections ?? false,
      trackDataVolume: config?.trackDataVolume ?? true,
      dataExfilThreshold: config?.dataExfilThreshold ?? 10 * 1024 * 1024,  // 10MB/min
      monitorDns: config?.monitorDns ?? true,
      historyPath: config?.historyPath ?? '/var/lib/security-audit/network-history.json',
      maxHistoryEntries: config?.maxHistoryEntries ?? 10000,
      geoipDbPath: config?.geoipDbPath
    };

    this.logger.info('network', 'initialized', 'Network traffic monitor initialized', {
      interval: this.config.interval,
      trackProcesses: this.config.trackProcesses,
      alertOnNewConnections: this.config.alertOnNewConnections
    });
  }

  // ==========================================================================
  // Lifecycle
  // ==========================================================================

  /**
   * Start monitoring network traffic
   */
  async start(): Promise<void> {
    if (this.running) {
      this.logger.warning('network', 'already_running', 'Monitor already running');
      return;
    }

    this.running = true;
    this.logger.info('network', 'started', 'Network traffic monitoring started');

    // Load history
    await this.loadHistory();

    // Initial scan to build baseline
    await this.scan();

    // Start periodic monitoring
    this.intervalHandle = setInterval(() => {
      this.scan().catch(err => {
        this.logger.error('network', 'scan_error', 'Error during network scan', {}, err);
      });
    }, this.config.interval);

    this.emit('started');
  }

  /**
   * Stop monitoring
   */
  async stop(): Promise<void> {
    if (!this.running) return;

    this.running = false;

    if (this.intervalHandle) {
      clearInterval(this.intervalHandle);
      this.intervalHandle = undefined;
    }

    // Save history
    await this.saveHistory();

    this.logger.info('network', 'stopped', 'Network traffic monitoring stopped');
    this.emit('stopped');
  }

  // ==========================================================================
  // Main Scan Loop
  // ==========================================================================

  /**
   * Perform a network scan
   */
  async scan(): Promise<NetworkConnection[]> {
    const connections = await this.getConnections();

    for (const conn of connections) {
      // Generate unique key for this connection
      const connKey = `${conn.localAddress}:${conn.localPort}-${conn.remoteAddress}:${conn.remotePort}-${conn.process?.pid || 'unknown'}`;

      // Check if this is a new connection
      const isNew = !this.seenConnections.has(connKey);
      if (isNew) {
        this.seenConnections.add(connKey);

        // Resolve hostname and geo if possible
        conn.resolved = await this.resolveConnection(conn);

        // Store in history
        this.connectionHistory.set(conn.id, conn);

        // Check for alerts
        await this.analyzeConnection(conn, isNew);
      }
    }

    // Prune old entries
    this.pruneHistory();

    return connections;
  }

  /**
   * Get current network connections
   */
  private async getConnections(): Promise<NetworkConnection[]> {
    const connections: NetworkConnection[] = [];

    try {
      // Try ss first (faster, more info)
      const { stdout } = await execAsync(
        'ss -tupn state established 2>/dev/null || netstat -tupn 2>/dev/null',
        { maxBuffer: 10 * 1024 * 1024 }
      );

      const lines = stdout.split('\n').slice(1);  // Skip header

      for (const line of lines) {
        const conn = this.parseConnectionLine(line);
        if (conn && conn.remoteAddress !== '0.0.0.0' && conn.remoteAddress !== '::') {
          // Determine direction
          conn.direction = this.isOutbound(conn) ? 'outbound' : 'inbound';

          // Get process info if enabled
          if (this.config.trackProcesses && conn.process?.pid) {
            conn.process = await this.getProcessInfo(conn.process.pid);
          }

          connections.push(conn);
        }
      }
    } catch (error) {
      this.logger.warning('network', 'connection_list_error', 'Failed to list connections', {},
        error instanceof Error ? error : undefined);
    }

    return connections;
  }

  /**
   * Parse a connection line from ss/netstat output
   */
  private parseConnectionLine(line: string): NetworkConnection | null {
    // ss format: Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
    // netstat format: Proto Recv-Q Send-Q Local Address Foreign Address State PID/Program

    const parts = line.trim().split(/\s+/);
    if (parts.length < 5) return null;

    try {
      let protocol: NetworkConnection['protocol'];
      let localAddr: string, localPort: number;
      let remoteAddr: string, remotePort: number;
      let state: string;
      let pid: number | undefined;
      let processName: string | undefined;

      if (line.includes('ESTAB') || line.includes('ESTABLISHED')) {
        // ss format
        protocol = parts[0].toLowerCase() as NetworkConnection['protocol'];
        state = parts[1];

        const localParts = parts[4].split(':');
        localPort = parseInt(localParts.pop()!, 10);
        localAddr = localParts.join(':');

        const remoteParts = parts[5].split(':');
        remotePort = parseInt(remoteParts.pop()!, 10);
        remoteAddr = remoteParts.join(':');

        // Parse process info: users:(("process",pid=123,fd=4))
        const processMatch = line.match(/users:\(\("([^"]+)",pid=(\d+)/);
        if (processMatch) {
          processName = processMatch[1];
          pid = parseInt(processMatch[2], 10);
        }
      } else {
        // netstat format
        protocol = parts[0].toLowerCase() as NetworkConnection['protocol'];

        const localParts = parts[3].split(':');
        localPort = parseInt(localParts.pop()!, 10);
        localAddr = localParts.join(':') || '0.0.0.0';

        const remoteParts = parts[4].split(':');
        remotePort = parseInt(remoteParts.pop()!, 10);
        remoteAddr = remoteParts.join(':');

        state = parts[5] || 'UNKNOWN';

        // Parse PID/Program
        const pidProgram = parts[6];
        if (pidProgram && pidProgram.includes('/')) {
          const [pidStr, name] = pidProgram.split('/');
          pid = parseInt(pidStr, 10);
          processName = name;
        }
      }

      return {
        id: uuidv4(),
        timestamp: new Date(),
        protocol,
        localAddress: localAddr,
        localPort,
        remoteAddress: remoteAddr,
        remotePort,
        state,
        direction: 'unknown',
        process: pid ? { pid, name: processName || 'unknown' } : undefined
      };
    } catch {
      return null;
    }
  }

  /**
   * Determine if connection is outbound
   */
  private isOutbound(conn: NetworkConnection): boolean {
    // Common server ports that would indicate inbound
    const serverPorts = [22, 80, 443, 8080, 8443, 3000, 5000, 5432, 3306, 6379, 27017];

    // If local port is a well-known server port, it's likely inbound
    if (serverPorts.includes(conn.localPort)) {
      return false;
    }

    // If remote port is a well-known server port, it's likely outbound
    if (serverPorts.includes(conn.remotePort)) {
      return true;
    }

    // Ephemeral ports (high numbers) on local side usually indicate outbound
    if (conn.localPort > 32768) {
      return true;
    }

    return false;
  }

  /**
   * Get detailed process info
   */
  private async getProcessInfo(pid: number): Promise<NetworkConnection['process']> {
    try {
      const [cmdline, status] = await Promise.all([
        fs.readFile(`/proc/${pid}/cmdline`, 'utf-8').catch(() => ''),
        fs.readFile(`/proc/${pid}/status`, 'utf-8').catch(() => '')
      ]);

      const nameMatch = status.match(/^Name:\s+(.+)$/m);
      const uidMatch = status.match(/^Uid:\s+(\d+)/m);

      let user: string | undefined;
      if (uidMatch) {
        try {
          const { stdout } = await execAsync(`getent passwd ${uidMatch[1]} | cut -d: -f1`);
          user = stdout.trim();
        } catch {
          user = `uid:${uidMatch[1]}`;
        }
      }

      return {
        pid,
        name: nameMatch?.[1] || 'unknown',
        cmdline: cmdline.replace(/\0/g, ' ').trim(),
        user
      };
    } catch {
      return { pid, name: 'unknown' };
    }
  }

  // ==========================================================================
  // Resolution & Enrichment
  // ==========================================================================

  /**
   * Resolve connection details (hostname, geo)
   */
  private async resolveConnection(conn: NetworkConnection): Promise<NetworkConnection['resolved']> {
    const resolved: NetworkConnection['resolved'] = {};

    // Reverse DNS
    try {
      const hostnames = await dns.reverse(conn.remoteAddress);
      resolved.hostname = hostnames[0];
    } catch {
      // No reverse DNS
    }

    // GeoIP lookup would go here if geoipDbPath is configured
    // For now, we'll skip actual geo lookup but the structure is here

    return resolved;
  }

  // ==========================================================================
  // Analysis & Alerting
  // ==========================================================================

  /**
   * Analyze a connection for suspicious activity
   */
  private async analyzeConnection(conn: NetworkConnection, isNew: boolean): Promise<void> {
    // Skip whitelisted destinations
    if (this.isWhitelisted(conn)) {
      return;
    }

    // Skip whitelisted processes
    if (conn.process && this.config.whitelistedProcesses?.includes(conn.process.name)) {
      return;
    }

    // Only analyze outbound connections
    if (conn.direction !== 'outbound') {
      return;
    }

    const alerts: PhoneHomeAlert[] = [];

    // Check for known bad IPs
    if (this.config.knownBadIps?.includes(conn.remoteAddress)) {
      alerts.push(this.createAlert('critical', 'known_bad', conn,
        `Connection to known malicious IP: ${conn.remoteAddress}`,
        { matchedIp: conn.remoteAddress }
      ));
    }

    // Check for known bad domains
    if (conn.resolved?.hostname) {
      for (const pattern of [...DEFAULT_BAD_DOMAINS, ...(this.config.knownBadDomains || [])]) {
        const regex = typeof pattern === 'string' ? new RegExp(pattern, 'i') : pattern;
        if (regex.test(conn.resolved.hostname)) {
          alerts.push(this.createAlert('critical', 'known_bad', conn,
            `Connection to suspicious domain: ${conn.resolved.hostname}`,
            { matchedDomain: conn.resolved.hostname, pattern: regex.source }
          ));
          break;
        }
      }
    }

    // Check for suspicious ports
    if (DEFAULT_SUSPICIOUS_PORTS.includes(conn.remotePort)) {
      alerts.push(this.createAlert('warning', 'unusual_port', conn,
        `Connection to suspicious port: ${conn.remotePort}`,
        { port: conn.remotePort }
      ));
    }

    // Check for suspicious countries
    if (conn.resolved?.country && this.config.suspiciousCountries?.includes(conn.resolved.country)) {
      alerts.push(this.createAlert('warning', 'suspicious_destination', conn,
        `Connection to suspicious country: ${conn.resolved.country}`,
        { country: conn.resolved.country }
      ));
    }

    // Alert on new connections if enabled
    if (isNew && this.config.alertOnNewConnections) {
      alerts.push(this.createAlert('info', 'new_connection', conn,
        `New outbound connection: ${conn.process?.name || 'unknown'} -> ${conn.remoteAddress}:${conn.remotePort}`,
        {}
      ));
    }

    // Process alerts
    for (const alert of alerts) {
      this.alerts.push(alert);
      this.emit('alert', alert);

      // Log based on severity
      if (alert.severity === 'critical') {
        this.logger.critical('security', 'phone_home_detected',
          `🚨 PHONE HOME DETECTED: ${alert.reason}`, {
            connection: {
              process: conn.process?.name,
              pid: conn.process?.pid,
              destination: `${conn.remoteAddress}:${conn.remotePort}`,
              hostname: conn.resolved?.hostname
            },
            type: alert.type
          });
      } else if (alert.severity === 'warning') {
        this.logger.warning('security', 'suspicious_connection',
          `⚠️ Suspicious connection: ${alert.reason}`, {
            connection: {
              process: conn.process?.name,
              destination: `${conn.remoteAddress}:${conn.remotePort}`
            }
          });
      } else {
        this.logger.info('network', 'new_connection', alert.reason, {
          process: conn.process?.name,
          destination: `${conn.remoteAddress}:${conn.remotePort}`
        });
      }
    }
  }

  /**
   * Check if destination is whitelisted
   */
  private isWhitelisted(conn: NetworkConnection): boolean {
    const dest = conn.remoteAddress;
    const hostname = conn.resolved?.hostname || '';

    for (const pattern of this.config.whitelistedDestinations || []) {
      if (pattern.startsWith('*.')) {
        // Wildcard domain match
        const suffix = pattern.slice(1);  // .google.com
        if (hostname.endsWith(suffix)) {
          return true;
        }
      } else if (pattern === dest || pattern === hostname) {
        return true;
      }
    }

    // Private IP ranges are generally safe
    if (this.isPrivateIp(dest)) {
      return true;
    }

    return false;
  }

  /**
   * Check if IP is private
   */
  private isPrivateIp(ip: string): boolean {
    // IPv4 private ranges
    if (ip.startsWith('10.') ||
        ip.startsWith('192.168.') ||
        ip.match(/^172\.(1[6-9]|2[0-9]|3[0-1])\./) ||
        ip.startsWith('127.') ||
        ip === '::1' ||
        ip.startsWith('fe80:') ||
        ip.startsWith('fc') ||
        ip.startsWith('fd')) {
      return true;
    }
    return false;
  }

  /**
   * Create an alert
   */
  private createAlert(
    severity: PhoneHomeAlert['severity'],
    type: PhoneHomeAlert['type'],
    connection: NetworkConnection,
    reason: string,
    details: Record<string, unknown>
  ): PhoneHomeAlert {
    const recommendations: string[] = [];

    switch (type) {
      case 'known_bad':
        recommendations.push('Immediately isolate the affected system');
        recommendations.push('Kill the process if safe to do so');
        recommendations.push('Capture network traffic for analysis');
        recommendations.push('Check for persistence mechanisms');
        break;
      case 'suspicious_destination':
        recommendations.push('Investigate the process making this connection');
        recommendations.push('Verify this is expected behavior');
        recommendations.push('Consider blocking this destination');
        break;
      case 'unusual_port':
        recommendations.push('Verify the process legitimately needs this port');
        recommendations.push('Check for known services on this port');
        break;
      case 'data_exfil':
        recommendations.push('Investigate data being transferred');
        recommendations.push('Consider rate limiting or blocking');
        break;
      default:
        recommendations.push('Review and verify this connection is expected');
    }

    return {
      id: uuidv4(),
      timestamp: new Date(),
      severity,
      type,
      connection,
      reason,
      details,
      recommendations
    };
  }

  // ==========================================================================
  // DNS Monitoring
  // ==========================================================================

  /**
   * Monitor DNS queries (requires access to DNS logs or packet capture)
   */
  async monitorDns(): Promise<void> {
    if (!this.config.monitorDns) return;

    // This would typically integrate with:
    // 1. systemd-resolved logs
    // 2. dnsmasq logs
    // 3. tcpdump/tshark for DNS packets
    // 4. eBPF for real-time DNS monitoring

    // For now, we'll check /var/log/syslog for DNS-related entries
    try {
      const { stdout } = await execAsync(
        'journalctl -u systemd-resolved --since "1 minute ago" --no-pager 2>/dev/null | grep -i "query" || true',
        { maxBuffer: 1024 * 1024 }
      );

      // Parse and analyze DNS queries
      // This is a simplified example
      const lines = stdout.split('\n').filter(Boolean);
      for (const line of lines) {
        // Extract query info and check against patterns
        this.logger.debug('network', 'dns_query', line);
      }
    } catch {
      // DNS monitoring not available
    }
  }

  // ==========================================================================
  // History Management
  // ==========================================================================

  /**
   * Load connection history from disk
   */
  private async loadHistory(): Promise<void> {
    try {
      const data = await fs.readFile(this.config.historyPath!, 'utf-8');
      const parsed = JSON.parse(data);

      // Restore seen connections
      if (parsed.seenConnections) {
        this.seenConnections = new Set(parsed.seenConnections);
      }

      this.logger.debug('network', 'history_loaded', `Loaded ${this.seenConnections.size} known connections`);
    } catch {
      // No history file yet
    }
  }

  /**
   * Save connection history to disk
   */
  private async saveHistory(): Promise<void> {
    try {
      const dir = this.config.historyPath!.split('/').slice(0, -1).join('/');
      await fs.mkdir(dir, { recursive: true });

      const data = {
        seenConnections: Array.from(this.seenConnections).slice(-this.config.maxHistoryEntries!),
        savedAt: new Date().toISOString()
      };

      await fs.writeFile(this.config.historyPath!, JSON.stringify(data, null, 2));
    } catch (error) {
      this.logger.warning('network', 'history_save_error', 'Failed to save history', {},
        error instanceof Error ? error : undefined);
    }
  }

  /**
   * Prune old history entries
   */
  private pruneHistory(): void {
    if (this.seenConnections.size > this.config.maxHistoryEntries!) {
      const excess = this.seenConnections.size - this.config.maxHistoryEntries!;
      const arr = Array.from(this.seenConnections);
      for (let i = 0; i < excess; i++) {
        this.seenConnections.delete(arr[i]);
      }
    }
  }

  // ==========================================================================
  // Public API
  // ==========================================================================

  /**
   * Get current connections
   */
  async getCurrentConnections(): Promise<NetworkConnection[]> {
    return this.getConnections();
  }

  /**
   * Get all alerts
   */
  getAlerts(): PhoneHomeAlert[] {
    return this.alerts;
  }

  /**
   * Clear alerts
   */
  clearAlerts(): void {
    this.alerts = [];
  }

  /**
   * Add a known bad IP
   */
  addBadIp(ip: string): void {
    if (!this.config.knownBadIps) {
      this.config.knownBadIps = [];
    }
    this.config.knownBadIps.push(ip);
    this.logger.info('network', 'bad_ip_added', `Added bad IP: ${ip}`);
  }

  /**
   * Add a known bad domain
   */
  addBadDomain(domain: string): void {
    if (!this.config.knownBadDomains) {
      this.config.knownBadDomains = [];
    }
    this.config.knownBadDomains.push(domain);
    this.logger.info('network', 'bad_domain_added', `Added bad domain: ${domain}`);
  }

  /**
   * Whitelist a destination
   */
  whitelistDestination(dest: string): void {
    if (!this.config.whitelistedDestinations) {
      this.config.whitelistedDestinations = [];
    }
    this.config.whitelistedDestinations.push(dest);
    this.logger.info('network', 'destination_whitelisted', `Whitelisted: ${dest}`);
  }

  /**
   * Check if monitor is running
   */
  isRunning(): boolean {
    return this.running;
  }

  /**
   * Get connection statistics
   */
  getStats(): {
    totalConnectionsSeen: number;
    currentAlerts: number;
    criticalAlerts: number;
  } {
    return {
      totalConnectionsSeen: this.seenConnections.size,
      currentAlerts: this.alerts.length,
      criticalAlerts: this.alerts.filter(a => a.severity === 'critical').length
    };
  }
}

export default NetworkTrafficMonitor;
