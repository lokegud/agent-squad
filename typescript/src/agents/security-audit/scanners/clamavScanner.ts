/**
 * ClamAV Antivirus Scanner Integration
 *
 * Features:
 * - Full ClamAV integration (daemon + CLI modes)
 * - Event bus logging for Matrix notifications
 * - Email alerts for malware detection
 * - Malware research/lookup (VirusTotal, MalwareBazaar, local DB)
 * - Origin tracking (file metadata, git history, access logs)
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs/promises';
import * as path from 'path';
import { EventEmitter } from 'events';
import {
  SecurityFinding,
  SeverityLevel,
  AuditResult,
  AuditStatus,
  ScanType
} from '../types';
import { AgentEventBus, eventBus, SourceLogger } from '../utils/eventBus';
import { v4 as uuidv4 } from 'uuid';

const execAsync = promisify(exec);

// ============================================================================
// Configuration Types
// ============================================================================

export interface ClamAVConfig {
  /** Paths to scan */
  targets: string[];
  /** Exclude patterns */
  excludePatterns?: string[];
  /** Use clamd daemon (faster) vs clamscan */
  useDaemon?: boolean;
  /** Clamd socket path */
  socketPath?: string;
  /** Scan archives */
  scanArchives?: boolean;
  /** Max file size to scan (MB) */
  maxFileSize?: number;
  /** Max scan time (seconds) */
  maxScanTime?: number;
  /** Move infected files to quarantine */
  quarantine?: boolean;
  /** Quarantine directory */
  quarantinePath?: string;
  /** Update virus definitions before scan */
  updateDefinitions?: boolean;
  /** Email configuration (optional) */
  email?: EmailConfig;
  /** Malware research configuration */
  research?: MalwareResearchConfig;
  /** Track file origins */
  trackOrigins?: boolean;
  /** Origin tracking database path */
  originDbPath?: string;
}

export interface EmailConfig {
  /** Enable email notifications */
  enabled: boolean;
  /** SMTP host */
  host: string;
  /** SMTP port */
  port: number;
  /** Use TLS */
  secure?: boolean;
  /** SMTP username */
  username?: string;
  /** SMTP password */
  password?: string;
  /** From address */
  from: string;
  /** Recipients for alerts */
  to: string[];
  /** CC recipients */
  cc?: string[];
  /** Subject prefix */
  subjectPrefix?: string;
}

export interface MalwareResearchConfig {
  /** VirusTotal API key */
  virusTotalApiKey?: string;
  /** MalwareBazaar API key */
  malwareBazaarApiKey?: string;
  /** Local malware database path */
  localDbPath?: string;
  /** Cache research results */
  cacheResults?: boolean;
  /** Cache TTL in seconds */
  cacheTtlSeconds?: number;
}

// ============================================================================
// Finding Types
// ============================================================================

export interface MalwareFinding extends SecurityFinding {
  malwareType: 'virus' | 'trojan' | 'worm' | 'ransomware' | 'spyware' | 'adware' | 'rootkit' | 'unknown';
  malwareName: string;
  filePath: string;
  fileHash?: string;
  quarantined: boolean;
  signature?: string;
  /** Research data from external sources */
  research?: MalwareResearchResult;
  /** Origin tracking data */
  origin?: MalwareOrigin;
}

export interface MalwareResearchResult {
  /** When the research was performed */
  researchedAt: Date;
  /** VirusTotal results */
  virusTotal?: {
    detected: boolean;
    positives: number;
    total: number;
    scanDate?: string;
    permalink?: string;
    scans?: Record<string, { detected: boolean; result: string; version?: string }>;
  };
  /** MalwareBazaar results */
  malwareBazaar?: {
    found: boolean;
    firstSeen?: string;
    lastSeen?: string;
    tags?: string[];
    family?: string;
    deliveryMethod?: string;
    intelligence?: string;
  };
  /** Local database match */
  localDb?: {
    found: boolean;
    knownAs?: string[];
    firstSeenLocally?: Date;
    previousOccurrences?: number;
    notes?: string;
  };
  /** AI-generated summary */
  summary?: string;
  /** Recommended actions */
  recommendations?: string[];
  /** Related IOCs (Indicators of Compromise) */
  relatedIOCs?: {
    ips?: string[];
    domains?: string[];
    urls?: string[];
    fileHashes?: string[];
  };
}

export interface MalwareOrigin {
  /** How the file arrived */
  deliveryMethod?: 'download' | 'email' | 'usb' | 'network_share' | 'git' | 'package_manager' | 'unknown';
  /** File creation time */
  createdAt?: Date;
  /** File modification time */
  modifiedAt?: Date;
  /** File access time */
  accessedAt?: Date;
  /** File owner */
  owner?: string;
  /** File group */
  group?: string;
  /** Original permissions */
  permissions?: string;
  /** Git information if in a repo */
  git?: {
    inRepo: boolean;
    commitHash?: string;
    commitAuthor?: string;
    commitDate?: string;
    commitMessage?: string;
    branch?: string;
  };
  /** Package manager info */
  packageManager?: {
    manager: 'npm' | 'pip' | 'gem' | 'composer' | 'cargo' | 'go' | 'other';
    package?: string;
    version?: string;
    installedAt?: Date;
  };
  /** Network origin if available */
  network?: {
    sourceIp?: string;
    sourceHost?: string;
    downloadUrl?: string;
    userAgent?: string;
    timestamp?: Date;
  };
  /** Parent process that created the file */
  parentProcess?: string;
  /** User who created/downloaded the file */
  createdBy?: string;
  /** Investigation notes */
  notes?: string[];
}

export interface ClamAVScanResult extends AuditResult {
  findings: MalwareFinding[];
  filesScanned: number;
  infectedFiles: number;
  dataScanned: string;
  definitionsVersion?: string;
}

// ============================================================================
// Research Cache
// ============================================================================

interface ResearchCacheEntry {
  hash: string;
  result: MalwareResearchResult;
  cachedAt: Date;
  expiresAt: Date;
}

// ============================================================================
// ClamAV Scanner Implementation
// ============================================================================

export class ClamAVScanner extends EventEmitter {
  private config: ClamAVConfig;
  private findings: MalwareFinding[] = [];
  private clamavAvailable: boolean = false;
  private definitionsVersion?: string;
  private logger: SourceLogger;
  private bus: AgentEventBus;
  private researchCache: Map<string, ResearchCacheEntry> = new Map();
  private originDb: Map<string, MalwareOrigin[]> = new Map();

  constructor(config?: Partial<ClamAVConfig>, bus?: AgentEventBus) {
    super();

    this.bus = bus || eventBus;
    this.logger = this.bus.createLogger('ClamAVScanner');

    this.config = {
      targets: config?.targets ?? [process.cwd()],
      excludePatterns: config?.excludePatterns ?? ['node_modules', '.git', 'vendor'],
      useDaemon: config?.useDaemon ?? true,
      socketPath: config?.socketPath ?? '/var/run/clamav/clamd.ctl',
      scanArchives: config?.scanArchives ?? true,
      maxFileSize: config?.maxFileSize ?? 100,
      maxScanTime: config?.maxScanTime ?? 300,
      quarantine: config?.quarantine ?? false,
      quarantinePath: config?.quarantinePath ?? '/var/quarantine',
      updateDefinitions: config?.updateDefinitions ?? false,
      email: config?.email,
      research: config?.research ?? { cacheResults: true, cacheTtlSeconds: 86400 },
      trackOrigins: config?.trackOrigins ?? true,
      originDbPath: config?.originDbPath ?? '/var/lib/security-audit/malware-origins.json'
    };

    this.logger.info('scan', 'initialized', 'ClamAV scanner initialized', {
      targets: this.config.targets,
      useDaemon: this.config.useDaemon,
      quarantine: this.config.quarantine,
      emailEnabled: this.config.email?.enabled,
      researchEnabled: !!this.config.research?.virusTotalApiKey
    });

    // Load origin database
    this.loadOriginDb();
  }

  // ==========================================================================
  // Availability & Setup
  // ==========================================================================

  /**
   * Check if ClamAV is available
   */
  async checkAvailability(): Promise<{ available: boolean; version?: string; daemon: boolean }> {
    let version: string | undefined;
    let daemonAvailable = false;

    // Check clamscan
    try {
      const { stdout } = await execAsync('clamscan --version 2>/dev/null');
      version = stdout.trim();
      this.clamavAvailable = true;
      this.logger.debug('scan', 'availability_check', 'ClamAV CLI available', { version });
    } catch {
      this.clamavAvailable = false;
      this.logger.warning('scan', 'availability_check', 'ClamAV CLI not available');
    }

    // Check clamd daemon
    if (this.config.useDaemon) {
      try {
        await execAsync('clamdscan --version 2>/dev/null');
        daemonAvailable = true;
        this.logger.debug('scan', 'availability_check', 'ClamAV daemon available');
      } catch {
        daemonAvailable = false;
        this.logger.notice('scan', 'availability_check', 'ClamAV daemon not available, will use CLI');
      }
    }

    return {
      available: this.clamavAvailable,
      version,
      daemon: daemonAvailable
    };
  }

  /**
   * Update virus definitions
   */
  async updateDefinitions(): Promise<{ success: boolean; message: string }> {
    this.logger.info('scan', 'update_definitions', 'Updating virus definitions');

    try {
      const { stdout, stderr } = await execAsync('sudo freshclam 2>&1 || freshclam 2>&1');
      const output = stdout + stderr;

      if (output.includes('Database updated') || output.includes('is up to date')) {
        this.logger.info('scan', 'definitions_updated', 'Virus definitions updated successfully');
        return { success: true, message: 'Virus definitions updated successfully' };
      }

      return { success: true, message: output.trim() };
    } catch (error) {
      const message = `Failed to update definitions: ${error instanceof Error ? error.message : String(error)}`;
      this.logger.error('scan', 'update_failed', message, {}, error instanceof Error ? error : undefined);
      return { success: false, message };
    }
  }

  // ==========================================================================
  // Main Scan Methods
  // ==========================================================================

  /**
   * Run a malware scan
   */
  async scan(): Promise<ClamAVScanResult> {
    const startTime = new Date();
    const correlationId = this.bus.startCorrelation('malware-scan');
    this.findings = [];

    this.logger.info('scan', 'start', 'Starting malware scan', {
      targets: this.config.targets,
      excludePatterns: this.config.excludePatterns
    });

    // Check availability
    const availability = await this.checkAvailability();
    if (!availability.available) {
      this.logger.error('scan', 'not_available', 'ClamAV not installed');
      this.bus.endCorrelation();
      return this.createResult(startTime, AuditStatus.FAILED, {
        error: 'ClamAV not installed. Install with: apt-get install clamav clamav-daemon'
      });
    }

    // Update definitions if requested
    if (this.config.updateDefinitions) {
      await this.updateDefinitions();
    }

    // Get definitions version
    await this.getDefinitionsVersion();

    try {
      let filesScanned = 0;
      let dataScanned = '0 MB';

      for (const target of this.config.targets) {
        this.logger.info('scan', 'scanning_target', `Scanning: ${target}`);
        const result = await this.scanTarget(target);
        filesScanned += result.filesScanned;
        dataScanned = result.dataScanned;
      }

      const endTime = new Date();

      // Process findings with research and origin tracking
      for (const finding of this.findings) {
        // Research malware
        if (finding.fileHash) {
          finding.research = await this.researchMalware(finding.fileHash, finding.malwareName);
        }

        // Track origin
        if (this.config.trackOrigins) {
          finding.origin = await this.trackOrigin(finding.filePath);
        }
      }

      // Send notifications
      if (this.findings.length > 0) {
        await this.sendAlerts();
      }

      this.logger.info('scan', 'complete', `Scan complete: ${filesScanned} files, ${this.findings.length} infections`, {
        filesScanned,
        infectedFiles: this.findings.length,
        dataScanned
      });

      this.bus.endCorrelation();

      return {
        auditId: uuidv4(),
        scanType: ScanType.CONFIG_AUDIT,
        status: AuditStatus.COMPLETED,
        startTime,
        endTime,
        duration: endTime.getTime() - startTime.getTime(),
        findings: this.findings,
        summary: this.generateSummary(),
        metadata: {
          scanner: 'ClamAV',
          definitionsVersion: this.definitionsVersion
        },
        filesScanned,
        infectedFiles: this.findings.length,
        dataScanned,
        definitionsVersion: this.definitionsVersion
      };
    } catch (error) {
      this.logger.error('scan', 'failed', 'Scan failed', {}, error instanceof Error ? error : undefined);
      this.bus.endCorrelation();
      return this.createResult(startTime, AuditStatus.FAILED, {
        error: String(error)
      });
    }
  }

  /**
   * Scan a single target
   */
  private async scanTarget(target: string): Promise<{ filesScanned: number; dataScanned: string }> {
    const excludeArgs = this.config.excludePatterns
      ?.map(p => `--exclude-dir="${p}"`)
      .join(' ') || '';

    const archiveArg = this.config.scanArchives ? '' : '--no-archive';
    const maxSizeArg = `--max-filesize=${this.config.maxFileSize}M`;
    const maxTimeArg = `--max-scantime=${this.config.maxScanTime}000`;

    let command: string;
    if (this.config.useDaemon) {
      command = `clamdscan --fdpass --no-summary ${excludeArgs} "${target}" 2>&1 || true`;
    } else {
      command = `clamscan -r ${archiveArg} ${maxSizeArg} ${maxTimeArg} ${excludeArgs} "${target}" 2>&1 || true`;
    }

    try {
      const { stdout } = await execAsync(command, {
        maxBuffer: 50 * 1024 * 1024,
        timeout: this.config.maxScanTime ? this.config.maxScanTime * 1000 : 300000
      });

      return this.parseOutput(stdout, target);
    } catch (error) {
      if (error && typeof error === 'object' && 'stdout' in error) {
        return this.parseOutput((error as { stdout: string }).stdout, target);
      }
      throw error;
    }
  }

  /**
   * Parse ClamAV output
   */
  private parseOutput(output: string, target: string): { filesScanned: number; dataScanned: string } {
    const lines = output.split('\n');
    let filesScanned = 0;
    let dataScanned = '0 MB';

    for (const line of lines) {
      // Check for infection
      const infectionMatch = line.match(/^(.+): (.+) FOUND$/);
      if (infectionMatch) {
        const [, filePath, malwareName] = infectionMatch;
        this.addMalwareFinding(filePath, malwareName);
        continue;
      }

      // Parse summary stats
      const scannedMatch = line.match(/Scanned files: (\d+)/);
      if (scannedMatch) {
        filesScanned = parseInt(scannedMatch[1], 10);
      }

      const dataMatch = line.match(/Data scanned: (.+)/);
      if (dataMatch) {
        dataScanned = dataMatch[1];
      }
    }

    return { filesScanned, dataScanned };
  }

  /**
   * Add a malware finding
   */
  private async addMalwareFinding(filePath: string, malwareName: string): Promise<void> {
    const malwareType = this.classifyMalware(malwareName);

    this.logger.critical('security', 'malware_detected', `MALWARE DETECTED: ${malwareName}`, {
      filePath,
      malwareName,
      malwareType
    });

    // Get file hash
    let fileHash: string | undefined;
    try {
      const { stdout } = await execAsync(`sha256sum "${filePath}" 2>/dev/null | cut -d' ' -f1`);
      fileHash = stdout.trim();
    } catch {
      // File might be inaccessible
    }

    // Quarantine if enabled
    let quarantined = false;
    if (this.config.quarantine && this.config.quarantinePath) {
      quarantined = await this.quarantineFile(filePath);
    }

    const finding: MalwareFinding = {
      id: uuidv4(),
      type: 'malware_detected',
      severity: SeverityLevel.CRITICAL,
      title: `Malware detected: ${malwareName}`,
      description: `ClamAV detected ${malwareType} malware "${malwareName}" in file`,
      location: filePath,
      evidence: [
        `Malware: ${malwareName}`,
        `File: ${filePath}`,
        fileHash ? `SHA256: ${fileHash}` : ''
      ].filter(Boolean),
      remediation: quarantined
        ? `File has been quarantined to ${this.config.quarantinePath}. Investigate the source and scan related systems.`
        : 'Quarantine or delete the infected file immediately. Investigate the source and scan related systems.',
      detectedAt: new Date(),
      status: 'open',
      malwareType,
      malwareName,
      filePath,
      fileHash,
      quarantined,
      signature: malwareName
    };

    this.findings.push(finding);
    this.emit('malware_detected', finding);
  }

  // ==========================================================================
  // Malware Research
  // ==========================================================================

  /**
   * Research malware using external sources
   */
  async researchMalware(hash: string, signatureName?: string): Promise<MalwareResearchResult> {
    this.logger.info('scan', 'researching', `Researching malware: ${hash.slice(0, 16)}...`);

    // Check cache first
    const cached = this.researchCache.get(hash);
    if (cached && cached.expiresAt > new Date()) {
      this.logger.debug('scan', 'research_cache_hit', 'Using cached research result');
      return cached.result;
    }

    const result: MalwareResearchResult = {
      researchedAt: new Date(),
      recommendations: []
    };

    // Query VirusTotal
    if (this.config.research?.virusTotalApiKey) {
      result.virusTotal = await this.queryVirusTotal(hash);
    }

    // Query MalwareBazaar
    if (this.config.research?.malwareBazaarApiKey) {
      result.malwareBazaar = await this.queryMalwareBazaar(hash);
    }

    // Check local database
    result.localDb = await this.queryLocalDb(hash, signatureName);

    // Generate summary and recommendations
    result.summary = this.generateResearchSummary(result, signatureName);
    result.recommendations = this.generateResearchRecommendations(result);

    // Extract related IOCs
    result.relatedIOCs = this.extractRelatedIOCs(result);

    // Cache the result
    if (this.config.research?.cacheResults) {
      const ttl = this.config.research.cacheTtlSeconds ?? 86400;
      this.researchCache.set(hash, {
        hash,
        result,
        cachedAt: new Date(),
        expiresAt: new Date(Date.now() + ttl * 1000)
      });
    }

    this.logger.info('scan', 'research_complete', 'Malware research complete', {
      hash: hash.slice(0, 16),
      virusTotalFound: result.virusTotal?.detected,
      malwareBazaarFound: result.malwareBazaar?.found,
      localDbFound: result.localDb?.found
    });

    return result;
  }

  /**
   * Query VirusTotal API
   */
  private async queryVirusTotal(hash: string): Promise<MalwareResearchResult['virusTotal']> {
    const apiKey = this.config.research?.virusTotalApiKey;
    if (!apiKey) return undefined;

    try {
      const response = await fetch(`https://www.virustotal.com/vtapi/v2/file/report?apikey=${apiKey}&resource=${hash}`);

      if (!response.ok) {
        this.logger.warning('scan', 'virustotal_error', `VirusTotal API error: ${response.status}`);
        return undefined;
      }

      const data = await response.json();

      if (data.response_code === 0) {
        return { detected: false, positives: 0, total: 0 };
      }

      return {
        detected: data.positives > 0,
        positives: data.positives,
        total: data.total,
        scanDate: data.scan_date,
        permalink: data.permalink,
        scans: data.scans
      };
    } catch (error) {
      this.logger.warning('scan', 'virustotal_error', 'Failed to query VirusTotal', {},
        error instanceof Error ? error : undefined);
      return undefined;
    }
  }

  /**
   * Query MalwareBazaar API
   */
  private async queryMalwareBazaar(hash: string): Promise<MalwareResearchResult['malwareBazaar']> {
    try {
      const response = await fetch('https://mb-api.abuse.ch/api/v1/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `query=get_info&hash=${hash}`
      });

      if (!response.ok) {
        return undefined;
      }

      const data = await response.json();

      if (data.query_status !== 'ok') {
        return { found: false };
      }

      const sample = data.data?.[0];
      if (!sample) {
        return { found: false };
      }

      return {
        found: true,
        firstSeen: sample.first_seen,
        lastSeen: sample.last_seen,
        tags: sample.tags,
        family: sample.signature,
        deliveryMethod: sample.delivery_method,
        intelligence: sample.intelligence?.mail_intelligence
      };
    } catch (error) {
      this.logger.warning('scan', 'malwarebazaar_error', 'Failed to query MalwareBazaar', {},
        error instanceof Error ? error : undefined);
      return undefined;
    }
  }

  /**
   * Query local malware database
   */
  private async queryLocalDb(hash: string, signatureName?: string): Promise<MalwareResearchResult['localDb']> {
    const dbPath = this.config.research?.localDbPath;
    if (!dbPath) {
      return { found: false };
    }

    try {
      const data = await fs.readFile(dbPath, 'utf-8');
      const db = JSON.parse(data) as Record<string, {
        knownAs: string[];
        firstSeen: string;
        occurrences: number;
        notes?: string;
      }>;

      const entry = db[hash];
      if (entry) {
        // Update occurrence count
        entry.occurrences++;
        await fs.writeFile(dbPath, JSON.stringify(db, null, 2));

        return {
          found: true,
          knownAs: entry.knownAs,
          firstSeenLocally: new Date(entry.firstSeen),
          previousOccurrences: entry.occurrences - 1,
          notes: entry.notes
        };
      }

      // Add new entry
      db[hash] = {
        knownAs: signatureName ? [signatureName] : [],
        firstSeen: new Date().toISOString(),
        occurrences: 1
      };
      await fs.writeFile(dbPath, JSON.stringify(db, null, 2));

      return {
        found: false,
        firstSeenLocally: new Date(),
        previousOccurrences: 0
      };
    } catch {
      // Database doesn't exist or is invalid
      return { found: false };
    }
  }

  /**
   * Generate research summary
   */
  private generateResearchSummary(result: MalwareResearchResult, signatureName?: string): string {
    const parts: string[] = [];

    if (signatureName) {
      parts.push(`Detected as: ${signatureName}`);
    }

    if (result.virusTotal?.detected) {
      parts.push(`VirusTotal: ${result.virusTotal.positives}/${result.virusTotal.total} engines detected this file`);
    }

    if (result.malwareBazaar?.found) {
      parts.push(`MalwareBazaar: Known malware family "${result.malwareBazaar.family || 'unknown'}"`);
      if (result.malwareBazaar.deliveryMethod) {
        parts.push(`Delivery method: ${result.malwareBazaar.deliveryMethod}`);
      }
    }

    if (result.localDb?.previousOccurrences && result.localDb.previousOccurrences > 0) {
      parts.push(`Previously seen ${result.localDb.previousOccurrences} time(s) in this environment`);
    }

    return parts.join('. ') || 'No additional research data available.';
  }

  /**
   * Generate research recommendations
   */
  private generateResearchRecommendations(result: MalwareResearchResult): string[] {
    const recommendations: string[] = [];

    recommendations.push('Immediately isolate the affected system from the network');
    recommendations.push('Preserve evidence for forensic analysis before cleanup');

    if (result.virusTotal?.positives && result.virusTotal.positives > 10) {
      recommendations.push('This is a well-known threat - check for updated removal tools');
    }

    if (result.malwareBazaar?.deliveryMethod === 'email_attachment') {
      recommendations.push('Review email logs for source and other recipients');
      recommendations.push('Block sender and similar attachments at email gateway');
    }

    if (result.localDb?.previousOccurrences && result.localDb.previousOccurrences > 0) {
      recommendations.push('RECURRING THREAT: Investigate why this keeps appearing');
      recommendations.push('Review and strengthen endpoint protection policies');
    }

    recommendations.push('Scan all connected systems and network shares');
    recommendations.push('Check for lateral movement and persistence mechanisms');
    recommendations.push('Review user credentials that may have been compromised');

    return recommendations;
  }

  /**
   * Extract related IOCs from research
   */
  private extractRelatedIOCs(result: MalwareResearchResult): MalwareResearchResult['relatedIOCs'] {
    // In a real implementation, this would extract IOCs from the research results
    // For now, we return a placeholder structure
    return {
      ips: [],
      domains: [],
      urls: [],
      fileHashes: []
    };
  }

  /**
   * Get detailed info about a previously detected malware
   */
  async getMalwareInfo(hashOrSignature: string): Promise<MalwareFinding | undefined> {
    // Check current findings
    const finding = this.findings.find(f =>
      f.fileHash === hashOrSignature ||
      f.malwareName === hashOrSignature ||
      f.signature === hashOrSignature
    );

    if (finding) {
      // Refresh research if needed
      if (finding.fileHash && !finding.research) {
        finding.research = await this.researchMalware(finding.fileHash, finding.malwareName);
      }
      return finding;
    }

    // Check cache
    const cached = this.researchCache.get(hashOrSignature);
    if (cached) {
      return {
        id: uuidv4(),
        type: 'malware_info',
        severity: SeverityLevel.INFO,
        title: `Cached malware info: ${hashOrSignature}`,
        description: cached.result.summary || 'Cached research result',
        location: 'cache',
        evidence: [],
        detectedAt: cached.cachedAt,
        status: 'closed',
        malwareType: 'unknown',
        malwareName: hashOrSignature,
        filePath: '',
        fileHash: hashOrSignature,
        quarantined: false,
        research: cached.result
      };
    }

    return undefined;
  }

  // ==========================================================================
  // Origin Tracking
  // ==========================================================================

  /**
   * Track the origin of a malware file
   */
  async trackOrigin(filePath: string): Promise<MalwareOrigin> {
    this.logger.info('scan', 'tracking_origin', `Tracking origin: ${filePath}`);

    const origin: MalwareOrigin = {
      notes: []
    };

    // Get file metadata
    try {
      const stats = await fs.stat(filePath);
      origin.createdAt = stats.birthtime;
      origin.modifiedAt = stats.mtime;
      origin.accessedAt = stats.atime;
      origin.permissions = (stats.mode & 0o777).toString(8);
    } catch {
      origin.notes?.push('Could not read file metadata');
    }

    // Get owner info
    try {
      const { stdout } = await execAsync(`ls -la "${filePath}" 2>/dev/null | awk '{print $3, $4}'`);
      const [owner, group] = stdout.trim().split(' ');
      origin.owner = owner;
      origin.group = group;
    } catch {
      // Owner info not available
    }

    // Check if in git repo
    origin.git = await this.getGitOrigin(filePath);

    // Check package manager origins
    origin.packageManager = await this.getPackageManagerOrigin(filePath);

    // Try to determine delivery method
    origin.deliveryMethod = this.inferDeliveryMethod(filePath, origin);

    // Store in origin database
    await this.storeOrigin(filePath, origin);

    this.logger.info('scan', 'origin_tracked', 'Origin tracking complete', {
      deliveryMethod: origin.deliveryMethod,
      hasGitInfo: origin.git?.inRepo,
      hasPackageInfo: !!origin.packageManager
    });

    return origin;
  }

  /**
   * Get git information for a file
   */
  private async getGitOrigin(filePath: string): Promise<MalwareOrigin['git']> {
    const dir = path.dirname(filePath);

    try {
      // Check if in a git repo
      await execAsync(`git -C "${dir}" rev-parse --git-dir 2>/dev/null`);

      // Get blame info
      const { stdout: blameOut } = await execAsync(
        `git -C "${dir}" log -1 --format="%H|%an|%aI|%s" -- "${filePath}" 2>/dev/null`
      );

      if (!blameOut.trim()) {
        return { inRepo: true };
      }

      const [hash, author, date, message] = blameOut.trim().split('|');

      // Get current branch
      const { stdout: branchOut } = await execAsync(`git -C "${dir}" branch --show-current 2>/dev/null`);

      return {
        inRepo: true,
        commitHash: hash,
        commitAuthor: author,
        commitDate: date,
        commitMessage: message,
        branch: branchOut.trim()
      };
    } catch {
      return { inRepo: false };
    }
  }

  /**
   * Get package manager information
   */
  private async getPackageManagerOrigin(filePath: string): Promise<MalwareOrigin['packageManager'] | undefined> {
    // Check for node_modules
    if (filePath.includes('node_modules')) {
      const match = filePath.match(/node_modules\/(@[^/]+\/[^/]+|[^/]+)/);
      if (match) {
        const packageName = match[1];
        try {
          const pkgJsonPath = path.join(filePath.split('node_modules')[0], 'node_modules', packageName, 'package.json');
          const pkgJson = JSON.parse(await fs.readFile(pkgJsonPath, 'utf-8'));
          return {
            manager: 'npm',
            package: packageName,
            version: pkgJson.version
          };
        } catch {
          return { manager: 'npm', package: packageName };
        }
      }
    }

    // Check for pip packages
    if (filePath.includes('site-packages')) {
      const match = filePath.match(/site-packages\/([^/]+)/);
      if (match) {
        return { manager: 'pip', package: match[1] };
      }
    }

    // Check for Ruby gems
    if (filePath.includes('/gems/')) {
      const match = filePath.match(/gems\/([^/]+)/);
      if (match) {
        return { manager: 'gem', package: match[1] };
      }
    }

    return undefined;
  }

  /**
   * Infer delivery method from path and metadata
   */
  private inferDeliveryMethod(filePath: string, origin: MalwareOrigin): MalwareOrigin['deliveryMethod'] {
    const lowerPath = filePath.toLowerCase();

    if (lowerPath.includes('/downloads/') || lowerPath.includes('/tmp/')) {
      return 'download';
    }

    if (origin.packageManager) {
      return 'package_manager';
    }

    if (origin.git?.inRepo) {
      return 'git';
    }

    if (lowerPath.includes('/mail/') || lowerPath.includes('/attachment')) {
      return 'email';
    }

    if (lowerPath.includes('/media/') || lowerPath.includes('/mnt/usb')) {
      return 'usb';
    }

    if (lowerPath.includes('/share/') || lowerPath.includes('/smb/') || lowerPath.includes('/nfs/')) {
      return 'network_share';
    }

    return 'unknown';
  }

  /**
   * Store origin information in database
   */
  private async storeOrigin(filePath: string, origin: MalwareOrigin): Promise<void> {
    try {
      const existing = this.originDb.get(filePath) || [];
      existing.push(origin);
      this.originDb.set(filePath, existing);
      await this.saveOriginDb();
    } catch {
      // Failed to store, not critical
    }
  }

  /**
   * Load origin database
   */
  private async loadOriginDb(): Promise<void> {
    try {
      const data = await fs.readFile(this.config.originDbPath!, 'utf-8');
      const parsed = JSON.parse(data);
      this.originDb = new Map(Object.entries(parsed));
    } catch {
      this.originDb = new Map();
    }
  }

  /**
   * Save origin database
   */
  private async saveOriginDb(): Promise<void> {
    try {
      const dir = path.dirname(this.config.originDbPath!);
      await fs.mkdir(dir, { recursive: true });
      const data = Object.fromEntries(this.originDb);
      await fs.writeFile(this.config.originDbPath!, JSON.stringify(data, null, 2));
    } catch {
      // Failed to save
    }
  }

  /**
   * Document malware origin manually
   */
  async documentOrigin(filePath: string, notes: string, additionalInfo?: Partial<MalwareOrigin>): Promise<void> {
    const existing = this.originDb.get(filePath) || [];
    const latest = existing[existing.length - 1] || {};

    const updated: MalwareOrigin = {
      ...latest,
      ...additionalInfo,
      notes: [...(latest.notes || []), notes]
    };

    existing.push(updated);
    this.originDb.set(filePath, existing);
    await this.saveOriginDb();

    this.logger.info('scan', 'origin_documented', `Origin documented for: ${filePath}`, { notes });
  }

  /**
   * Get origin history for a file
   */
  async getOriginHistory(filePath: string): Promise<MalwareOrigin[]> {
    return this.originDb.get(filePath) || [];
  }

  // ==========================================================================
  // Notifications
  // ==========================================================================

  /**
   * Send alerts for detected malware
   */
  private async sendAlerts(): Promise<void> {
    // Log critical events (these go to Matrix via the event bus)
    for (const finding of this.findings) {
      this.logger.critical('security', 'malware_alert',
        `🚨 MALWARE ALERT: ${finding.malwareName} in ${finding.filePath}`, {
          malwareName: finding.malwareName,
          malwareType: finding.malwareType,
          filePath: finding.filePath,
          fileHash: finding.fileHash,
          quarantined: finding.quarantined,
          research: finding.research?.summary,
          origin: finding.origin?.deliveryMethod
        });
    }

    // Send email if configured
    if (this.config.email?.enabled) {
      await this.sendEmail();
    }
  }

  /**
   * Send email alert
   */
  private async sendEmail(): Promise<void> {
    const email = this.config.email;
    if (!email) return;

    this.logger.info('scan', 'sending_email', `Sending email alert to ${email.to.join(', ')}`);

    const subject = `${email.subjectPrefix || '[SECURITY ALERT]'} Malware detected - ${this.findings.length} infection(s)`;

    const body = this.generateEmailBody();

    try {
      // Try using sendmail/mail command
      const mailCommand = `echo "${body.replace(/"/g, '\\"')}" | mail -s "${subject}" ${email.to.join(' ')}`;

      // Or if that doesn't work, try with msmtp or other MTA
      // This is a best-effort approach - if no MTA is configured, it will fail gracefully
      await execAsync(mailCommand, { timeout: 30000 });

      this.logger.info('scan', 'email_sent', 'Email alert sent successfully');
    } catch (error) {
      // Try alternative method with curl to an email API if configured
      this.logger.warning('scan', 'email_failed', 'Failed to send email via local MTA, trying alternatives');

      // Attempt SMTP directly if we have full config
      if (email.host && email.username && email.password) {
        await this.sendSmtpEmail(email, subject, body);
      } else {
        this.logger.error('scan', 'email_failed', 'Could not send email alert - no SMTP configured', {},
          error instanceof Error ? error : undefined);
      }
    }
  }

  /**
   * Send email via SMTP (using node's capabilities or curl)
   */
  private async sendSmtpEmail(email: EmailConfig, subject: string, body: string): Promise<void> {
    try {
      // Build the email in MIME format
      const boundary = `boundary-${Date.now()}`;
      const mimeBody = [
        `From: ${email.from}`,
        `To: ${email.to.join(', ')}`,
        email.cc ? `Cc: ${email.cc.join(', ')}` : '',
        `Subject: ${subject}`,
        'MIME-Version: 1.0',
        `Content-Type: multipart/alternative; boundary="${boundary}"`,
        '',
        `--${boundary}`,
        'Content-Type: text/plain; charset=UTF-8',
        '',
        body,
        '',
        `--${boundary}`,
        'Content-Type: text/html; charset=UTF-8',
        '',
        this.generateEmailHtml(),
        '',
        `--${boundary}--`
      ].filter(Boolean).join('\r\n');

      // Use curl to send via SMTP
      const smtpUrl = `smtp${email.secure ? 's' : ''}://${email.host}:${email.port}`;
      const curlCommand = `curl --url "${smtpUrl}" \
        --ssl-reqd \
        --mail-from "${email.from}" \
        ${email.to.map(t => `--mail-rcpt "${t}"`).join(' ')} \
        --user "${email.username}:${email.password}" \
        -T - <<< '${mimeBody.replace(/'/g, "'\\''")}'`;

      await execAsync(curlCommand, { timeout: 60000 });
      this.logger.info('scan', 'email_sent', 'Email sent via SMTP');
    } catch (error) {
      this.logger.error('scan', 'smtp_failed', 'SMTP email failed', {},
        error instanceof Error ? error : undefined);
    }
  }

  /**
   * Generate plain text email body
   */
  private generateEmailBody(): string {
    const lines: string[] = [
      '='.repeat(60),
      'SECURITY ALERT: MALWARE DETECTED',
      '='.repeat(60),
      '',
      `Detection Time: ${new Date().toISOString()}`,
      `Total Infections: ${this.findings.length}`,
      `Definitions Version: ${this.definitionsVersion || 'Unknown'}`,
      '',
      '-'.repeat(60),
      'FINDINGS:',
      '-'.repeat(60),
    ];

    for (const finding of this.findings) {
      lines.push('');
      lines.push(`[${finding.severity.toUpperCase()}] ${finding.malwareName}`);
      lines.push(`  Type: ${finding.malwareType}`);
      lines.push(`  File: ${finding.filePath}`);
      if (finding.fileHash) {
        lines.push(`  SHA256: ${finding.fileHash}`);
      }
      lines.push(`  Quarantined: ${finding.quarantined ? 'Yes' : 'No'}`);

      if (finding.research?.summary) {
        lines.push(`  Research: ${finding.research.summary}`);
      }

      if (finding.origin?.deliveryMethod) {
        lines.push(`  Origin: ${finding.origin.deliveryMethod}`);
        if (finding.origin.git?.commitAuthor) {
          lines.push(`  Git Author: ${finding.origin.git.commitAuthor}`);
        }
        if (finding.origin.packageManager?.package) {
          lines.push(`  Package: ${finding.origin.packageManager.package}`);
        }
      }
    }

    lines.push('');
    lines.push('-'.repeat(60));
    lines.push('RECOMMENDED ACTIONS:');
    lines.push('-'.repeat(60));
    lines.push('');
    lines.push('1. Isolate affected systems immediately');
    lines.push('2. Preserve evidence for forensic analysis');
    lines.push('3. Scan all connected systems');
    lines.push('4. Review access logs for compromise indicators');
    lines.push('5. Check for lateral movement');
    lines.push('');
    lines.push('='.repeat(60));

    return lines.join('\n');
  }

  /**
   * Generate HTML email body
   */
  private generateEmailHtml(): string {
    const findingsHtml = this.findings.map(f => `
      <tr style="background: #fff5f5; border-left: 4px solid #e53e3e;">
        <td style="padding: 12px;">
          <strong style="color: #e53e3e;">${f.malwareName}</strong><br>
          <small>Type: ${f.malwareType}</small>
        </td>
        <td style="padding: 12px; font-family: monospace; font-size: 12px;">
          ${f.filePath}
        </td>
        <td style="padding: 12px;">
          ${f.quarantined ? '✅ Quarantined' : '⚠️ Active'}
        </td>
        <td style="padding: 12px;">
          ${f.origin?.deliveryMethod || 'Unknown'}
        </td>
      </tr>
    `).join('');

    return `
<!DOCTYPE html>
<html>
<head>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
    .alert-header { background: #e53e3e; color: white; padding: 20px; text-align: center; }
    .content { padding: 20px; }
    table { width: 100%; border-collapse: collapse; margin: 20px 0; }
    th { background: #2d3748; color: white; padding: 12px; text-align: left; }
    td { border-bottom: 1px solid #e2e8f0; }
    .actions { background: #edf2f7; padding: 20px; border-radius: 8px; }
    .actions li { margin: 8px 0; }
  </style>
</head>
<body>
  <div class="alert-header">
    <h1>🚨 SECURITY ALERT: MALWARE DETECTED</h1>
    <p>${this.findings.length} infection(s) found</p>
  </div>

  <div class="content">
    <p><strong>Detection Time:</strong> ${new Date().toISOString()}</p>
    <p><strong>Definitions Version:</strong> ${this.definitionsVersion || 'Unknown'}</p>

    <h2>Findings</h2>
    <table>
      <tr>
        <th>Malware</th>
        <th>File Path</th>
        <th>Status</th>
        <th>Origin</th>
      </tr>
      ${findingsHtml}
    </table>

    <div class="actions">
      <h3>Recommended Actions</h3>
      <ol>
        <li><strong>Isolate</strong> affected systems immediately</li>
        <li><strong>Preserve</strong> evidence for forensic analysis</li>
        <li><strong>Scan</strong> all connected systems</li>
        <li><strong>Review</strong> access logs for compromise indicators</li>
        <li><strong>Check</strong> for lateral movement</li>
      </ol>
    </div>
  </div>
</body>
</html>`;
  }

  // ==========================================================================
  // Single File / Stream Scanning
  // ==========================================================================

  /**
   * Scan a single file
   */
  async scanFile(filePath: string): Promise<{ clean: boolean; malware?: string; finding?: MalwareFinding }> {
    const availability = await this.checkAvailability();
    if (!availability.available) {
      throw new Error('ClamAV not available');
    }

    this.logger.info('scan', 'scanning_file', `Scanning file: ${filePath}`);

    try {
      const command = this.config.useDaemon
        ? `clamdscan --fdpass --no-summary "${filePath}" 2>&1`
        : `clamscan "${filePath}" 2>&1`;

      const { stdout } = await execAsync(command);

      if (stdout.includes('FOUND')) {
        const match = stdout.match(/: (.+) FOUND/);
        const malwareName = match?.[1] || 'Unknown';

        // Create a finding with full research
        await this.addMalwareFinding(filePath, malwareName);
        const finding = this.findings[this.findings.length - 1];

        if (finding.fileHash) {
          finding.research = await this.researchMalware(finding.fileHash, malwareName);
        }
        if (this.config.trackOrigins) {
          finding.origin = await this.trackOrigin(filePath);
        }

        this.logger.critical('security', 'malware_found', `Malware found in file: ${malwareName}`, {
          filePath,
          malwareName
        });

        return { clean: false, malware: malwareName, finding };
      }

      this.logger.info('scan', 'file_clean', `File is clean: ${filePath}`);
      return { clean: true };
    } catch (error) {
      if (error && typeof error === 'object' && 'stdout' in error) {
        const stdout = (error as { stdout: string }).stdout;
        if (stdout.includes('FOUND')) {
          const match = stdout.match(/: (.+) FOUND/);
          return { clean: false, malware: match?.[1] };
        }
      }
      throw error;
    }
  }

  /**
   * Scan a data stream
   */
  async scanStream(data: Buffer): Promise<{ clean: boolean; malware?: string }> {
    const availability = await this.checkAvailability();
    if (!availability.available || !availability.daemon) {
      throw new Error('ClamAV daemon required for stream scanning');
    }

    const tempFile = `/tmp/clamscan_${Date.now()}_${Math.random().toString(36).slice(2)}`;

    try {
      await fs.writeFile(tempFile, data);
      const result = await this.scanFile(tempFile);
      return { clean: result.clean, malware: result.malware };
    } finally {
      try {
        await fs.unlink(tempFile);
      } catch {
        // Cleanup failed
      }
    }
  }

  // ==========================================================================
  // Utilities
  // ==========================================================================

  /**
   * Classify malware type from signature name
   */
  private classifyMalware(name: string): MalwareFinding['malwareType'] {
    const lowerName = name.toLowerCase();

    if (lowerName.includes('trojan') || lowerName.includes('troj')) return 'trojan';
    if (lowerName.includes('worm')) return 'worm';
    if (lowerName.includes('ransom') || lowerName.includes('crypt')) return 'ransomware';
    if (lowerName.includes('spy') || lowerName.includes('keylog')) return 'spyware';
    if (lowerName.includes('adware') || lowerName.includes('pup')) return 'adware';
    if (lowerName.includes('rootkit')) return 'rootkit';
    if (lowerName.includes('virus')) return 'virus';

    return 'unknown';
  }

  /**
   * Quarantine an infected file
   */
  private async quarantineFile(filePath: string): Promise<boolean> {
    try {
      const quarantinePath = this.config.quarantinePath!;
      await fs.mkdir(quarantinePath, { recursive: true });

      const timestamp = Date.now();
      const basename = path.basename(filePath);
      const quarantineFile = path.join(quarantinePath, `${timestamp}_${basename}.quarantine`);

      await fs.rename(filePath, quarantineFile);

      const metadata = {
        originalPath: filePath,
        quarantineTime: new Date().toISOString(),
        reason: 'Malware detected by ClamAV'
      };
      await fs.writeFile(`${quarantineFile}.meta`, JSON.stringify(metadata, null, 2));

      this.logger.info('scan', 'quarantined', `File quarantined: ${filePath} -> ${quarantineFile}`);
      return true;
    } catch (error) {
      this.logger.error('scan', 'quarantine_failed', `Failed to quarantine: ${filePath}`, {},
        error instanceof Error ? error : undefined);
      return false;
    }
  }

  /**
   * Get virus definitions version
   */
  private async getDefinitionsVersion(): Promise<void> {
    try {
      const { stdout } = await execAsync('sigtool --info /var/lib/clamav/daily.cvd 2>/dev/null || echo ""');
      const versionMatch = stdout.match(/Version: (\d+)/);
      if (versionMatch) {
        this.definitionsVersion = versionMatch[1];
      }
    } catch {
      // Definitions version not available
    }
  }

  private generateSummary() {
    return {
      totalFindings: this.findings.length,
      criticalCount: this.findings.filter(f => f.severity === SeverityLevel.CRITICAL).length,
      highCount: this.findings.filter(f => f.severity === SeverityLevel.HIGH).length,
      mediumCount: 0,
      lowCount: 0,
      infoCount: 0,
      passedChecks: 0,
      failedChecks: this.findings.length,
      skippedChecks: 0,
      riskScore: this.findings.length > 0 ? 100 : 0,
      recommendations: this.findings.length > 0
        ? ['Investigate all detected malware immediately', 'Scan all connected systems', 'Review access logs for compromise indicators']
        : ['Continue regular malware scanning']
    };
  }

  private createResult(
    startTime: Date,
    status: AuditStatus,
    metadata: Record<string, unknown>
  ): ClamAVScanResult {
    return {
      auditId: uuidv4(),
      scanType: ScanType.CONFIG_AUDIT,
      status,
      startTime,
      endTime: new Date(),
      findings: this.findings,
      summary: this.generateSummary(),
      metadata,
      filesScanned: 0,
      infectedFiles: this.findings.length,
      dataScanned: '0 MB',
      definitionsVersion: this.definitionsVersion
    };
  }

  /**
   * Get all findings
   */
  getFindings(): MalwareFinding[] {
    return this.findings;
  }

  /**
   * Clear findings
   */
  clearFindings(): void {
    this.findings = [];
  }
}

export default ClamAVScanner;
