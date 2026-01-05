/**
 * ClamAV Antivirus Scanner Integration
 * Integrates ClamAV for malware detection in security audits
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs/promises';
import * as path from 'path';
import {
  SecurityFinding,
  SeverityLevel,
  AuditResult,
  AuditStatus,
  ScanType
} from '../types';
import { v4 as uuidv4 } from 'uuid';

const execAsync = promisify(exec);

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
}

export interface MalwareFinding extends SecurityFinding {
  malwareType: 'virus' | 'trojan' | 'worm' | 'ransomware' | 'spyware' | 'adware' | 'rootkit' | 'unknown';
  malwareName: string;
  filePath: string;
  fileHash?: string;
  quarantined: boolean;
  signature?: string;
}

export interface ClamAVScanResult extends AuditResult {
  findings: MalwareFinding[];
  filesScanned: number;
  infectedFiles: number;
  dataScanned: string;
  definitionsVersion?: string;
}

export class ClamAVScanner {
  private config: ClamAVConfig;
  private findings: MalwareFinding[] = [];
  private clamavAvailable: boolean = false;
  private definitionsVersion?: string;

  constructor(config?: Partial<ClamAVConfig>) {
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
      updateDefinitions: config?.updateDefinitions ?? false
    };
  }

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
    } catch {
      this.clamavAvailable = false;
    }

    // Check clamd daemon
    if (this.config.useDaemon) {
      try {
        await execAsync('clamdscan --version 2>/dev/null');
        daemonAvailable = true;
      } catch {
        daemonAvailable = false;
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
    try {
      const { stdout, stderr } = await execAsync('sudo freshclam 2>&1 || freshclam 2>&1');
      const output = stdout + stderr;

      if (output.includes('Database updated') || output.includes('is up to date')) {
        return { success: true, message: 'Virus definitions updated successfully' };
      }

      return { success: true, message: output.trim() };
    } catch (error) {
      return {
        success: false,
        message: `Failed to update definitions: ${error instanceof Error ? error.message : String(error)}`
      };
    }
  }

  /**
   * Run a malware scan
   */
  async scan(): Promise<ClamAVScanResult> {
    const startTime = new Date();
    this.findings = [];

    // Check availability
    const availability = await this.checkAvailability();
    if (!availability.available) {
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
        const result = await this.scanTarget(target);
        filesScanned += result.filesScanned;
        dataScanned = result.dataScanned;
      }

      const endTime = new Date();

      return {
        auditId: uuidv4(),
        scanType: ScanType.CONFIG_AUDIT, // Using CONFIG_AUDIT as base type
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
        maxBuffer: 50 * 1024 * 1024, // 50MB buffer
        timeout: this.config.maxScanTime ? this.config.maxScanTime * 1000 : 300000
      });

      // Parse output
      return this.parseOutput(stdout, target);
    } catch (error) {
      // ClamAV returns non-zero exit code when infections found
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

    // Get file hash if possible
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
  }

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

      // Create quarantine directory
      await fs.mkdir(quarantinePath, { recursive: true });

      // Generate quarantine filename
      const timestamp = Date.now();
      const basename = path.basename(filePath);
      const quarantineFile = path.join(quarantinePath, `${timestamp}_${basename}.quarantine`);

      // Move file to quarantine
      await fs.rename(filePath, quarantineFile);

      // Create metadata file
      const metadata = {
        originalPath: filePath,
        quarantineTime: new Date().toISOString(),
        reason: 'Malware detected by ClamAV'
      };
      await fs.writeFile(`${quarantineFile}.meta`, JSON.stringify(metadata, null, 2));

      return true;
    } catch {
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
   * Scan a single file (useful for on-demand scanning)
   */
  async scanFile(filePath: string): Promise<{ clean: boolean; malware?: string }> {
    const availability = await this.checkAvailability();
    if (!availability.available) {
      throw new Error('ClamAV not available');
    }

    try {
      const command = this.config.useDaemon
        ? `clamdscan --fdpass --no-summary "${filePath}" 2>&1`
        : `clamscan "${filePath}" 2>&1`;

      const { stdout } = await execAsync(command);

      if (stdout.includes('FOUND')) {
        const match = stdout.match(/: (.+) FOUND/);
        return { clean: false, malware: match?.[1] };
      }

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
   * Scan data stream (useful for scanning uploads)
   */
  async scanStream(data: Buffer): Promise<{ clean: boolean; malware?: string }> {
    const availability = await this.checkAvailability();
    if (!availability.available || !availability.daemon) {
      throw new Error('ClamAV daemon required for stream scanning');
    }

    // Write to temp file and scan
    const tempFile = `/tmp/clamscan_${Date.now()}_${Math.random().toString(36).slice(2)}`;

    try {
      await fs.writeFile(tempFile, data);
      const result = await this.scanFile(tempFile);
      return result;
    } finally {
      try {
        await fs.unlink(tempFile);
      } catch {
        // Cleanup failed, not critical
      }
    }
  }
}

export default ClamAVScanner;
