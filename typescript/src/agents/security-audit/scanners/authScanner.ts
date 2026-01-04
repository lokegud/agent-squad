/**
 * Authentication Security Scanner
 * Reviews shared credentials vs proper isolation, MFA, password policies
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as crypto from 'crypto';
import {
  AuthFinding,
  SeverityLevel,
  AuthReviewConfig,
  AuditResult,
  AuditStatus,
  ScanType
} from '../types';
import { v4 as uuidv4 } from 'uuid';

const execAsync = promisify(exec);

// Common weak passwords to check against
const WEAK_PASSWORDS = [
  'password', 'password123', '123456', '12345678', 'qwerty',
  'admin', 'administrator', 'root', 'letmein', 'welcome',
  'monkey', 'dragon', 'master', 'login', 'abc123',
  'passw0rd', 'Password1', 'iloveyou', 'trustno1', 'sunshine'
];

// Paths where credentials might be stored
const CREDENTIAL_PATHS = [
  '.env',
  '.env.local',
  '.env.production',
  '.env.development',
  'config/credentials.yml',
  'config/secrets.yml',
  'config/database.yml',
  '.aws/credentials',
  '.docker/config.json',
  '.kube/config',
  '.npmrc',
  '.pypirc',
  '.netrc',
  '.pgpass'
];

export class AuthScanner {
  private config: AuthReviewConfig;
  private findings: AuthFinding[] = [];
  private credentialHashes: Map<string, string[]> = new Map();

  constructor(config?: Partial<AuthReviewConfig>) {
    this.config = {
      scanType: ScanType.AUTH_REVIEW,
      targets: config?.targets ?? [process.cwd(), process.env.HOME || ''],
      checkSharedCredentials: config?.checkSharedCredentials ?? true,
      checkPasswordStrength: config?.checkPasswordStrength ?? true,
      checkMFA: config?.checkMFA ?? true,
      checkPermissions: config?.checkPermissions ?? true,
      checkCredentialAge: config?.checkCredentialAge ?? true,
      maxCredentialAgeDays: config?.maxCredentialAgeDays ?? 90,
      maxDepth: config?.maxDepth ?? 3,
      timeout: config?.timeout ?? 300000,
      parallelism: config?.parallelism ?? 4
    };
  }

  /**
   * Run a full authentication security scan
   */
  async scan(): Promise<AuditResult> {
    const startTime = new Date();
    this.findings = [];
    this.credentialHashes.clear();

    try {
      const scanPromises: Promise<void>[] = [];

      if (this.config.checkSharedCredentials) {
        scanPromises.push(this.checkSharedCredentials());
      }
      if (this.config.checkPasswordStrength) {
        scanPromises.push(this.checkPasswordStrength());
      }
      if (this.config.checkMFA) {
        scanPromises.push(this.checkMFAConfiguration());
      }
      if (this.config.checkPermissions) {
        scanPromises.push(this.checkPermissions());
      }
      if (this.config.checkCredentialAge) {
        scanPromises.push(this.checkCredentialAge());
      }

      // Additional checks
      scanPromises.push(this.checkServiceAccounts());
      scanPromises.push(this.checkSSHConfiguration());
      scanPromises.push(this.checkAPIKeyManagement());

      await Promise.all(scanPromises);

      const endTime = new Date();
      return this.generateReport(startTime, endTime);
    } catch (error) {
      return {
        auditId: uuidv4(),
        scanType: ScanType.AUTH_REVIEW,
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
   * Check for shared credentials across environments/services
   */
  private async checkSharedCredentials(): Promise<void> {
    const credentialsByHash: Map<string, Array<{ path: string; key: string }>> = new Map();

    for (const target of this.config.targets) {
      await this.scanForCredentials(target, credentialsByHash);
    }

    // Find credentials that appear in multiple places
    for (const [hash, locations] of credentialsByHash) {
      if (locations.length > 1) {
        const uniquePaths = [...new Set(locations.map(l => l.path))];
        const uniqueKeys = [...new Set(locations.map(l => l.key))];

        if (uniquePaths.length > 1 || uniqueKeys.length > 1) {
          this.addFinding({
            id: uuidv4(),
            type: 'shared_credentials',
            severity: SeverityLevel.HIGH,
            title: 'Shared credentials detected',
            description: `The same credential is used in multiple locations or for multiple purposes`,
            location: uniquePaths.join(', '),
            evidence: [
              `Found in ${uniquePaths.length} different files`,
              `Keys: ${uniqueKeys.join(', ')}`
            ],
            remediation: 'Use unique credentials for each service/environment. Implement a secrets manager for centralized credential management.',
            authType: 'shared_credentials',
            affectedServices: uniqueKeys,
            isolationLevel: 'none',
            detectedAt: new Date(),
            status: 'open'
          });
        }
      }
    }
  }

  private async scanForCredentials(
    dir: string,
    credentialsByHash: Map<string, Array<{ path: string; key: string }>>,
    depth = 0
  ): Promise<void> {
    if (depth > (this.config.maxDepth ?? 3)) return;

    try {
      const entries = await fs.readdir(dir, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);

        // Skip common non-relevant directories
        if (entry.isDirectory()) {
          const skipDirs = ['node_modules', '.git', 'vendor', '__pycache__', 'venv', '.venv'];
          if (!skipDirs.includes(entry.name)) {
            await this.scanForCredentials(fullPath, credentialsByHash, depth + 1);
          }
        } else if (this.isCredentialFile(entry.name)) {
          await this.extractCredentials(fullPath, credentialsByHash);
        }
      }
    } catch {
      // Permission denied or doesn't exist
    }
  }

  private isCredentialFile(filename: string): boolean {
    return CREDENTIAL_PATHS.some(p => filename === path.basename(p)) ||
           filename.endsWith('.env') ||
           filename === 'credentials' ||
           filename === 'secrets.yml' ||
           filename === 'secrets.yaml';
  }

  private async extractCredentials(
    filePath: string,
    credentialsByHash: Map<string, Array<{ path: string; key: string }>>
  ): Promise<void> {
    try {
      const content = await fs.readFile(filePath, 'utf-8');
      const lines = content.split('\n');

      for (const line of lines) {
        // Match key=value or key: value patterns
        const match = line.match(/^([A-Z_][A-Z0-9_]*)\s*[=:]\s*['"]?([^'"#\s]+)['"]?/i);
        if (match) {
          const [, key, value] = match;

          // Skip if it looks like a placeholder
          if (this.isPlaceholder(value)) continue;

          // Skip if key doesn't look like a credential
          const credentialKeys = ['password', 'secret', 'key', 'token', 'auth', 'credential', 'passwd'];
          if (!credentialKeys.some(k => key.toLowerCase().includes(k))) continue;

          const hash = this.hashCredential(value);
          const locations = credentialsByHash.get(hash) || [];
          locations.push({ path: filePath, key });
          credentialsByHash.set(hash, locations);
        }
      }
    } catch {
      // Can't read file
    }
  }

  private hashCredential(value: string): string {
    return crypto.createHash('sha256').update(value).digest('hex').substring(0, 16);
  }

  private isPlaceholder(value: string): boolean {
    const placeholders = ['changeme', 'your_', 'xxx', 'placeholder', '${', '{{', 'todo', 'fixme', 'example'];
    return placeholders.some(p => value.toLowerCase().includes(p)) || value.length < 4;
  }

  /**
   * Check password strength in configuration files
   */
  private async checkPasswordStrength(): Promise<void> {
    for (const target of this.config.targets) {
      await this.scanForWeakPasswords(target);
    }
  }

  private async scanForWeakPasswords(dir: string, depth = 0): Promise<void> {
    if (depth > (this.config.maxDepth ?? 3)) return;

    try {
      const entries = await fs.readdir(dir, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);

        if (entry.isDirectory()) {
          const skipDirs = ['node_modules', '.git', 'vendor', '__pycache__'];
          if (!skipDirs.includes(entry.name)) {
            await this.scanForWeakPasswords(fullPath, depth + 1);
          }
        } else if (this.isCredentialFile(entry.name)) {
          await this.checkFileForWeakPasswords(fullPath);
        }
      }
    } catch {
      // Skip inaccessible directories
    }
  }

  private async checkFileForWeakPasswords(filePath: string): Promise<void> {
    try {
      const content = await fs.readFile(filePath, 'utf-8');

      for (const weakPassword of WEAK_PASSWORDS) {
        const pattern = new RegExp(`password\\s*[=:]\\s*['"]?${weakPassword}['"]?`, 'gi');
        if (pattern.test(content)) {
          this.addFinding({
            id: uuidv4(),
            type: 'weak_password',
            severity: SeverityLevel.CRITICAL,
            title: 'Weak password detected',
            description: `A commonly known weak password was found in ${filePath}`,
            location: filePath,
            evidence: ['Password matches known weak password list'],
            remediation: 'Use strong, randomly generated passwords. Consider using a password manager or secrets manager.',
            authType: 'weak_password',
            isolationLevel: 'none',
            detectedAt: new Date(),
            status: 'open'
          });
          break; // One finding per file is enough
        }
      }

      // Check for short passwords
      const shortPasswordPattern = /password\s*[=:]\s*['"]?([^'"#\s]{1,7})['"]?/gi;
      const matches = content.match(shortPasswordPattern);
      if (matches) {
        this.addFinding({
          id: uuidv4(),
          type: 'short_password',
          severity: SeverityLevel.HIGH,
          title: 'Short password detected',
          description: `A password shorter than 8 characters was found in ${filePath}`,
          location: filePath,
          evidence: ['Password is less than 8 characters'],
          remediation: 'Use passwords of at least 12 characters with mixed case, numbers, and special characters.',
          authType: 'weak_password',
          isolationLevel: 'none',
          detectedAt: new Date(),
          status: 'open'
        });
      }
    } catch {
      // Can't read file
    }
  }

  /**
   * Check MFA configuration
   */
  private async checkMFAConfiguration(): Promise<void> {
    // Check AWS MFA configuration
    await this.checkAWSMFA();

    // Check SSH configuration for key-only auth
    await this.checkSSHMFA();
  }

  private async checkAWSMFA(): Promise<void> {
    try {
      // Check if AWS CLI is configured
      const { stdout } = await execAsync('aws sts get-caller-identity 2>/dev/null || echo "{}"');

      if (stdout.includes('UserId')) {
        // AWS is configured, check for MFA policy
        try {
          const { stdout: policyOutput } = await execAsync(
            'aws iam get-account-password-policy 2>/dev/null || echo "{}"'
          );

          const policy = JSON.parse(policyOutput);

          if (policy.PasswordPolicy && !policy.PasswordPolicy.RequireMFA) {
            this.addFinding({
              id: uuidv4(),
              type: 'missing_mfa',
              severity: SeverityLevel.HIGH,
              title: 'AWS account does not require MFA',
              description: 'The AWS account password policy does not require MFA for console access',
              location: 'AWS IAM',
              evidence: ['RequireMFA: false in password policy'],
              remediation: 'Enable MFA requirement in the AWS IAM password policy.',
              authType: 'missing_mfa',
              affectedServices: ['AWS IAM'],
              isolationLevel: 'partial',
              detectedAt: new Date(),
              status: 'open'
            });
          }
        } catch {
          // Can't check MFA policy
        }
      }
    } catch {
      // AWS CLI not available or not configured
    }
  }

  private async checkSSHMFA(): Promise<void> {
    try {
      const sshdConfig = await fs.readFile('/etc/ssh/sshd_config', 'utf-8');

      // Check if password authentication is enabled
      if (/^PasswordAuthentication\s+yes/im.test(sshdConfig)) {
        this.addFinding({
          id: uuidv4(),
          type: 'ssh_password_auth',
          severity: SeverityLevel.MEDIUM,
          title: 'SSH password authentication enabled',
          description: 'SSH allows password authentication which is less secure than key-based authentication',
          location: '/etc/ssh/sshd_config',
          evidence: ['PasswordAuthentication yes'],
          remediation: 'Disable password authentication and use SSH keys only. Consider adding TOTP-based MFA.',
          authType: 'missing_mfa',
          affectedServices: ['SSH'],
          isolationLevel: 'partial',
          detectedAt: new Date(),
          status: 'open'
        });
      }

      // Check if root login is enabled
      if (/^PermitRootLogin\s+yes/im.test(sshdConfig)) {
        this.addFinding({
          id: uuidv4(),
          type: 'ssh_root_login',
          severity: SeverityLevel.HIGH,
          title: 'SSH root login enabled',
          description: 'SSH allows direct root login which increases attack surface',
          location: '/etc/ssh/sshd_config',
          evidence: ['PermitRootLogin yes'],
          remediation: 'Disable root login and use sudo instead.',
          authType: 'excessive_permissions',
          affectedServices: ['SSH'],
          isolationLevel: 'none',
          detectedAt: new Date(),
          status: 'open'
        });
      }
    } catch {
      // Can't read SSH config
    }
  }

  /**
   * Check file and service permissions
   */
  private async checkPermissions(): Promise<void> {
    // Check credential file permissions
    for (const credPath of CREDENTIAL_PATHS) {
      for (const base of this.config.targets) {
        const fullPath = path.join(base, credPath);
        await this.checkFilePermissions(fullPath);
      }
    }

    // Check SSH key permissions
    const sshDir = path.join(process.env.HOME || '', '.ssh');
    try {
      const entries = await fs.readdir(sshDir);
      for (const entry of entries) {
        if (entry.includes('id_') && !entry.endsWith('.pub')) {
          await this.checkFilePermissions(path.join(sshDir, entry), 0o600);
        }
      }
    } catch {
      // SSH directory doesn't exist
    }
  }

  private async checkFilePermissions(filePath: string, expectedMode = 0o600): Promise<void> {
    try {
      const stats = await fs.stat(filePath);
      const mode = stats.mode & 0o777;

      // Check if file is readable by others
      if (mode & 0o044) {
        this.addFinding({
          id: uuidv4(),
          type: 'insecure_permissions',
          severity: SeverityLevel.HIGH,
          title: `Credential file has insecure permissions: ${filePath}`,
          description: `File ${filePath} is readable by other users (mode: ${mode.toString(8)})`,
          location: filePath,
          evidence: [`Current mode: ${mode.toString(8)}`, `Expected mode: ${expectedMode.toString(8)}`],
          remediation: `Change permissions with: chmod ${expectedMode.toString(8)} ${filePath}`,
          authType: 'excessive_permissions',
          isolationLevel: 'partial',
          detectedAt: new Date(),
          status: 'open'
        });
      }
    } catch {
      // File doesn't exist
    }
  }

  /**
   * Check credential age
   */
  private async checkCredentialAge(): Promise<void> {
    const maxAgeDays = this.config.maxCredentialAgeDays ?? 90;

    // Check AWS credential age
    await this.checkAWSCredentialAge(maxAgeDays);

    // Check local file ages
    for (const credPath of CREDENTIAL_PATHS) {
      for (const base of this.config.targets) {
        const fullPath = path.join(base, credPath);
        await this.checkFileAge(fullPath, maxAgeDays);
      }
    }
  }

  private async checkAWSCredentialAge(maxAgeDays: number): Promise<void> {
    try {
      const { stdout } = await execAsync(
        'aws iam list-access-keys --query "AccessKeyMetadata[*].[AccessKeyId,CreateDate]" --output json 2>/dev/null || echo "[]"'
      );

      const keys = JSON.parse(stdout);
      const now = new Date();

      for (const [keyId, createDate] of keys) {
        const created = new Date(createDate);
        const ageDays = Math.floor((now.getTime() - created.getTime()) / (1000 * 60 * 60 * 24));

        if (ageDays > maxAgeDays) {
          this.addFinding({
            id: uuidv4(),
            type: 'stale_credentials',
            severity: SeverityLevel.MEDIUM,
            title: `Stale AWS access key: ${keyId}`,
            description: `AWS access key is ${ageDays} days old (max recommended: ${maxAgeDays} days)`,
            location: 'AWS IAM',
            evidence: [`Key ID: ${keyId}`, `Age: ${ageDays} days`, `Created: ${createDate}`],
            remediation: 'Rotate the access key and update all systems using it.',
            authType: 'stale_credentials',
            affectedServices: ['AWS'],
            isolationLevel: 'partial',
            detectedAt: new Date(),
            status: 'open'
          });
        }
      }
    } catch {
      // AWS CLI not available
    }
  }

  private async checkFileAge(filePath: string, maxAgeDays: number): Promise<void> {
    try {
      const stats = await fs.stat(filePath);
      const now = new Date();
      const ageDays = Math.floor((now.getTime() - stats.mtime.getTime()) / (1000 * 60 * 60 * 24));

      if (ageDays > maxAgeDays) {
        this.addFinding({
          id: uuidv4(),
          type: 'stale_credentials',
          severity: SeverityLevel.LOW,
          title: `Credential file not rotated: ${filePath}`,
          description: `Credential file has not been updated in ${ageDays} days`,
          location: filePath,
          evidence: [`Last modified: ${stats.mtime.toISOString()}`, `Age: ${ageDays} days`],
          remediation: 'Rotate credentials regularly and update the credential file.',
          authType: 'stale_credentials',
          isolationLevel: 'partial',
          detectedAt: new Date(),
          status: 'open'
        });
      }
    } catch {
      // File doesn't exist
    }
  }

  /**
   * Check service accounts
   */
  private async checkServiceAccounts(): Promise<void> {
    try {
      // Check for Kubernetes service accounts
      const { stdout } = await execAsync(
        'kubectl get serviceaccounts -A -o json 2>/dev/null || echo "{}"'
      );

      const accounts = JSON.parse(stdout);

      if (accounts.items) {
        for (const account of accounts.items) {
          // Check if service account has cluster-admin
          if (account.metadata?.name === 'default') {
            this.addFinding({
              id: uuidv4(),
              type: 'default_service_account',
              severity: SeverityLevel.MEDIUM,
              title: `Default service account in use: ${account.metadata.namespace}`,
              description: 'Pods are using the default service account which may have excessive permissions',
              location: `Namespace: ${account.metadata.namespace}`,
              evidence: [`ServiceAccount: default`],
              remediation: 'Create dedicated service accounts with minimal required permissions.',
              authType: 'excessive_permissions',
              affectedServices: ['Kubernetes'],
              isolationLevel: 'partial',
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
   * Check SSH configuration
   */
  private async checkSSHConfiguration(): Promise<void> {
    const sshDir = path.join(process.env.HOME || '', '.ssh');

    try {
      // Check authorized_keys for wildcards or weak keys
      const authKeys = await fs.readFile(path.join(sshDir, 'authorized_keys'), 'utf-8');
      const lines = authKeys.split('\n').filter(Boolean);

      for (const line of lines) {
        // Check for DSA keys (deprecated)
        if (line.includes('ssh-dss')) {
          this.addFinding({
            id: uuidv4(),
            type: 'weak_ssh_key',
            severity: SeverityLevel.HIGH,
            title: 'Deprecated DSA SSH key in use',
            description: 'An SSH DSA key was found in authorized_keys. DSA is deprecated and considered weak.',
            location: path.join(sshDir, 'authorized_keys'),
            evidence: ['ssh-dss key found'],
            remediation: 'Replace DSA keys with Ed25519 or RSA 4096-bit keys.',
            authType: 'weak_password',
            isolationLevel: 'partial',
            detectedAt: new Date(),
            status: 'open'
          });
        }

        // Check for RSA keys smaller than 2048 bits
        if (line.includes('ssh-rsa')) {
          const parts = line.split(' ');
          if (parts[1]) {
            const keyLength = Buffer.from(parts[1], 'base64').length * 8;
            if (keyLength < 2048) {
              this.addFinding({
                id: uuidv4(),
                type: 'weak_ssh_key',
                severity: SeverityLevel.MEDIUM,
                title: 'Weak RSA SSH key in use',
                description: `An RSA SSH key smaller than 2048 bits was found (${keyLength} bits)`,
                location: path.join(sshDir, 'authorized_keys'),
                evidence: [`RSA key size: ~${keyLength} bits`],
                remediation: 'Use RSA keys of at least 4096 bits or switch to Ed25519.',
                authType: 'weak_password',
                isolationLevel: 'partial',
                detectedAt: new Date(),
                status: 'open'
              });
            }
          }
        }
      }
    } catch {
      // No authorized_keys file
    }
  }

  /**
   * Check API key management
   */
  private async checkAPIKeyManagement(): Promise<void> {
    // Check for API keys in environment
    const apiKeyPatterns = ['API_KEY', 'APIKEY', 'API_SECRET', 'API_TOKEN'];

    for (const [key, value] of Object.entries(process.env)) {
      if (apiKeyPatterns.some(p => key.includes(p)) && value) {
        // Check if it looks like a real API key
        if (value.length > 10 && !this.isPlaceholder(value)) {
          this.addFinding({
            id: uuidv4(),
            type: 'api_key_in_env',
            severity: SeverityLevel.MEDIUM,
            title: `API key found in environment: ${key}`,
            description: 'An API key is stored in an environment variable. Consider using a secrets manager.',
            location: `ENV:${key}`,
            evidence: [`Environment variable: ${key}`],
            remediation: 'Use a secrets manager for API keys instead of environment variables.',
            authType: 'shared_credentials',
            affectedServices: [key],
            isolationLevel: 'partial',
            detectedAt: new Date(),
            status: 'open'
          });
        }
      }
    }
  }

  private addFinding(finding: AuthFinding): void {
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

    if (this.findings.some(f => f.authType === 'shared_credentials')) {
      recommendations.push('Implement unique credentials per service/environment');
    }
    if (this.findings.some(f => f.authType === 'weak_password')) {
      recommendations.push('Enforce strong password policies across all systems');
    }
    if (this.findings.some(f => f.authType === 'missing_mfa')) {
      recommendations.push('Enable MFA for all human user accounts');
    }
    if (this.findings.some(f => f.authType === 'stale_credentials')) {
      recommendations.push('Implement automated credential rotation');
    }

    return recommendations;
  }

  private generateReport(startTime: Date, endTime: Date): AuditResult {
    return {
      auditId: uuidv4(),
      scanType: ScanType.AUTH_REVIEW,
      status: AuditStatus.COMPLETED,
      startTime,
      endTime,
      duration: endTime.getTime() - startTime.getTime(),
      findings: this.findings,
      summary: this.generateSummary(),
      metadata: {
        targetsScanned: this.config.targets,
        checksPerformed: [
          'shared_credentials',
          'password_strength',
          'mfa_configuration',
          'file_permissions',
          'credential_age',
          'service_accounts',
          'ssh_configuration',
          'api_key_management'
        ]
      }
    };
  }
}

export default AuthScanner;
