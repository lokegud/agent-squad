/**
 * Safety Wrappers
 * Prevents destructive commands, validates code with linting/LSP,
 * and provides MCP integration for memory and documentation
 */

import { exec, spawn } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs/promises';
import * as path from 'path';
import { EventEmitter } from 'events';

const execAsync = promisify(exec);

// ============================================================================
// Command Safety Wrapper
// ============================================================================

export interface CommandSafetyConfig {
  /** Require verification for destructive commands */
  requireVerification: boolean;
  /** Verification timeout (ms) */
  verificationTimeout: number;
  /** Blocked command patterns */
  blockedPatterns: RegExp[];
  /** Allowed command patterns (if set, only these are allowed) */
  allowedPatterns?: RegExp[];
  /** Commands requiring explicit verification */
  verifyPatterns: RegExp[];
  /** Dry run mode - don't execute, just validate */
  dryRun: boolean;
  /** Log all commands */
  auditLog: boolean;
  /** Audit log path */
  auditLogPath?: string;
  /** Verification callback */
  verificationCallback?: (command: string, risk: string) => Promise<boolean>;
}

export interface CommandRiskAssessment {
  command: string;
  risk: 'safe' | 'caution' | 'dangerous' | 'blocked';
  reasons: string[];
  requiresVerification: boolean;
  alternatives?: string[];
}

// Destructive command patterns
const DESTRUCTIVE_PATTERNS = [
  // File system destruction
  /\brm\s+(-rf?|--recursive|--force)\s+[\/~]/i,
  /\brm\s+-rf?\s+\*/i,
  /\brmdir\s+/i,
  /\bmkfs\b/i,
  /\bdd\s+.*of=/i,
  /\bshred\b/i,
  />\s*\/dev\/sd[a-z]/i,

  // System destruction
  /:(){ :|:& };:/,  // Fork bomb
  /\bsystemctl\s+(stop|disable|mask)\s+(network|ssh|docker)/i,
  /\bkillall\b/i,
  /\bpkill\s+-9/i,

  // Permission/security changes
  /\bchmod\s+(-R\s+)?777/i,
  /\bchmod\s+(-R\s+)?666/i,
  /\bchown\s+-R\s+.*\s+\//i,
  /\bpasswd\s+root/i,
  /\busermod\s+.*-aG\s+sudo/i,

  // Database destruction
  /\bDROP\s+(DATABASE|TABLE|SCHEMA)/i,
  /\bTRUNCATE\s+TABLE/i,
  /\bDELETE\s+FROM\s+\w+\s*;?\s*$/i,  // DELETE without WHERE

  // Container destruction
  /\bdocker\s+(rm|rmi|system\s+prune)\s+-f/i,
  /\bdocker\s+stop\s+\$\(docker\s+ps/i,
  /\bkubectl\s+delete\s+(namespace|ns)\s+/i,

  // Git destruction
  /\bgit\s+push\s+.*--force/i,
  /\bgit\s+reset\s+--hard/i,
  /\bgit\s+clean\s+-fd/i,

  // Network disruption
  /\biptables\s+-F/i,
  /\biptables\s+.*DROP/i,
  /\bifconfig\s+\w+\s+down/i,

  // Encryption/ransom risk
  /\bopenssl\s+enc\s+.*-e/i,
  /\bgpg\s+.*--encrypt/i,
];

// Commands requiring verification (but not blocked)
const VERIFY_PATTERNS = [
  /\brm\s+/i,
  /\bsudo\s+/i,
  /\bchmod\s+/i,
  /\bchown\s+/i,
  /\bsystemctl\s+(restart|reload)/i,
  /\bdocker\s+(stop|rm|rmi)/i,
  /\bkubectl\s+delete/i,
  /\bgit\s+(push|reset|rebase)/i,
  /\bDROP\s+/i,
  /\bDELETE\s+/i,
  /\bUPDATE\s+.*SET/i,
  /\bnpm\s+(publish|unpublish)/i,
  /\bpip\s+uninstall/i,
];

export class CommandSafetyWrapper extends EventEmitter {
  private config: CommandSafetyConfig;
  private pendingVerifications: Map<string, {
    resolve: (approved: boolean) => void;
    timeout: NodeJS.Timeout;
  }> = new Map();

  constructor(config?: Partial<CommandSafetyConfig>) {
    super();

    this.config = {
      requireVerification: config?.requireVerification ?? true,
      verificationTimeout: config?.verificationTimeout ?? 60000,
      blockedPatterns: config?.blockedPatterns ?? DESTRUCTIVE_PATTERNS,
      allowedPatterns: config?.allowedPatterns,
      verifyPatterns: config?.verifyPatterns ?? VERIFY_PATTERNS,
      dryRun: config?.dryRun ?? false,
      auditLog: config?.auditLog ?? true,
      auditLogPath: config?.auditLogPath ?? '/var/log/security-audit/commands.log',
      verificationCallback: config?.verificationCallback
    };
  }

  /**
   * Assess risk of a command
   */
  assessRisk(command: string): CommandRiskAssessment {
    const reasons: string[] = [];
    let risk: CommandRiskAssessment['risk'] = 'safe';
    let requiresVerification = false;
    const alternatives: string[] = [];

    // Check blocked patterns
    for (const pattern of this.config.blockedPatterns) {
      if (pattern.test(command)) {
        risk = 'blocked';
        reasons.push(`Matches blocked pattern: ${pattern.source}`);
      }
    }

    // Check if only allowed patterns
    if (this.config.allowedPatterns && risk !== 'blocked') {
      const isAllowed = this.config.allowedPatterns.some(p => p.test(command));
      if (!isAllowed) {
        risk = 'blocked';
        reasons.push('Command not in allowed list');
      }
    }

    // Check verification patterns
    if (risk !== 'blocked') {
      for (const pattern of this.config.verifyPatterns) {
        if (pattern.test(command)) {
          risk = risk === 'safe' ? 'caution' : risk;
          requiresVerification = true;
          reasons.push(`Requires verification: ${pattern.source}`);
        }
      }
    }

    // Suggest safer alternatives
    if (command.includes('rm -rf')) {
      alternatives.push('Use trash-cli or move to a backup location first');
    }
    if (command.includes('chmod 777')) {
      alternatives.push('Use more restrictive permissions like 755 or 644');
    }
    if (command.includes('--force')) {
      alternatives.push('Remove --force flag and review changes first');
    }

    return {
      command,
      risk,
      reasons,
      requiresVerification: this.config.requireVerification && requiresVerification,
      alternatives: alternatives.length > 0 ? alternatives : undefined
    };
  }

  /**
   * Execute a command safely
   */
  async execute(
    command: string,
    options?: { cwd?: string; timeout?: number }
  ): Promise<{ stdout: string; stderr: string; blocked: boolean }> {
    const assessment = this.assessRisk(command);

    // Log the attempt
    await this.logCommand(command, assessment);

    // Block dangerous commands
    if (assessment.risk === 'blocked') {
      this.emit('blocked', { command, assessment });
      return {
        stdout: '',
        stderr: `Command blocked: ${assessment.reasons.join(', ')}`,
        blocked: true
      };
    }

    // Request verification if needed
    if (assessment.requiresVerification) {
      const approved = await this.requestVerification(command, assessment);
      if (!approved) {
        return {
          stdout: '',
          stderr: 'Command not approved by user',
          blocked: true
        };
      }
    }

    // Dry run mode
    if (this.config.dryRun) {
      return {
        stdout: `[DRY RUN] Would execute: ${command}`,
        stderr: '',
        blocked: false
      };
    }

    // Execute the command
    try {
      const { stdout, stderr } = await execAsync(command, {
        cwd: options?.cwd,
        timeout: options?.timeout ?? 60000,
        maxBuffer: 10 * 1024 * 1024
      });

      this.emit('executed', { command, stdout, stderr });
      return { stdout, stderr, blocked: false };
    } catch (error) {
      const execError = error as { stdout?: string; stderr?: string; message?: string };
      return {
        stdout: execError.stdout || '',
        stderr: execError.stderr || execError.message || String(error),
        blocked: false
      };
    }
  }

  /**
   * Request verification from user
   */
  private async requestVerification(
    command: string,
    assessment: CommandRiskAssessment
  ): Promise<boolean> {
    // Use callback if provided
    if (this.config.verificationCallback) {
      return this.config.verificationCallback(command, assessment.reasons.join(', '));
    }

    // Emit verification request
    const verificationId = `${Date.now()}_${Math.random().toString(36).slice(2)}`;

    return new Promise((resolve) => {
      const timeout = setTimeout(() => {
        this.pendingVerifications.delete(verificationId);
        resolve(false);
      }, this.config.verificationTimeout);

      this.pendingVerifications.set(verificationId, { resolve, timeout });

      this.emit('verification_required', {
        id: verificationId,
        command,
        assessment
      });
    });
  }

  /**
   * Approve a pending verification
   */
  approveVerification(id: string, approved: boolean): void {
    const pending = this.pendingVerifications.get(id);
    if (pending) {
      clearTimeout(pending.timeout);
      pending.resolve(approved);
      this.pendingVerifications.delete(id);
    }
  }

  /**
   * Log command to audit log
   */
  private async logCommand(
    command: string,
    assessment: CommandRiskAssessment
  ): Promise<void> {
    if (!this.config.auditLog) return;

    const entry = {
      timestamp: new Date().toISOString(),
      command,
      risk: assessment.risk,
      reasons: assessment.reasons,
      requiresVerification: assessment.requiresVerification
    };

    try {
      if (this.config.auditLogPath) {
        const dir = path.dirname(this.config.auditLogPath);
        await fs.mkdir(dir, { recursive: true });
        await fs.appendFile(
          this.config.auditLogPath,
          JSON.stringify(entry) + '\n'
        );
      }
    } catch {
      // Log to console if file logging fails
      console.log('[AUDIT]', JSON.stringify(entry));
    }
  }
}

// ============================================================================
// Code Linting Wrapper
// ============================================================================

export interface LintConfig {
  /** Enable TypeScript checking */
  typescript: boolean;
  /** Enable ESLint */
  eslint: boolean;
  /** Enable Prettier formatting check */
  prettier: boolean;
  /** Enable Python linting (pylint/ruff) */
  python: boolean;
  /** Enable shell script checking (shellcheck) */
  shellcheck: boolean;
  /** Custom ESLint config path */
  eslintConfig?: string;
  /** Fail on warnings */
  failOnWarnings: boolean;
  /** Auto-fix issues */
  autoFix: boolean;
}

export interface LintResult {
  valid: boolean;
  language: string;
  errors: LintIssue[];
  warnings: LintIssue[];
  fixed?: string;
}

export interface LintIssue {
  line: number;
  column: number;
  severity: 'error' | 'warning';
  message: string;
  rule?: string;
  fix?: string;
}

export class CodeLinter {
  private config: LintConfig;

  constructor(config?: Partial<LintConfig>) {
    this.config = {
      typescript: config?.typescript ?? true,
      eslint: config?.eslint ?? true,
      prettier: config?.prettier ?? true,
      python: config?.python ?? true,
      shellcheck: config?.shellcheck ?? true,
      eslintConfig: config?.eslintConfig,
      failOnWarnings: config?.failOnWarnings ?? false,
      autoFix: config?.autoFix ?? false
    };
  }

  /**
   * Lint code based on detected language
   */
  async lint(code: string, language?: string): Promise<LintResult> {
    const detectedLanguage = language || this.detectLanguage(code);

    switch (detectedLanguage) {
      case 'typescript':
      case 'javascript':
        return this.lintJavaScript(code, detectedLanguage === 'typescript');

      case 'python':
        return this.lintPython(code);

      case 'shell':
      case 'bash':
        return this.lintShell(code);

      default:
        return {
          valid: true,
          language: detectedLanguage,
          errors: [],
          warnings: []
        };
    }
  }

  /**
   * Detect programming language from code
   */
  private detectLanguage(code: string): string {
    if (code.includes('import ') && (code.includes(': ') || code.includes('interface '))) {
      return 'typescript';
    }
    if (code.includes('const ') || code.includes('function ') || code.includes('=>')) {
      return 'javascript';
    }
    if (code.includes('def ') || code.includes('import ') && code.includes(':')) {
      return 'python';
    }
    if (code.startsWith('#!/bin/bash') || code.startsWith('#!/bin/sh') || code.includes('$((')) {
      return 'shell';
    }
    return 'unknown';
  }

  /**
   * Lint JavaScript/TypeScript code
   */
  private async lintJavaScript(code: string, isTypeScript: boolean): Promise<LintResult> {
    const errors: LintIssue[] = [];
    const warnings: LintIssue[] = [];

    // Write to temp file
    const ext = isTypeScript ? '.ts' : '.js';
    const tempFile = `/tmp/lint_${Date.now()}${ext}`;

    try {
      await fs.writeFile(tempFile, code);

      // Run ESLint
      if (this.config.eslint) {
        try {
          const eslintConfig = this.config.eslintConfig
            ? `--config ${this.config.eslintConfig}`
            : '';
          const fixArg = this.config.autoFix ? '--fix' : '';

          const { stdout } = await execAsync(
            `npx eslint ${eslintConfig} ${fixArg} --format json "${tempFile}" 2>/dev/null || true`
          );

          const results = JSON.parse(stdout || '[]');
          for (const result of results) {
            for (const message of result.messages || []) {
              const issue: LintIssue = {
                line: message.line,
                column: message.column,
                severity: message.severity === 2 ? 'error' : 'warning',
                message: message.message,
                rule: message.ruleId
              };

              if (issue.severity === 'error') {
                errors.push(issue);
              } else {
                warnings.push(issue);
              }
            }
          }
        } catch {
          // ESLint not available
        }
      }

      // Run TypeScript compiler check
      if (isTypeScript && this.config.typescript) {
        try {
          const { stderr } = await execAsync(
            `npx tsc --noEmit --skipLibCheck "${tempFile}" 2>&1 || true`
          );

          const lines = stderr.split('\n');
          for (const line of lines) {
            const match = line.match(/\((\d+),(\d+)\):\s+(error|warning)\s+TS\d+:\s+(.+)/);
            if (match) {
              const issue: LintIssue = {
                line: parseInt(match[1], 10),
                column: parseInt(match[2], 10),
                severity: match[3] as 'error' | 'warning',
                message: match[4]
              };

              if (issue.severity === 'error') {
                errors.push(issue);
              } else {
                warnings.push(issue);
              }
            }
          }
        } catch {
          // TypeScript not available
        }
      }

      // Read fixed code if auto-fix enabled
      let fixed: string | undefined;
      if (this.config.autoFix) {
        fixed = await fs.readFile(tempFile, 'utf-8');
      }

      const valid = errors.length === 0 &&
        (!this.config.failOnWarnings || warnings.length === 0);

      return {
        valid,
        language: isTypeScript ? 'typescript' : 'javascript',
        errors,
        warnings,
        fixed
      };
    } finally {
      try {
        await fs.unlink(tempFile);
      } catch {
        // Cleanup failed
      }
    }
  }

  /**
   * Lint Python code
   */
  private async lintPython(code: string): Promise<LintResult> {
    const errors: LintIssue[] = [];
    const warnings: LintIssue[] = [];
    const tempFile = `/tmp/lint_${Date.now()}.py`;

    try {
      await fs.writeFile(tempFile, code);

      // Try ruff first (faster), then pylint
      try {
        const { stdout } = await execAsync(
          `ruff check --output-format json "${tempFile}" 2>/dev/null || true`
        );

        const results = JSON.parse(stdout || '[]');
        for (const result of results) {
          const issue: LintIssue = {
            line: result.location?.row || 1,
            column: result.location?.column || 1,
            severity: result.code?.startsWith('E') ? 'error' : 'warning',
            message: result.message,
            rule: result.code
          };

          if (issue.severity === 'error') {
            errors.push(issue);
          } else {
            warnings.push(issue);
          }
        }
      } catch {
        // Try pylint
        try {
          const { stdout } = await execAsync(
            `pylint --output-format=json "${tempFile}" 2>/dev/null || true`
          );

          const results = JSON.parse(stdout || '[]');
          for (const result of results) {
            const issue: LintIssue = {
              line: result.line,
              column: result.column,
              severity: result.type === 'error' ? 'error' : 'warning',
              message: result.message,
              rule: result.symbol
            };

            if (issue.severity === 'error') {
              errors.push(issue);
            } else {
              warnings.push(issue);
            }
          }
        } catch {
          // No Python linter available
        }
      }

      const valid = errors.length === 0 &&
        (!this.config.failOnWarnings || warnings.length === 0);

      return { valid, language: 'python', errors, warnings };
    } finally {
      try {
        await fs.unlink(tempFile);
      } catch {
        // Cleanup failed
      }
    }
  }

  /**
   * Lint shell scripts
   */
  private async lintShell(code: string): Promise<LintResult> {
    if (!this.config.shellcheck) {
      return { valid: true, language: 'shell', errors: [], warnings: [] };
    }

    const errors: LintIssue[] = [];
    const warnings: LintIssue[] = [];
    const tempFile = `/tmp/lint_${Date.now()}.sh`;

    try {
      await fs.writeFile(tempFile, code);

      const { stdout } = await execAsync(
        `shellcheck --format=json "${tempFile}" 2>/dev/null || true`
      );

      const results = JSON.parse(stdout || '[]');
      for (const result of results) {
        const issue: LintIssue = {
          line: result.line,
          column: result.column,
          severity: result.level === 'error' ? 'error' : 'warning',
          message: result.message,
          rule: `SC${result.code}`,
          fix: result.fix?.replacements?.[0]?.replacement
        };

        if (issue.severity === 'error') {
          errors.push(issue);
        } else {
          warnings.push(issue);
        }
      }

      const valid = errors.length === 0 &&
        (!this.config.failOnWarnings || warnings.length === 0);

      return { valid, language: 'shell', errors, warnings };
    } catch {
      return { valid: true, language: 'shell', errors: [], warnings: [] };
    } finally {
      try {
        await fs.unlink(tempFile);
      } catch {
        // Cleanup failed
      }
    }
  }
}

// ============================================================================
// MCP Memory Integration
// ============================================================================

export interface MCPConfig {
  /** MCP server endpoint */
  endpoint: string;
  /** API key */
  apiKey?: string;
  /** Memory namespace */
  namespace: string;
  /** Enable automatic context saving */
  autoSave: boolean;
  /** Max memory entries */
  maxEntries: number;
  /** Memory TTL (seconds) */
  ttlSeconds: number;
}

export interface MemoryEntry {
  id: string;
  key: string;
  value: unknown;
  metadata: Record<string, unknown>;
  createdAt: Date;
  updatedAt: Date;
  expiresAt?: Date;
}

export class MCPMemory {
  private config: MCPConfig;
  private localCache: Map<string, MemoryEntry> = new Map();

  constructor(config: Partial<MCPConfig>) {
    this.config = {
      endpoint: config.endpoint || 'http://localhost:3000/mcp',
      apiKey: config.apiKey,
      namespace: config.namespace || 'security-audit',
      autoSave: config.autoSave ?? true,
      maxEntries: config.maxEntries ?? 1000,
      ttlSeconds: config.ttlSeconds ?? 86400 // 24 hours
    };
  }

  /**
   * Store a memory entry
   */
  async remember(
    key: string,
    value: unknown,
    metadata?: Record<string, unknown>
  ): Promise<MemoryEntry> {
    const entry: MemoryEntry = {
      id: `${this.config.namespace}:${key}`,
      key,
      value,
      metadata: metadata || {},
      createdAt: new Date(),
      updatedAt: new Date(),
      expiresAt: new Date(Date.now() + this.config.ttlSeconds * 1000)
    };

    // Store locally
    this.localCache.set(key, entry);

    // Prune if needed
    if (this.localCache.size > this.config.maxEntries) {
      this.pruneOldest();
    }

    // Store remotely if endpoint configured
    if (this.config.endpoint && this.config.autoSave) {
      await this.syncToServer(entry);
    }

    return entry;
  }

  /**
   * Recall a memory entry
   */
  async recall(key: string): Promise<unknown | undefined> {
    // Check local cache first
    const local = this.localCache.get(key);
    if (local) {
      if (!local.expiresAt || local.expiresAt > new Date()) {
        return local.value;
      }
      this.localCache.delete(key);
    }

    // Try remote
    if (this.config.endpoint) {
      return this.fetchFromServer(key);
    }

    return undefined;
  }

  /**
   * Search memories
   */
  async search(query: string, limit = 10): Promise<MemoryEntry[]> {
    const results: MemoryEntry[] = [];
    const queryLower = query.toLowerCase();

    // Search local cache
    for (const entry of this.localCache.values()) {
      if (entry.expiresAt && entry.expiresAt <= new Date()) continue;

      const valueStr = JSON.stringify(entry.value).toLowerCase();
      const keyStr = entry.key.toLowerCase();

      if (keyStr.includes(queryLower) || valueStr.includes(queryLower)) {
        results.push(entry);
        if (results.length >= limit) break;
      }
    }

    return results;
  }

  /**
   * Forget a memory entry
   */
  async forget(key: string): Promise<void> {
    this.localCache.delete(key);

    if (this.config.endpoint) {
      await this.deleteFromServer(key);
    }
  }

  /**
   * Store conversation context
   */
  async storeContext(
    sessionId: string,
    context: {
      lastAction: string;
      findings: unknown[];
      recommendations: string[];
    }
  ): Promise<void> {
    await this.remember(`context:${sessionId}`, context, {
      type: 'context',
      sessionId
    });
  }

  /**
   * Retrieve conversation context
   */
  async getContext(sessionId: string): Promise<unknown | undefined> {
    return this.recall(`context:${sessionId}`);
  }

  /**
   * Store documentation reference
   */
  async storeDocs(
    topic: string,
    content: string,
    source?: string
  ): Promise<void> {
    await this.remember(`docs:${topic}`, { content, source }, {
      type: 'documentation',
      topic
    });
  }

  /**
   * Retrieve documentation
   */
  async getDocs(topic: string): Promise<string | undefined> {
    const entry = await this.recall(`docs:${topic}`);
    if (entry && typeof entry === 'object' && 'content' in entry) {
      return (entry as { content: string }).content;
    }
    return undefined;
  }

  /**
   * Get all memories
   */
  getAll(): MemoryEntry[] {
    const now = new Date();
    return Array.from(this.localCache.values()).filter(
      entry => !entry.expiresAt || entry.expiresAt > now
    );
  }

  /**
   * Clear all memories
   */
  clear(): void {
    this.localCache.clear();
  }

  /**
   * Prune oldest entries
   */
  private pruneOldest(): void {
    const entries = Array.from(this.localCache.entries())
      .sort((a, b) => a[1].updatedAt.getTime() - b[1].updatedAt.getTime());

    const toRemove = entries.slice(0, Math.floor(this.config.maxEntries * 0.1));
    for (const [key] of toRemove) {
      this.localCache.delete(key);
    }
  }

  /**
   * Sync to MCP server
   */
  private async syncToServer(entry: MemoryEntry): Promise<void> {
    try {
      const response = await fetch(`${this.config.endpoint}/memory`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(this.config.apiKey && { 'Authorization': `Bearer ${this.config.apiKey}` })
        },
        body: JSON.stringify({
          namespace: this.config.namespace,
          key: entry.key,
          value: entry.value,
          metadata: entry.metadata,
          ttl: this.config.ttlSeconds
        })
      });

      if (!response.ok) {
        console.warn('MCP sync failed:', response.status);
      }
    } catch {
      // Server not available, use local only
    }
  }

  /**
   * Fetch from MCP server
   */
  private async fetchFromServer(key: string): Promise<unknown | undefined> {
    try {
      const response = await fetch(
        `${this.config.endpoint}/memory/${this.config.namespace}/${encodeURIComponent(key)}`,
        {
          headers: {
            ...(this.config.apiKey && { 'Authorization': `Bearer ${this.config.apiKey}` })
          }
        }
      );

      if (response.ok) {
        const data = await response.json();
        return data.value;
      }
    } catch {
      // Server not available
    }

    return undefined;
  }

  /**
   * Delete from MCP server
   */
  private async deleteFromServer(key: string): Promise<void> {
    try {
      await fetch(
        `${this.config.endpoint}/memory/${this.config.namespace}/${encodeURIComponent(key)}`,
        {
          method: 'DELETE',
          headers: {
            ...(this.config.apiKey && { 'Authorization': `Bearer ${this.config.apiKey}` })
          }
        }
      );
    } catch {
      // Server not available
    }
  }
}

// Export all wrappers
export default {
  CommandSafetyWrapper,
  CodeLinter,
  MCPMemory
};
