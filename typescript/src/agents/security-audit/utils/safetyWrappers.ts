/**
 * Safety Wrappers
 * Prevents destructive commands, validates code with linting/LSP,
 * and provides MCP integration for memory and documentation
 *
 * All wrappers emit events through the central event bus for
 * logging, monitoring, and Matrix notifications.
 */

import { exec, spawn } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs/promises';
import * as path from 'path';
import { EventEmitter } from 'events';
import { AgentEventBus, eventBus, SourceLogger } from './eventBus';

const execAsync = promisify(exec);

// ============================================================================
// Command Safety Wrapper
// ============================================================================

export interface CommandSafetyConfig {
  /** Require verification for dangerous commands */
  requireVerification: boolean;
  /** Verification timeout (ms) */
  verificationTimeout: number;
  /** Commands requiring explicit verification (dangerous operations) */
  dangerousPatterns: RegExp[];
  /** Allowed command patterns (if set, only these are allowed) */
  allowedPatterns?: RegExp[];
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
  risk: 'safe' | 'dangerous';
  reasons: string[];
  requiresVerification: boolean;
  alternatives?: string[];
}

// All dangerous command patterns - these require verification before execution
const DANGEROUS_PATTERNS = [
  // File system destruction
  /\brm\s+(-rf?|--recursive|--force)\s+[\/~]/i,
  /\brm\s+-rf?\s+\*/i,
  /\brm\s+/i,
  /\brmdir\s+/i,
  /\bmkfs\b/i,
  /\bdd\s+.*of=/i,
  /\bshred\b/i,
  />\s*\/dev\/sd[a-z]/i,

  // System operations
  /:(){ :|:& };:/,  // Fork bomb
  /\bsystemctl\s+(stop|disable|mask|restart|reload)\s+/i,
  /\bkillall\b/i,
  /\bpkill\s+-9/i,
  /\bsudo\s+/i,

  // Permission/security changes
  /\bchmod\s+(-R\s+)?777/i,
  /\bchmod\s+(-R\s+)?666/i,
  /\bchmod\s+/i,
  /\bchown\s+/i,
  /\bpasswd\s+/i,
  /\busermod\s+/i,

  // Database operations
  /\bDROP\s+(DATABASE|TABLE|SCHEMA)/i,
  /\bTRUNCATE\s+TABLE/i,
  /\bDELETE\s+FROM/i,
  /\bUPDATE\s+.*SET/i,

  // Container operations
  /\bdocker\s+(rm|rmi|stop|system\s+prune)/i,
  /\bdocker\s+stop\s+\$\(docker\s+ps/i,
  /\bkubectl\s+delete/i,

  // Git operations
  /\bgit\s+push\s+.*--force/i,
  /\bgit\s+push/i,
  /\bgit\s+reset\s+--hard/i,
  /\bgit\s+reset/i,
  /\bgit\s+rebase/i,
  /\bgit\s+clean\s+-fd/i,

  // Network operations
  /\biptables\s+/i,
  /\bifconfig\s+\w+\s+down/i,

  // Encryption operations
  /\bopenssl\s+enc\s+.*-e/i,
  /\bgpg\s+.*--encrypt/i,

  // Package management
  /\bnpm\s+(publish|unpublish)/i,
  /\bpip\s+uninstall/i,
  /\bapt\s+(remove|purge)/i,
  /\byum\s+(remove|erase)/i,
];

export class CommandSafetyWrapper extends EventEmitter {
  private config: CommandSafetyConfig;
  private pendingVerifications: Map<string, {
    resolve: (approved: boolean) => void;
    timeout: NodeJS.Timeout;
  }> = new Map();
  private logger: SourceLogger;
  private bus: AgentEventBus;

  constructor(config?: Partial<CommandSafetyConfig>, bus?: AgentEventBus) {
    super();

    this.bus = bus || eventBus;
    this.logger = this.bus.createLogger('CommandSafetyWrapper');

    this.config = {
      requireVerification: config?.requireVerification ?? true,
      verificationTimeout: config?.verificationTimeout ?? 60000,
      dangerousPatterns: config?.dangerousPatterns ?? DANGEROUS_PATTERNS,
      allowedPatterns: config?.allowedPatterns,
      dryRun: config?.dryRun ?? false,
      auditLog: config?.auditLog ?? true,
      auditLogPath: config?.auditLogPath ?? '/var/log/security-audit/commands.log',
      verificationCallback: config?.verificationCallback
    };

    this.logger.info('command', 'initialized', 'Command safety wrapper initialized', {
      requireVerification: this.config.requireVerification,
      dryRun: this.config.dryRun,
      dangerousPatternCount: this.config.dangerousPatterns.length
    });
  }

  /**
   * Assess risk of a command
   */
  assessRisk(command: string): CommandRiskAssessment {
    const reasons: string[] = [];
    let risk: CommandRiskAssessment['risk'] = 'safe';
    let requiresVerification = false;
    const alternatives: string[] = [];

    // Check if only allowed patterns (whitelist mode)
    if (this.config.allowedPatterns) {
      const isAllowed = this.config.allowedPatterns.some(p => p.test(command));
      if (!isAllowed) {
        risk = 'dangerous';
        requiresVerification = true;
        reasons.push('Command not in allowed list');
      }
    }

    // Check dangerous patterns - all require verification
    for (const pattern of this.config.dangerousPatterns) {
      if (pattern.test(command)) {
        risk = 'dangerous';
        requiresVerification = true;
        reasons.push(`Dangerous operation: ${pattern.source}`);
        break;  // One match is enough
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
    if (command.includes('git push')) {
      alternatives.push('Consider using git push --dry-run first');
    }
    if (command.includes('DROP')) {
      alternatives.push('Create a backup before dropping');
    }
    if (command.includes('DELETE FROM') && !command.toLowerCase().includes('where')) {
      alternatives.push('Add a WHERE clause to limit deletion scope');
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
    const correlationId = this.bus.startCorrelation('command');
    const assessment = this.assessRisk(command);

    // Log the attempt
    this.logger.debug('command', 'assess', `Assessing command: ${command.slice(0, 50)}...`, {
      risk: assessment.risk,
      requiresVerification: assessment.requiresVerification
    });

    await this.logCommand(command, assessment);

    // Request verification for dangerous commands
    if (assessment.requiresVerification) {
      this.logger.notice('command', 'verification_required',
        `⚠️ Dangerous command requires verification: ${command.slice(0, 100)}`, {
          command: command.slice(0, 200),
          reasons: assessment.reasons,
          alternatives: assessment.alternatives
        });

      this.emit('verification_required', { command, assessment });

      const approved = await this.requestVerification(command, assessment);
      if (!approved) {
        this.logger.warning('command', 'verification_denied',
          `User denied command execution: ${command.slice(0, 100)}`, {
            command: command.slice(0, 200)
          });

        this.bus.endCorrelation();
        return {
          stdout: '',
          stderr: `Command requires verification: ${assessment.reasons.join(', ')}\nAlternatives: ${assessment.alternatives?.join(', ') || 'none'}`,
          blocked: true
        };
      }

      this.logger.info('command', 'verification_approved',
        `User approved dangerous command: ${command.slice(0, 100)}`, {
          command: command.slice(0, 200)
        });
    }

    // Dry run mode
    if (this.config.dryRun) {
      this.logger.info('command', 'dry_run', `Dry run: ${command.slice(0, 100)}`, {
        command: command.slice(0, 200)
      });

      this.bus.endCorrelation();
      return {
        stdout: `[DRY RUN] Would execute: ${command}`,
        stderr: '',
        blocked: false
      };
    }

    // Execute the command
    try {
      this.logger.debug('command', 'executing', `Executing: ${command.slice(0, 100)}`, {
        cwd: options?.cwd,
        timeout: options?.timeout
      });

      const { stdout, stderr } = await execAsync(command, {
        cwd: options?.cwd,
        timeout: options?.timeout ?? 60000,
        maxBuffer: 10 * 1024 * 1024
      });

      this.logger.info('command', 'executed', `Command completed: ${command.slice(0, 100)}`, {
        stdoutLength: stdout.length,
        stderrLength: stderr.length,
        hasStderr: stderr.length > 0
      });

      this.emit('executed', { command, stdout, stderr });
      this.bus.endCorrelation();
      return { stdout, stderr, blocked: false };
    } catch (error) {
      const execError = error as { stdout?: string; stderr?: string; message?: string };

      this.logger.error('command', 'execution_failed', `Command failed: ${command.slice(0, 100)}`, {
        command: command.slice(0, 200),
        stdout: execError.stdout?.slice(0, 500),
        stderr: execError.stderr?.slice(0, 500)
      }, error instanceof Error ? error : String(error));

      this.bus.endCorrelation();
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

export class CodeLinter extends EventEmitter {
  private config: LintConfig;
  private logger: SourceLogger;
  private bus: AgentEventBus;

  constructor(config?: Partial<LintConfig>, bus?: AgentEventBus) {
    super();

    this.bus = bus || eventBus;
    this.logger = this.bus.createLogger('CodeLinter');

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

    this.logger.info('lint', 'initialized', 'Code linter initialized', {
      typescript: this.config.typescript,
      eslint: this.config.eslint,
      python: this.config.python,
      shellcheck: this.config.shellcheck
    });
  }

  /**
   * Lint code based on detected language
   */
  async lint(code: string, language?: string): Promise<LintResult> {
    const detectedLanguage = language || this.detectLanguage(code);
    const correlationId = this.bus.startCorrelation('lint');

    this.logger.debug('lint', 'start', `Linting ${detectedLanguage} code (${code.length} chars)`, {
      language: detectedLanguage,
      codeLength: code.length
    });

    let result: LintResult;

    switch (detectedLanguage) {
      case 'typescript':
      case 'javascript':
        result = await this.lintJavaScript(code, detectedLanguage === 'typescript');
        break;

      case 'python':
        result = await this.lintPython(code);
        break;

      case 'shell':
      case 'bash':
        result = await this.lintShell(code);
        break;

      default:
        result = {
          valid: true,
          language: detectedLanguage,
          errors: [],
          warnings: []
        };
    }

    // Log result
    if (result.errors.length > 0) {
      this.logger.warning('lint', 'errors_found', `Found ${result.errors.length} errors in ${detectedLanguage} code`, {
        language: detectedLanguage,
        errorCount: result.errors.length,
        warningCount: result.warnings.length,
        errors: result.errors.slice(0, 5)  // First 5 errors
      });

      this.emit('errors', { result });
    } else if (result.warnings.length > 0) {
      this.logger.notice('lint', 'warnings_found', `Found ${result.warnings.length} warnings in ${detectedLanguage} code`, {
        language: detectedLanguage,
        warningCount: result.warnings.length,
        warnings: result.warnings.slice(0, 5)
      });

      this.emit('warnings', { result });
    } else {
      this.logger.info('lint', 'passed', `Code passed linting (${detectedLanguage})`, {
        language: detectedLanguage
      });

      this.emit('passed', { result });
    }

    this.bus.endCorrelation();
    return result;
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

export class MCPMemory extends EventEmitter {
  private config: MCPConfig;
  private localCache: Map<string, MemoryEntry> = new Map();
  private logger: SourceLogger;
  private bus: AgentEventBus;

  constructor(config: Partial<MCPConfig>, bus?: AgentEventBus) {
    super();

    this.bus = bus || eventBus;
    this.logger = this.bus.createLogger('MCPMemory');

    this.config = {
      endpoint: config.endpoint || 'http://localhost:3000/mcp',
      apiKey: config.apiKey,
      namespace: config.namespace || 'security-audit',
      autoSave: config.autoSave ?? true,
      maxEntries: config.maxEntries ?? 1000,
      ttlSeconds: config.ttlSeconds ?? 86400 // 24 hours
    };

    this.logger.info('memory', 'initialized', 'MCP memory initialized', {
      endpoint: this.config.endpoint,
      namespace: this.config.namespace,
      maxEntries: this.config.maxEntries,
      ttlSeconds: this.config.ttlSeconds
    });
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

    this.logger.debug('memory', 'stored', `Stored memory: ${key}`, {
      key,
      hasMetadata: !!metadata,
      cacheSize: this.localCache.size
    });

    this.emit('stored', { key, entry });

    // Prune if needed
    if (this.localCache.size > this.config.maxEntries) {
      this.logger.notice('memory', 'pruning', `Cache full, pruning oldest entries`, {
        currentSize: this.localCache.size,
        maxEntries: this.config.maxEntries
      });
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
        this.logger.debug('memory', 'recall_hit', `Memory cache hit: ${key}`, { key });
        this.emit('recall', { key, found: true, source: 'cache' });
        return local.value;
      }
      this.logger.debug('memory', 'recall_expired', `Memory expired: ${key}`, { key });
      this.localCache.delete(key);
    }

    // Try remote
    if (this.config.endpoint) {
      const value = await this.fetchFromServer(key);
      if (value !== undefined) {
        this.logger.debug('memory', 'recall_remote', `Memory fetched from server: ${key}`, { key });
        this.emit('recall', { key, found: true, source: 'remote' });
      } else {
        this.logger.debug('memory', 'recall_miss', `Memory not found: ${key}`, { key });
        this.emit('recall', { key, found: false });
      }
      return value;
    }

    this.emit('recall', { key, found: false });
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
        this.logger.warning('memory', 'sync_failed', `MCP sync failed for key: ${entry.key}`, {
          key: entry.key,
          status: response.status,
          statusText: response.statusText
        });
        this.emit('sync_failed', { key: entry.key, status: response.status });
      } else {
        this.logger.debug('memory', 'synced', `Synced to MCP server: ${entry.key}`, { key: entry.key });
        this.emit('synced', { key: entry.key });
      }
    } catch (error) {
      this.logger.warning('memory', 'sync_error', `MCP server unavailable for key: ${entry.key}`, {
        key: entry.key,
        endpoint: this.config.endpoint
      }, error instanceof Error ? error : String(error));
      this.emit('sync_error', { key: entry.key, error });
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
        this.logger.debug('memory', 'fetch_success', `Fetched from server: ${key}`, { key });
        return data.value;
      }

      this.logger.debug('memory', 'fetch_not_found', `Key not found on server: ${key}`, {
        key,
        status: response.status
      });
    } catch (error) {
      this.logger.warning('memory', 'fetch_error', `Failed to fetch from server: ${key}`, {
        key,
        endpoint: this.config.endpoint
      }, error instanceof Error ? error : String(error));
    }

    return undefined;
  }

  /**
   * Delete from MCP server
   */
  private async deleteFromServer(key: string): Promise<void> {
    try {
      const response = await fetch(
        `${this.config.endpoint}/memory/${this.config.namespace}/${encodeURIComponent(key)}`,
        {
          method: 'DELETE',
          headers: {
            ...(this.config.apiKey && { 'Authorization': `Bearer ${this.config.apiKey}` })
          }
        }
      );

      if (response.ok) {
        this.logger.debug('memory', 'delete_success', `Deleted from server: ${key}`, { key });
        this.emit('deleted', { key, source: 'remote' });
      } else {
        this.logger.warning('memory', 'delete_failed', `Failed to delete from server: ${key}`, {
          key,
          status: response.status
        });
      }
    } catch (error) {
      this.logger.warning('memory', 'delete_error', `Error deleting from server: ${key}`, {
        key
      }, error instanceof Error ? error : String(error));
    }
  }
}

// Export all wrappers
export default {
  CommandSafetyWrapper,
  CodeLinter,
  MCPMemory
};
