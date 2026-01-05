/**
 * Configuration Loader
 *
 * Loads agent configuration from YAML, JSON, or environment variables.
 * Supports:
 * - File-based config (config.yaml, config.json)
 * - Environment variable overrides
 * - Schema validation
 * - Default values
 * - Config inheritance/merging
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import * as yaml from 'js-yaml';
import { SecurityAuditAgentConfig, ScanConfig, ScanType } from '../types';

// ============================================================================
// Types
// ============================================================================

export interface ConfigLoaderOptions {
  /** Path to config file */
  configPath?: string;
  /** Search paths for config file */
  searchPaths?: string[];
  /** Environment variable prefix (default: SECURITY_AUDIT) */
  envPrefix?: string;
  /** Whether to validate config against schema */
  validate?: boolean;
  /** Whether to allow environment overrides */
  allowEnvOverrides?: boolean;
}

export interface LoadedConfig {
  config: SecurityAuditAgentConfig;
  source: 'file' | 'env' | 'default';
  filePath?: string;
  warnings: string[];
}

export interface ConfigSchema {
  [key: string]: {
    type: 'string' | 'number' | 'boolean' | 'array' | 'object';
    required?: boolean;
    default?: unknown;
    env?: string;
    validate?: (value: unknown) => boolean;
    description?: string;
  };
}

// ============================================================================
// Default Configuration
// ============================================================================

const DEFAULT_CONFIG: SecurityAuditAgentConfig = {
  name: 'SecurityAuditAgent',
  description: 'AI-powered security audit agent',
  modelConfig: {
    modelId: 'anthropic.claude-3-sonnet-20240229-v1:0',
    temperature: 0,
    maxTokens: 4096,
    streaming: true
  },
  localModelConfig: {
    enabled: true,
    modelPath: '',
    modelType: 'ollama',
    endpoint: 'http://localhost:11434',
    capabilities: ['scan', 'classify']
  },
  vertexConfig: {
    enabled: false,
    projectId: '',
    location: 'us-central1',
    modelId: 'gemini-1.5-pro',
    useForPatternAnalysis: true,
    useForAnomalyDetection: true
  },
  scanConfigs: [],
  monitoringConfig: {
    enabled: true,
    intervalSeconds: 60,
    alertThresholds: [
      { metric: 'critical_findings', operator: 'gt', value: 0, severity: 'critical' },
      { metric: 'high_findings', operator: 'gt', value: 5, severity: 'high' }
    ],
    notificationChannels: []
  },
  sanitizationConfig: {
    enabled: true,
    patterns: [
      { pattern: '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b', replacement: '[EMAIL]', type: 'email' },
      { pattern: '\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b', replacement: '[IP]', type: 'ip' },
      { pattern: '(?:password|passwd|pwd|secret|token|api_key|apikey)\\s*[=:]\\s*[\'"]?[^\\s\'"]+', replacement: '[REDACTED]', type: 'credential' }
    ],
    preserveFormat: true,
    hashSensitiveValues: false
  },
  storageConfig: {
    type: 'sqlite',
    connectionString: './security-audit.db',
    retentionDays: 90,
    encryptAtRest: false
  }
};

// ============================================================================
// Config Schema for Validation
// ============================================================================

const CONFIG_SCHEMA: ConfigSchema = {
  'name': { type: 'string', required: true, env: 'NAME' },
  'description': { type: 'string', required: false },
  'modelConfig.modelId': { type: 'string', env: 'MODEL_ID' },
  'modelConfig.temperature': { type: 'number', env: 'MODEL_TEMPERATURE' },
  'modelConfig.maxTokens': { type: 'number', env: 'MODEL_MAX_TOKENS' },
  'localModelConfig.enabled': { type: 'boolean', env: 'LOCAL_MODEL_ENABLED' },
  'localModelConfig.endpoint': { type: 'string', env: 'LOCAL_MODEL_ENDPOINT' },
  'vertexConfig.enabled': { type: 'boolean', env: 'VERTEX_ENABLED' },
  'vertexConfig.projectId': { type: 'string', env: 'VERTEX_PROJECT_ID' },
  'vertexConfig.location': { type: 'string', env: 'VERTEX_LOCATION' },
  'monitoringConfig.enabled': { type: 'boolean', env: 'MONITORING_ENABLED' },
  'monitoringConfig.intervalSeconds': { type: 'number', env: 'MONITORING_INTERVAL' },
  'storageConfig.type': { type: 'string', env: 'STORAGE_TYPE' },
  'storageConfig.connectionString': { type: 'string', env: 'STORAGE_CONNECTION' },
  'storageConfig.retentionDays': { type: 'number', env: 'STORAGE_RETENTION_DAYS' }
};

// ============================================================================
// Config Loader Implementation
// ============================================================================

export class ConfigLoader {
  private options: Required<ConfigLoaderOptions>;

  constructor(options?: ConfigLoaderOptions) {
    this.options = {
      configPath: options?.configPath || '',
      searchPaths: options?.searchPaths || [
        process.cwd(),
        path.join(process.cwd(), 'config'),
        '/etc/security-audit',
        path.join(process.env.HOME || '', '.config', 'security-audit')
      ],
      envPrefix: options?.envPrefix || 'SECURITY_AUDIT',
      validate: options?.validate ?? true,
      allowEnvOverrides: options?.allowEnvOverrides ?? true
    };
  }

  /**
   * Load configuration from file, env, or defaults
   */
  async load(): Promise<LoadedConfig> {
    const warnings: string[] = [];
    let config: SecurityAuditAgentConfig;
    let source: 'file' | 'env' | 'default' = 'default';
    let filePath: string | undefined;

    // Try to load from file
    const fileConfig = await this.loadFromFile();
    if (fileConfig) {
      config = this.mergeConfigs(DEFAULT_CONFIG, fileConfig.config);
      source = 'file';
      filePath = fileConfig.path;
    } else {
      config = { ...DEFAULT_CONFIG };
      warnings.push('No config file found, using defaults');
    }

    // Apply environment overrides
    if (this.options.allowEnvOverrides) {
      const envOverrides = this.loadFromEnv();
      if (Object.keys(envOverrides).length > 0) {
        config = this.mergeConfigs(config, envOverrides as Partial<SecurityAuditAgentConfig>);
        if (source === 'default') {
          source = 'env';
        }
      }
    }

    // Validate
    if (this.options.validate) {
      const validationErrors = this.validateConfig(config);
      warnings.push(...validationErrors);
    }

    return { config, source, filePath, warnings };
  }

  /**
   * Load config from file
   */
  private async loadFromFile(): Promise<{ config: Partial<SecurityAuditAgentConfig>; path: string } | null> {
    const configNames = ['security-audit.yaml', 'security-audit.yml', 'security-audit.json', 'config.yaml', 'config.yml', 'config.json'];

    // Check explicit path first
    if (this.options.configPath) {
      try {
        const config = await this.readConfigFile(this.options.configPath);
        return { config, path: this.options.configPath };
      } catch (error) {
        // Explicit path failed, continue to search
      }
    }

    // Search in standard locations
    for (const searchPath of this.options.searchPaths) {
      for (const configName of configNames) {
        const fullPath = path.join(searchPath, configName);
        try {
          const config = await this.readConfigFile(fullPath);
          return { config, path: fullPath };
        } catch {
          // File doesn't exist or can't be read, continue
        }
      }
    }

    return null;
  }

  /**
   * Read and parse a config file
   */
  private async readConfigFile(filePath: string): Promise<Partial<SecurityAuditAgentConfig>> {
    const content = await fs.readFile(filePath, 'utf-8');
    const ext = path.extname(filePath).toLowerCase();

    if (ext === '.yaml' || ext === '.yml') {
      return yaml.load(content) as Partial<SecurityAuditAgentConfig>;
    } else if (ext === '.json') {
      return JSON.parse(content);
    } else {
      // Try YAML first, then JSON
      try {
        return yaml.load(content) as Partial<SecurityAuditAgentConfig>;
      } catch {
        return JSON.parse(content);
      }
    }
  }

  /**
   * Load config from environment variables
   */
  private loadFromEnv(): Record<string, unknown> {
    const config: Record<string, unknown> = {};
    const prefix = this.options.envPrefix + '_';

    for (const [path, schema] of Object.entries(CONFIG_SCHEMA)) {
      const envKey = schema.env ? `${prefix}${schema.env}` : `${prefix}${path.toUpperCase().replace(/\./g, '_')}`;
      const envValue = process.env[envKey];

      if (envValue !== undefined) {
        const value = this.parseEnvValue(envValue, schema.type);
        this.setNestedValue(config, path, value);
      }
    }

    return config;
  }

  /**
   * Parse environment variable to appropriate type
   */
  private parseEnvValue(value: string, type: string): unknown {
    switch (type) {
      case 'number':
        return parseFloat(value);
      case 'boolean':
        return value.toLowerCase() === 'true' || value === '1';
      case 'array':
        return value.split(',').map(s => s.trim());
      case 'object':
        try {
          return JSON.parse(value);
        } catch {
          return value;
        }
      default:
        return value;
    }
  }

  /**
   * Set a nested value in an object using dot notation
   */
  private setNestedValue(obj: Record<string, unknown>, path: string, value: unknown): void {
    const parts = path.split('.');
    let current = obj;

    for (let i = 0; i < parts.length - 1; i++) {
      const part = parts[i];
      if (!(part in current)) {
        current[part] = {};
      }
      current = current[part] as Record<string, unknown>;
    }

    current[parts[parts.length - 1]] = value;
  }

  /**
   * Deep merge two configs
   */
  private mergeConfigs<T extends object>(base: T, override: Partial<T>): T {
    const result = { ...base };

    for (const key of Object.keys(override) as Array<keyof T>) {
      const overrideValue = override[key];
      const baseValue = result[key];

      if (overrideValue === undefined) continue;

      if (
        typeof overrideValue === 'object' &&
        overrideValue !== null &&
        !Array.isArray(overrideValue) &&
        typeof baseValue === 'object' &&
        baseValue !== null &&
        !Array.isArray(baseValue)
      ) {
        result[key] = this.mergeConfigs(baseValue as object, overrideValue as object) as T[keyof T];
      } else {
        result[key] = overrideValue as T[keyof T];
      }
    }

    return result;
  }

  /**
   * Validate configuration
   */
  private validateConfig(config: SecurityAuditAgentConfig): string[] {
    const errors: string[] = [];

    // Check required fields
    if (!config.name) {
      errors.push('Config validation: name is required');
    }

    // Validate model config
    if (config.modelConfig) {
      if (config.modelConfig.temperature < 0 || config.modelConfig.temperature > 1) {
        errors.push('Config validation: modelConfig.temperature must be between 0 and 1');
      }
      if (config.modelConfig.maxTokens < 1) {
        errors.push('Config validation: modelConfig.maxTokens must be positive');
      }
    }

    // Validate Vertex config
    if (config.vertexConfig?.enabled && !config.vertexConfig.projectId) {
      errors.push('Config validation: vertexConfig.projectId required when Vertex is enabled');
    }

    // Validate monitoring config
    if (config.monitoringConfig?.intervalSeconds < 5) {
      errors.push('Config validation: monitoringConfig.intervalSeconds must be >= 5');
    }

    // Validate storage config
    if (config.storageConfig?.type === 'postgres' && !config.storageConfig.connectionString) {
      errors.push('Config validation: storageConfig.connectionString required for postgres');
    }

    return errors;
  }

  /**
   * Write config to file
   */
  async save(config: SecurityAuditAgentConfig, filePath: string): Promise<void> {
    const ext = path.extname(filePath).toLowerCase();
    let content: string;

    if (ext === '.yaml' || ext === '.yml') {
      content = yaml.dump(config, { indent: 2, lineWidth: 120 });
    } else {
      content = JSON.stringify(config, null, 2);
    }

    await fs.mkdir(path.dirname(filePath), { recursive: true });
    await fs.writeFile(filePath, content, 'utf-8');
  }

  /**
   * Generate a sample config file
   */
  static generateSampleConfig(): string {
    return `# Security Audit Agent Configuration
# =====================================

# Agent identification
name: SecurityAuditAgent
description: AI-powered infrastructure security auditing

# AI Model Configuration
modelConfig:
  modelId: anthropic.claude-3-sonnet-20240229-v1:0
  temperature: 0
  maxTokens: 4096
  streaming: true

# Local Model (Ollama) Configuration
localModelConfig:
  enabled: true
  modelType: ollama
  endpoint: http://localhost:11434
  # modelPath: /path/to/model  # For local file models
  capabilities:
    - scan
    - classify

# Vertex AI Configuration (for cloud analysis)
vertexConfig:
  enabled: false
  projectId: your-gcp-project
  location: us-central1
  modelId: gemini-1.5-pro
  useForPatternAnalysis: true
  useForAnomalyDetection: true

# Scan Configurations
scanConfigs:
  - type: config
    enabled: true
    targets:
      - /etc
      - /home
    excludePatterns:
      - "*.log"
      - "*.tmp"

  - type: network
    enabled: true
    targets:
      - 192.168.1.0/24

  - type: container
    enabled: true

  - type: auth
    enabled: true

  - type: log
    enabled: true
    targets:
      - /var/log

# Continuous Monitoring
monitoringConfig:
  enabled: true
  intervalSeconds: 60
  alertThresholds:
    - metric: critical_findings
      operator: gt
      value: 0
      severity: critical
    - metric: high_findings
      operator: gt
      value: 5
      severity: high
  notificationChannels:
    - type: matrix
      config:
        homeserver: https://matrix.example.com
        roomId: "!room:example.com"

# Data Sanitization
sanitizationConfig:
  enabled: true
  preserveFormat: true
  hashSensitiveValues: false
  patterns:
    - pattern: "\\\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\\\.[A-Z|a-z]{2,}\\\\b"
      replacement: "[EMAIL]"
      type: email
    - pattern: "(?:password|secret|token|api_key)\\\\s*[=:]\\\\s*[^\\\\s]+"
      replacement: "[REDACTED]"
      type: credential

# Storage Configuration
storageConfig:
  type: sqlite  # sqlite, postgres, or memory
  connectionString: ./security-audit.db
  retentionDays: 90
  encryptAtRest: false

# Network Traffic Monitoring
networkMonitorConfig:
  enabled: true
  interval: 5000
  trackProcesses: true
  alertOnNewConnections: false
  dataExfilThreshold: 10485760  # 10MB
  whitelistedDestinations:
    - "*.google.com"
    - "*.microsoft.com"
    - "*.ubuntu.com"
  whitelistedProcesses:
    - systemd-resolve
    - snapd

# ClamAV Integration
clamavConfig:
  enabled: true
  socketPath: /var/run/clamav/clamd.ctl
  scanOnAccess: false
  quarantinePath: /var/lib/security-audit/quarantine
  emailAlerts:
    enabled: false
    smtpHost: smtp.example.com
    smtpPort: 587
    from: security@example.com
    to:
      - admin@example.com

# Matrix Integration
matrixConfig:
  enabled: true
  homeserver: https://matrix.example.com
  accessToken: \${MATRIX_ACCESS_TOKEN}
  defaultRoom: "!alerts:example.com"
  severityRooms:
    critical: "!critical:example.com"
    high: "!security:example.com"
`;
  }
}

/**
 * Convenience function to load config
 */
export async function loadConfig(options?: ConfigLoaderOptions): Promise<LoadedConfig> {
  const loader = new ConfigLoader(options);
  return loader.load();
}

/**
 * Generate sample config file
 */
export function generateSampleConfig(): string {
  return ConfigLoader.generateSampleConfig();
}

export default ConfigLoader;
