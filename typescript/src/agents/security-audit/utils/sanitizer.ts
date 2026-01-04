/**
 * Data Sanitization Utility
 * Sanitizes sensitive data before sending to cloud services
 * Keeps security data local while enabling cloud analysis of patterns
 */

import * as crypto from 'crypto';
import {
  SanitizationConfig,
  SanitizationPattern,
  SanitizedData,
  SanitizationLogEntry
} from '../types';

// Default sanitization patterns for common sensitive data
export const DEFAULT_SANITIZATION_PATTERNS: SanitizationPattern[] = [
  // Credentials
  {
    name: 'password',
    pattern: /(?:password|passwd|pwd|secret)[\s]*[=:]\s*['"]?([^'"\s\n]+)['"]?/gi,
    replacement: (match: string) => match.replace(/[=:]\s*['"]?([^'"\s\n]+)['"]?/, '=[REDACTED]'),
    category: 'credentials'
  },
  {
    name: 'api_key',
    pattern: /(?:api[_-]?key|apikey|api[_-]?secret)[\s]*[=:]\s*['"]?([A-Za-z0-9_\-\.]+)['"]?/gi,
    replacement: '[API_KEY_REDACTED]',
    category: 'credentials'
  },
  {
    name: 'bearer_token',
    pattern: /Bearer\s+[A-Za-z0-9_\-\.]+/gi,
    replacement: 'Bearer [TOKEN_REDACTED]',
    category: 'credentials'
  },
  {
    name: 'aws_access_key',
    pattern: /AKIA[0-9A-Z]{16}/g,
    replacement: '[AWS_ACCESS_KEY_REDACTED]',
    category: 'credentials'
  },
  {
    name: 'aws_secret_key',
    pattern: /(?:aws[_-]?secret[_-]?(?:access[_-]?)?key)[\s]*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi,
    replacement: '[AWS_SECRET_REDACTED]',
    category: 'credentials'
  },
  {
    name: 'private_key',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    replacement: '[PRIVATE_KEY_REDACTED]',
    category: 'credentials'
  },
  {
    name: 'jwt_token',
    pattern: /eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/g,
    replacement: '[JWT_REDACTED]',
    category: 'credentials'
  },

  // PII
  {
    name: 'email',
    pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    replacement: (match: string) => {
      const [local, domain] = match.split('@');
      return `${local[0]}***@${domain}`;
    },
    category: 'pii'
  },
  {
    name: 'phone',
    pattern: /(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}/g,
    replacement: '[PHONE_REDACTED]',
    category: 'pii'
  },
  {
    name: 'ssn',
    pattern: /\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b/g,
    replacement: '[SSN_REDACTED]',
    category: 'pii'
  },
  {
    name: 'credit_card',
    pattern: /\b(?:[0-9]{4}[-\s]?){3}[0-9]{4}\b/g,
    replacement: '[CC_REDACTED]',
    category: 'pii'
  },
  {
    name: 'imsi',
    pattern: /\b[0-9]{15}\b/g,
    replacement: '[IMSI_REDACTED]',
    category: 'pii'
  },
  {
    name: 'imei',
    pattern: /\b[0-9]{15,17}\b/g,
    replacement: '[IMEI_REDACTED]',
    category: 'pii'
  },

  // Network
  {
    name: 'internal_ip',
    pattern: /\b(?:10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3})\b/g,
    replacement: (match: string) => {
      const parts = match.split('.');
      return `${parts[0]}.${parts[1]}.x.x`;
    },
    category: 'network'
  },
  {
    name: 'mac_address',
    pattern: /\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g,
    replacement: '[MAC_REDACTED]',
    category: 'network'
  },

  // Internal paths and hostnames
  {
    name: 'internal_hostname',
    pattern: /\b[a-z0-9-]+\.(?:internal|local|corp|private|lan)\b/gi,
    replacement: '[INTERNAL_HOST]',
    category: 'internal'
  },
  {
    name: 'file_path_unix',
    pattern: /\/(?:home|Users|var|etc)\/[a-zA-Z0-9._\-\/]+/g,
    replacement: (match: string) => {
      const parts = match.split('/');
      if (parts.length > 3) {
        return `/${parts[1]}/${parts[2]}/[PATH_REDACTED]`;
      }
      return match;
    },
    category: 'internal'
  },
  {
    name: 'database_connection',
    pattern: /(?:mysql|postgresql|mongodb|redis):\/\/[^\s]+/gi,
    replacement: (match: string) => {
      const protocol = match.split('://')[0];
      return `${protocol}://[CONNECTION_REDACTED]`;
    },
    category: 'credentials'
  }
];

/**
 * Sanitizer class for cleaning sensitive data
 */
export class DataSanitizer {
  private config: SanitizationConfig;
  private patterns: SanitizationPattern[];

  constructor(config?: Partial<SanitizationConfig>) {
    this.config = {
      enabled: config?.enabled ?? true,
      patterns: config?.patterns ?? DEFAULT_SANITIZATION_PATTERNS,
      preserveFormat: config?.preserveFormat ?? true,
      hashSensitiveValues: config?.hashSensitiveValues ?? false
    };
    this.patterns = this.config.patterns;
  }

  /**
   * Add custom sanitization patterns
   */
  addPattern(pattern: SanitizationPattern): void {
    this.patterns.push(pattern);
  }

  /**
   * Sanitize a string value
   */
  sanitizeString(value: string): { sanitized: string; log: SanitizationLogEntry[] } {
    if (!this.config.enabled) {
      return { sanitized: value, log: [] };
    }

    let result = value;
    const log: SanitizationLogEntry[] = [];

    for (const pattern of this.patterns) {
      const matches = result.match(pattern.pattern);
      if (matches && matches.length > 0) {
        const replacement = typeof pattern.replacement === 'function'
          ? pattern.replacement
          : () => pattern.replacement as string;

        result = result.replace(pattern.pattern, replacement as (...args: string[]) => string);

        log.push({
          field: pattern.name,
          category: pattern.category,
          originalLength: matches.reduce((sum, m) => sum + m.length, 0),
          replaced: true
        });
      }
    }

    return { sanitized: result, log };
  }

  /**
   * Sanitize an object recursively
   */
  sanitizeObject<T extends Record<string, unknown>>(obj: T): SanitizedData<T> {
    const sanitizationLog: SanitizationLogEntry[] = [];
    const originalHash = this.hashObject(obj);

    const sanitized = this.sanitizeRecursive(obj, '', sanitizationLog);

    return {
      data: sanitized as T,
      sanitizationLog,
      originalHash
    };
  }

  private sanitizeRecursive(
    value: unknown,
    path: string,
    log: SanitizationLogEntry[]
  ): unknown {
    if (value === null || value === undefined) {
      return value;
    }

    if (typeof value === 'string') {
      const { sanitized, log: stringLog } = this.sanitizeString(value);
      stringLog.forEach(entry => {
        log.push({ ...entry, field: path ? `${path}.${entry.field}` : entry.field });
      });
      return sanitized;
    }

    if (Array.isArray(value)) {
      return value.map((item, index) =>
        this.sanitizeRecursive(item, `${path}[${index}]`, log)
      );
    }

    if (typeof value === 'object') {
      const result: Record<string, unknown> = {};
      for (const [key, val] of Object.entries(value)) {
        const newPath = path ? `${path}.${key}` : key;
        result[key] = this.sanitizeRecursive(val, newPath, log);
      }
      return result;
    }

    return value;
  }

  /**
   * Create a hash of an object for verification
   */
  private hashObject(obj: unknown): string {
    const json = JSON.stringify(obj, null, 0);
    return crypto.createHash('sha256').update(json).digest('hex').substring(0, 16);
  }

  /**
   * Anonymize config data for cloud analysis
   * Preserves structure and patterns while removing sensitive values
   */
  anonymizeForAnalysis(data: Record<string, unknown>): Record<string, unknown> {
    return this.anonymizeRecursive(data);
  }

  private anonymizeRecursive(value: unknown): unknown {
    if (value === null || value === undefined) {
      return value;
    }

    if (typeof value === 'string') {
      // Preserve the type and approximate length, but anonymize content
      if (value.length === 0) return '';
      if (value.length <= 5) return 'x'.repeat(value.length);
      return `[${value.length} chars]`;
    }

    if (typeof value === 'number') {
      // Preserve numeric type but anonymize
      return 0;
    }

    if (typeof value === 'boolean') {
      return value; // Booleans are generally safe
    }

    if (Array.isArray(value)) {
      return value.map(item => this.anonymizeRecursive(item));
    }

    if (typeof value === 'object') {
      const result: Record<string, unknown> = {};
      for (const [key, val] of Object.entries(value)) {
        // Keep keys but anonymize values (keys often contain structural info)
        result[key] = this.anonymizeRecursive(val);
      }
      return result;
    }

    return value;
  }

  /**
   * Extract patterns from data without sensitive content
   * Useful for sending to cloud for pattern analysis
   */
  extractPatterns(data: Record<string, unknown>): PatternSummary {
    const patterns: PatternSummary = {
      structure: this.extractStructure(data),
      types: this.extractTypes(data),
      keyPatterns: this.extractKeyPatterns(data),
      valuePatterns: this.extractValuePatterns(data)
    };
    return patterns;
  }

  private extractStructure(obj: unknown, depth = 0): StructureNode {
    if (depth > 10) return { type: 'max_depth' };

    if (obj === null) return { type: 'null' };
    if (obj === undefined) return { type: 'undefined' };
    if (typeof obj === 'string') return { type: 'string', length: obj.length };
    if (typeof obj === 'number') return { type: 'number' };
    if (typeof obj === 'boolean') return { type: 'boolean' };

    if (Array.isArray(obj)) {
      return {
        type: 'array',
        length: obj.length,
        itemType: obj.length > 0 ? this.extractStructure(obj[0], depth + 1) : undefined
      };
    }

    if (typeof obj === 'object') {
      const children: Record<string, StructureNode> = {};
      for (const [key, value] of Object.entries(obj)) {
        children[key] = this.extractStructure(value, depth + 1);
      }
      return { type: 'object', children };
    }

    return { type: 'unknown' };
  }

  private extractTypes(obj: unknown): TypeSummary {
    const summary: TypeSummary = {
      strings: 0,
      numbers: 0,
      booleans: 0,
      nulls: 0,
      arrays: 0,
      objects: 0
    };
    this.countTypes(obj, summary);
    return summary;
  }

  private countTypes(obj: unknown, summary: TypeSummary): void {
    if (obj === null) { summary.nulls++; return; }
    if (typeof obj === 'string') { summary.strings++; return; }
    if (typeof obj === 'number') { summary.numbers++; return; }
    if (typeof obj === 'boolean') { summary.booleans++; return; }
    if (Array.isArray(obj)) {
      summary.arrays++;
      obj.forEach(item => this.countTypes(item, summary));
      return;
    }
    if (typeof obj === 'object') {
      summary.objects++;
      Object.values(obj).forEach(value => this.countTypes(value, summary));
    }
  }

  private extractKeyPatterns(obj: unknown): string[] {
    const keys = new Set<string>();
    this.collectKeys(obj, keys);
    return Array.from(keys);
  }

  private collectKeys(obj: unknown, keys: Set<string>): void {
    if (typeof obj !== 'object' || obj === null) return;
    if (Array.isArray(obj)) {
      obj.forEach(item => this.collectKeys(item, keys));
      return;
    }
    for (const [key, value] of Object.entries(obj)) {
      keys.add(key);
      this.collectKeys(value, keys);
    }
  }

  private extractValuePatterns(obj: unknown): ValuePattern[] {
    const patterns: ValuePattern[] = [];
    this.analyzeValuePatterns(obj, patterns);
    return patterns;
  }

  private analyzeValuePatterns(obj: unknown, patterns: ValuePattern[]): void {
    if (typeof obj === 'string') {
      // Detect common patterns in string values
      if (/^[0-9a-f]{32}$/i.test(obj)) patterns.push({ type: 'md5_hash' });
      else if (/^[0-9a-f]{40}$/i.test(obj)) patterns.push({ type: 'sha1_hash' });
      else if (/^[0-9a-f]{64}$/i.test(obj)) patterns.push({ type: 'sha256_hash' });
      else if (/^\d{4}-\d{2}-\d{2}/.test(obj)) patterns.push({ type: 'date' });
      else if (/^https?:\/\//.test(obj)) patterns.push({ type: 'url' });
      else if (/^\d+\.\d+\.\d+\.\d+$/.test(obj)) patterns.push({ type: 'ip_address' });
      return;
    }
    if (Array.isArray(obj)) {
      obj.forEach(item => this.analyzeValuePatterns(item, patterns));
      return;
    }
    if (typeof obj === 'object' && obj !== null) {
      Object.values(obj).forEach(value => this.analyzeValuePatterns(value, patterns));
    }
  }
}

interface StructureNode {
  type: string;
  length?: number;
  itemType?: StructureNode;
  children?: Record<string, StructureNode>;
}

interface TypeSummary {
  strings: number;
  numbers: number;
  booleans: number;
  nulls: number;
  arrays: number;
  objects: number;
}

interface ValuePattern {
  type: string;
}

interface PatternSummary {
  structure: StructureNode;
  types: TypeSummary;
  keyPatterns: string[];
  valuePatterns: ValuePattern[];
}

export default DataSanitizer;
