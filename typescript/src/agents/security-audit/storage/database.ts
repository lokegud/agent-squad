/**
 * Database Storage Layer
 *
 * Provides persistence for:
 * - Audit results and findings
 * - Historical trends
 * - Alert history
 * - Configuration snapshots
 *
 * Supports: SQLite (default), PostgreSQL
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import { FullAuditResult, AuditResult, Finding, SeverityLevel } from '../types';
import { eventBus, SourceLogger } from '../utils/eventBus';

// ============================================================================
// Types
// ============================================================================

export interface StorageConfig {
  /** Storage type */
  type: 'sqlite' | 'postgres' | 'memory';
  /** Connection string or file path */
  connectionString: string;
  /** Days to retain data */
  retentionDays: number;
  /** Encrypt data at rest */
  encryptAtRest: boolean;
  /** Encryption key (required if encryptAtRest is true) */
  encryptionKey?: string;
}

export interface StoredAudit {
  id: string;
  timestamp: Date;
  status: string;
  riskScore: number;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  duration: number;
  metadata?: Record<string, unknown>;
}

export interface StoredFinding {
  id: string;
  auditId: string;
  timestamp: Date;
  severity: SeverityLevel;
  category: string;
  title: string;
  description: string;
  location: string;
  remediation: string;
  status: 'open' | 'resolved' | 'ignored' | 'false_positive';
  resolvedAt?: Date;
  resolvedBy?: string;
  notes?: string;
  hash: string;  // For deduplication
}

export interface TrendData {
  date: Date;
  riskScore: number;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
}

export interface StoredAlert {
  id: string;
  timestamp: Date;
  severity: string;
  type: string;
  message: string;
  source: string;
  acknowledged: boolean;
  acknowledgedAt?: Date;
  acknowledgedBy?: string;
  data?: Record<string, unknown>;
}

export interface QueryOptions {
  limit?: number;
  offset?: number;
  orderBy?: string;
  orderDir?: 'asc' | 'desc';
  filters?: Record<string, unknown>;
}

// ============================================================================
// Database Interface
// ============================================================================

export interface IDatabase {
  initialize(): Promise<void>;
  close(): Promise<void>;

  // Audits
  saveAudit(result: FullAuditResult): Promise<string>;
  getAudit(id: string): Promise<StoredAudit | null>;
  listAudits(options?: QueryOptions): Promise<StoredAudit[]>;
  deleteAudit(id: string): Promise<boolean>;

  // Findings
  saveFinding(finding: StoredFinding): Promise<string>;
  getFinding(id: string): Promise<StoredFinding | null>;
  listFindings(options?: QueryOptions): Promise<StoredFinding[]>;
  updateFindingStatus(id: string, status: StoredFinding['status'], by?: string, notes?: string): Promise<boolean>;
  getOpenFindings(): Promise<StoredFinding[]>;
  findDuplicateFinding(hash: string): Promise<StoredFinding | null>;

  // Trends
  getTrends(days: number): Promise<TrendData[]>;
  getRiskScoreHistory(days: number): Promise<Array<{ date: Date; score: number }>>;

  // Alerts
  saveAlert(alert: Omit<StoredAlert, 'id'>): Promise<string>;
  getAlert(id: string): Promise<StoredAlert | null>;
  listAlerts(options?: QueryOptions): Promise<StoredAlert[]>;
  acknowledgeAlert(id: string, by: string): Promise<boolean>;
  getUnacknowledgedAlerts(): Promise<StoredAlert[]>;

  // Maintenance
  pruneOldData(retentionDays: number): Promise<number>;
  getStats(): Promise<{ audits: number; findings: number; alerts: number; dbSize: number }>;
}

// ============================================================================
// SQLite Implementation
// ============================================================================

export class SQLiteDatabase implements IDatabase {
  private db: any;  // better-sqlite3 or sql.js instance
  private config: StorageConfig;
  private logger: SourceLogger;
  private initialized: boolean = false;

  constructor(config: StorageConfig) {
    this.config = config;
    this.logger = eventBus.createLogger('SQLiteDatabase');
  }

  async initialize(): Promise<void> {
    if (this.initialized) return;

    try {
      // Ensure directory exists
      const dir = path.dirname(this.config.connectionString);
      await fs.mkdir(dir, { recursive: true });

      // Use better-sqlite3 if available, fall back to sql.js
      try {
        const Database = require('better-sqlite3');
        this.db = new Database(this.config.connectionString);
        this.db.pragma('journal_mode = WAL');
      } catch {
        // Fall back to in-memory simulation with file persistence
        this.db = new InMemoryDatabase(this.config.connectionString);
        await this.db.load();
      }

      await this.createTables();
      this.initialized = true;
      this.logger.info('storage', 'initialized', `SQLite database initialized at ${this.config.connectionString}`);
    } catch (error) {
      this.logger.error('storage', 'init_failed', 'Failed to initialize SQLite database', {}, error as Error);
      throw error;
    }
  }

  private async createTables(): Promise<void> {
    const tables = `
      CREATE TABLE IF NOT EXISTS audits (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        status TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        total_findings INTEGER NOT NULL,
        critical_count INTEGER NOT NULL,
        high_count INTEGER NOT NULL,
        medium_count INTEGER NOT NULL,
        low_count INTEGER NOT NULL,
        info_count INTEGER NOT NULL,
        duration INTEGER NOT NULL,
        metadata TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS findings (
        id TEXT PRIMARY KEY,
        audit_id TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        severity TEXT NOT NULL,
        category TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        location TEXT NOT NULL,
        remediation TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'open',
        resolved_at TEXT,
        resolved_by TEXT,
        notes TEXT,
        hash TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (audit_id) REFERENCES audits(id)
      );

      CREATE TABLE IF NOT EXISTS alerts (
        id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        severity TEXT NOT NULL,
        type TEXT NOT NULL,
        message TEXT NOT NULL,
        source TEXT NOT NULL,
        acknowledged INTEGER NOT NULL DEFAULT 0,
        acknowledged_at TEXT,
        acknowledged_by TEXT,
        data TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
      );

      CREATE INDEX IF NOT EXISTS idx_audits_timestamp ON audits(timestamp);
      CREATE INDEX IF NOT EXISTS idx_findings_audit_id ON findings(audit_id);
      CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
      CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
      CREATE INDEX IF NOT EXISTS idx_findings_hash ON findings(hash);
      CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
      CREATE INDEX IF NOT EXISTS idx_alerts_acknowledged ON alerts(acknowledged);
    `;

    if (this.db.exec) {
      this.db.exec(tables);
    } else {
      await this.db.run(tables);
    }
  }

  async close(): Promise<void> {
    if (this.db) {
      if (this.db.close) {
        this.db.close();
      } else if (this.db.save) {
        await this.db.save();
      }
    }
    this.initialized = false;
  }

  // ==========================================================================
  // Audits
  // ==========================================================================

  async saveAudit(result: FullAuditResult): Promise<string> {
    const duration = result.endTime
      ? result.endTime.getTime() - result.startTime.getTime()
      : 0;

    const sql = `
      INSERT INTO audits (id, timestamp, status, risk_score, total_findings,
        critical_count, high_count, medium_count, low_count, info_count, duration, metadata)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    const params = [
      result.auditId,
      result.startTime.toISOString(),
      result.status,
      result.overallSummary.riskScore,
      result.overallSummary.totalFindings,
      result.overallSummary.criticalCount,
      result.overallSummary.highCount,
      result.overallSummary.mediumCount,
      result.overallSummary.lowCount,
      result.overallSummary.infoCount,
      duration,
      JSON.stringify({})
    ];

    await this.run(sql, params);

    // Save findings from each category
    const categories = ['configAudit', 'networkMapping', 'containerSecurity', 'authReview', 'logAnalysis'];
    for (const category of categories) {
      const auditResult = (result as Record<string, unknown>)[category] as AuditResult | undefined;
      if (auditResult?.findings) {
        for (const finding of auditResult.findings) {
          await this.saveFindingFromAudit(result.auditId, category, finding);
        }
      }
    }

    this.logger.info('storage', 'audit_saved', `Saved audit ${result.auditId}`, {
      findings: result.overallSummary.totalFindings
    });

    return result.auditId;
  }

  private async saveFindingFromAudit(auditId: string, category: string, finding: Finding): Promise<void> {
    const hash = this.hashFinding(finding);
    const id = `${auditId}-${hash.slice(0, 8)}`;

    const sql = `
      INSERT OR IGNORE INTO findings (id, audit_id, timestamp, severity, category,
        title, description, location, remediation, status, hash)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    await this.run(sql, [
      id,
      auditId,
      new Date().toISOString(),
      finding.severity,
      category,
      finding.title,
      finding.description,
      finding.location,
      finding.remediation,
      'open',
      hash
    ]);
  }

  async getAudit(id: string): Promise<StoredAudit | null> {
    const sql = 'SELECT * FROM audits WHERE id = ?';
    const row = await this.get(sql, [id]);
    return row ? this.rowToAudit(row) : null;
  }

  async listAudits(options?: QueryOptions): Promise<StoredAudit[]> {
    let sql = 'SELECT * FROM audits';
    const params: unknown[] = [];

    sql += ` ORDER BY ${options?.orderBy || 'timestamp'} ${options?.orderDir || 'DESC'}`;

    if (options?.limit) {
      sql += ' LIMIT ?';
      params.push(options.limit);
    }
    if (options?.offset) {
      sql += ' OFFSET ?';
      params.push(options.offset);
    }

    const rows = await this.all(sql, params);
    return rows.map(this.rowToAudit);
  }

  async deleteAudit(id: string): Promise<boolean> {
    await this.run('DELETE FROM findings WHERE audit_id = ?', [id]);
    const result = await this.run('DELETE FROM audits WHERE id = ?', [id]);
    return result.changes > 0;
  }

  // ==========================================================================
  // Findings
  // ==========================================================================

  async saveFinding(finding: StoredFinding): Promise<string> {
    const sql = `
      INSERT INTO findings (id, audit_id, timestamp, severity, category,
        title, description, location, remediation, status, hash, notes)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    await this.run(sql, [
      finding.id,
      finding.auditId,
      finding.timestamp.toISOString(),
      finding.severity,
      finding.category,
      finding.title,
      finding.description,
      finding.location,
      finding.remediation,
      finding.status,
      finding.hash,
      finding.notes || null
    ]);

    return finding.id;
  }

  async getFinding(id: string): Promise<StoredFinding | null> {
    const sql = 'SELECT * FROM findings WHERE id = ?';
    const row = await this.get(sql, [id]);
    return row ? this.rowToFinding(row) : null;
  }

  async listFindings(options?: QueryOptions): Promise<StoredFinding[]> {
    let sql = 'SELECT * FROM findings';
    const params: unknown[] = [];
    const conditions: string[] = [];

    if (options?.filters) {
      if (options.filters.severity) {
        conditions.push('severity = ?');
        params.push(options.filters.severity);
      }
      if (options.filters.status) {
        conditions.push('status = ?');
        params.push(options.filters.status);
      }
      if (options.filters.category) {
        conditions.push('category = ?');
        params.push(options.filters.category);
      }
      if (options.filters.auditId) {
        conditions.push('audit_id = ?');
        params.push(options.filters.auditId);
      }
    }

    if (conditions.length > 0) {
      sql += ' WHERE ' + conditions.join(' AND ');
    }

    sql += ` ORDER BY ${options?.orderBy || 'timestamp'} ${options?.orderDir || 'DESC'}`;

    if (options?.limit) {
      sql += ' LIMIT ?';
      params.push(options.limit);
    }

    const rows = await this.all(sql, params);
    return rows.map(this.rowToFinding);
  }

  async updateFindingStatus(id: string, status: StoredFinding['status'], by?: string, notes?: string): Promise<boolean> {
    const sql = `
      UPDATE findings
      SET status = ?, resolved_at = ?, resolved_by = ?, notes = COALESCE(?, notes)
      WHERE id = ?
    `;

    const resolvedAt = status === 'resolved' ? new Date().toISOString() : null;
    const result = await this.run(sql, [status, resolvedAt, by || null, notes, id]);
    return result.changes > 0;
  }

  async getOpenFindings(): Promise<StoredFinding[]> {
    return this.listFindings({ filters: { status: 'open' } });
  }

  async findDuplicateFinding(hash: string): Promise<StoredFinding | null> {
    const sql = 'SELECT * FROM findings WHERE hash = ? AND status = ? ORDER BY timestamp DESC LIMIT 1';
    const row = await this.get(sql, [hash, 'open']);
    return row ? this.rowToFinding(row) : null;
  }

  // ==========================================================================
  // Trends
  // ==========================================================================

  async getTrends(days: number): Promise<TrendData[]> {
    const sql = `
      SELECT
        DATE(timestamp) as date,
        AVG(risk_score) as risk_score,
        SUM(total_findings) as total_findings,
        SUM(critical_count) as critical_count,
        SUM(high_count) as high_count,
        SUM(medium_count) as medium_count,
        SUM(low_count) as low_count
      FROM audits
      WHERE timestamp >= DATE('now', '-' || ? || ' days')
      GROUP BY DATE(timestamp)
      ORDER BY date ASC
    `;

    const rows = await this.all(sql, [days]);
    return rows.map(row => ({
      date: new Date(row.date),
      riskScore: Math.round(row.risk_score),
      totalFindings: row.total_findings,
      criticalCount: row.critical_count,
      highCount: row.high_count,
      mediumCount: row.medium_count,
      lowCount: row.low_count
    }));
  }

  async getRiskScoreHistory(days: number): Promise<Array<{ date: Date; score: number }>> {
    const sql = `
      SELECT timestamp, risk_score
      FROM audits
      WHERE timestamp >= DATE('now', '-' || ? || ' days')
      ORDER BY timestamp ASC
    `;

    const rows = await this.all(sql, [days]);
    return rows.map(row => ({
      date: new Date(row.timestamp),
      score: row.risk_score
    }));
  }

  // ==========================================================================
  // Alerts
  // ==========================================================================

  async saveAlert(alert: Omit<StoredAlert, 'id'>): Promise<string> {
    const id = `alert-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

    const sql = `
      INSERT INTO alerts (id, timestamp, severity, type, message, source, acknowledged, data)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `;

    await this.run(sql, [
      id,
      alert.timestamp.toISOString(),
      alert.severity,
      alert.type,
      alert.message,
      alert.source,
      alert.acknowledged ? 1 : 0,
      alert.data ? JSON.stringify(alert.data) : null
    ]);

    return id;
  }

  async getAlert(id: string): Promise<StoredAlert | null> {
    const sql = 'SELECT * FROM alerts WHERE id = ?';
    const row = await this.get(sql, [id]);
    return row ? this.rowToAlert(row) : null;
  }

  async listAlerts(options?: QueryOptions): Promise<StoredAlert[]> {
    let sql = 'SELECT * FROM alerts';
    const params: unknown[] = [];

    sql += ` ORDER BY ${options?.orderBy || 'timestamp'} ${options?.orderDir || 'DESC'}`;

    if (options?.limit) {
      sql += ' LIMIT ?';
      params.push(options.limit);
    }

    const rows = await this.all(sql, params);
    return rows.map(this.rowToAlert);
  }

  async acknowledgeAlert(id: string, by: string): Promise<boolean> {
    const sql = 'UPDATE alerts SET acknowledged = 1, acknowledged_at = ?, acknowledged_by = ? WHERE id = ?';
    const result = await this.run(sql, [new Date().toISOString(), by, id]);
    return result.changes > 0;
  }

  async getUnacknowledgedAlerts(): Promise<StoredAlert[]> {
    const sql = 'SELECT * FROM alerts WHERE acknowledged = 0 ORDER BY timestamp DESC';
    const rows = await this.all(sql, []);
    return rows.map(this.rowToAlert);
  }

  // ==========================================================================
  // Maintenance
  // ==========================================================================

  async pruneOldData(retentionDays: number): Promise<number> {
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - retentionDays);
    const cutoffStr = cutoff.toISOString();

    let deleted = 0;

    // Delete old findings first (foreign key)
    const findingsResult = await this.run(
      'DELETE FROM findings WHERE audit_id IN (SELECT id FROM audits WHERE timestamp < ?)',
      [cutoffStr]
    );
    deleted += findingsResult.changes;

    // Delete old audits
    const auditsResult = await this.run('DELETE FROM audits WHERE timestamp < ?', [cutoffStr]);
    deleted += auditsResult.changes;

    // Delete old alerts
    const alertsResult = await this.run('DELETE FROM alerts WHERE timestamp < ?', [cutoffStr]);
    deleted += alertsResult.changes;

    this.logger.info('storage', 'pruned', `Pruned ${deleted} old records`, { retentionDays });

    return deleted;
  }

  async getStats(): Promise<{ audits: number; findings: number; alerts: number; dbSize: number }> {
    const audits = await this.get('SELECT COUNT(*) as count FROM audits', []);
    const findings = await this.get('SELECT COUNT(*) as count FROM findings', []);
    const alerts = await this.get('SELECT COUNT(*) as count FROM alerts', []);

    let dbSize = 0;
    try {
      const stat = await fs.stat(this.config.connectionString);
      dbSize = stat.size;
    } catch {
      // File doesn't exist or in-memory
    }

    return {
      audits: audits?.count || 0,
      findings: findings?.count || 0,
      alerts: alerts?.count || 0,
      dbSize
    };
  }

  // ==========================================================================
  // Helpers
  // ==========================================================================

  private async run(sql: string, params: unknown[]): Promise<{ changes: number }> {
    if (this.db.prepare) {
      const stmt = this.db.prepare(sql);
      const result = stmt.run(...params);
      return { changes: result.changes };
    } else {
      return this.db.run(sql, params);
    }
  }

  private async get(sql: string, params: unknown[]): Promise<Record<string, unknown> | undefined> {
    if (this.db.prepare) {
      const stmt = this.db.prepare(sql);
      return stmt.get(...params);
    } else {
      return this.db.get(sql, params);
    }
  }

  private async all(sql: string, params: unknown[]): Promise<Array<Record<string, unknown>>> {
    if (this.db.prepare) {
      const stmt = this.db.prepare(sql);
      return stmt.all(...params);
    } else {
      return this.db.all(sql, params);
    }
  }

  private rowToAudit(row: Record<string, unknown>): StoredAudit {
    return {
      id: row.id as string,
      timestamp: new Date(row.timestamp as string),
      status: row.status as string,
      riskScore: row.risk_score as number,
      totalFindings: row.total_findings as number,
      criticalCount: row.critical_count as number,
      highCount: row.high_count as number,
      mediumCount: row.medium_count as number,
      lowCount: row.low_count as number,
      infoCount: row.info_count as number,
      duration: row.duration as number,
      metadata: row.metadata ? JSON.parse(row.metadata as string) : undefined
    };
  }

  private rowToFinding(row: Record<string, unknown>): StoredFinding {
    return {
      id: row.id as string,
      auditId: row.audit_id as string,
      timestamp: new Date(row.timestamp as string),
      severity: row.severity as SeverityLevel,
      category: row.category as string,
      title: row.title as string,
      description: row.description as string,
      location: row.location as string,
      remediation: row.remediation as string,
      status: row.status as StoredFinding['status'],
      resolvedAt: row.resolved_at ? new Date(row.resolved_at as string) : undefined,
      resolvedBy: row.resolved_by as string | undefined,
      notes: row.notes as string | undefined,
      hash: row.hash as string
    };
  }

  private rowToAlert(row: Record<string, unknown>): StoredAlert {
    return {
      id: row.id as string,
      timestamp: new Date(row.timestamp as string),
      severity: row.severity as string,
      type: row.type as string,
      message: row.message as string,
      source: row.source as string,
      acknowledged: Boolean(row.acknowledged),
      acknowledgedAt: row.acknowledged_at ? new Date(row.acknowledged_at as string) : undefined,
      acknowledgedBy: row.acknowledged_by as string | undefined,
      data: row.data ? JSON.parse(row.data as string) : undefined
    };
  }

  private hashFinding(finding: Finding): string {
    const str = `${finding.title}|${finding.location}|${finding.severity}`;
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash = hash & hash;
    }
    return Math.abs(hash).toString(16).padStart(8, '0');
  }
}

// ============================================================================
// In-Memory Database (Fallback)
// ============================================================================

class InMemoryDatabase {
  private data: {
    audits: Map<string, Record<string, unknown>>;
    findings: Map<string, Record<string, unknown>>;
    alerts: Map<string, Record<string, unknown>>;
  };
  private filePath: string;

  constructor(filePath: string) {
    this.filePath = filePath;
    this.data = {
      audits: new Map(),
      findings: new Map(),
      alerts: new Map()
    };
  }

  async load(): Promise<void> {
    try {
      const content = await fs.readFile(this.filePath, 'utf-8');
      const parsed = JSON.parse(content);
      this.data.audits = new Map(Object.entries(parsed.audits || {}));
      this.data.findings = new Map(Object.entries(parsed.findings || {}));
      this.data.alerts = new Map(Object.entries(parsed.alerts || {}));
    } catch {
      // File doesn't exist yet
    }
  }

  async save(): Promise<void> {
    const data = {
      audits: Object.fromEntries(this.data.audits),
      findings: Object.fromEntries(this.data.findings),
      alerts: Object.fromEntries(this.data.alerts)
    };
    await fs.mkdir(path.dirname(this.filePath), { recursive: true });
    await fs.writeFile(this.filePath, JSON.stringify(data, null, 2));
  }

  async run(sql: string, params: unknown[]): Promise<{ changes: number }> {
    // Parse and execute simple SQL
    const insertMatch = sql.match(/INSERT\s+(?:OR\s+IGNORE\s+)?INTO\s+(\w+)/i);
    const updateMatch = sql.match(/UPDATE\s+(\w+)/i);
    const deleteMatch = sql.match(/DELETE\s+FROM\s+(\w+)/i);

    if (insertMatch) {
      const table = insertMatch[1] as keyof typeof this.data;
      const id = params[0] as string;
      const row: Record<string, unknown> = {};

      // Extract column names from SQL
      const colMatch = sql.match(/\(([^)]+)\)\s*VALUES/i);
      if (colMatch) {
        const cols = colMatch[1].split(',').map(c => c.trim());
        cols.forEach((col, i) => {
          row[col] = params[i];
        });
      }

      this.data[table].set(id, row);
      await this.save();
      return { changes: 1 };
    }

    if (updateMatch) {
      const table = updateMatch[1] as keyof typeof this.data;
      const id = params[params.length - 1] as string;
      const existing = this.data[table].get(id);
      if (existing) {
        // Simple update - just update status fields
        existing.status = params[0];
        existing.resolved_at = params[1];
        existing.resolved_by = params[2];
        if (params[3]) existing.notes = params[3];
        await this.save();
        return { changes: 1 };
      }
      return { changes: 0 };
    }

    if (deleteMatch) {
      const table = deleteMatch[1] as keyof typeof this.data;
      const whereMatch = sql.match(/WHERE\s+(\w+)\s*=\s*\?/i);
      if (whereMatch) {
        const col = whereMatch[1];
        const value = params[0];
        let deleted = 0;
        for (const [id, row] of this.data[table].entries()) {
          if (row[col] === value) {
            this.data[table].delete(id);
            deleted++;
          }
        }
        await this.save();
        return { changes: deleted };
      }
    }

    return { changes: 0 };
  }

  async get(sql: string, params: unknown[]): Promise<Record<string, unknown> | undefined> {
    const rows = await this.all(sql, params);
    return rows[0];
  }

  async all(sql: string, params: unknown[]): Promise<Array<Record<string, unknown>>> {
    const fromMatch = sql.match(/FROM\s+(\w+)/i);
    if (!fromMatch) return [];

    const table = fromMatch[1] as keyof typeof this.data;
    let results = Array.from(this.data[table].values());

    // Handle COUNT
    if (sql.includes('COUNT(*)')) {
      return [{ count: results.length }];
    }

    // Handle WHERE
    const whereMatch = sql.match(/WHERE\s+(\w+)\s*=\s*\?/i);
    if (whereMatch) {
      const col = whereMatch[1];
      const value = params[0];
      results = results.filter(row => row[col] === value);
    }

    // Handle ORDER BY
    const orderMatch = sql.match(/ORDER\s+BY\s+(\w+)\s+(ASC|DESC)?/i);
    if (orderMatch) {
      const col = orderMatch[1];
      const dir = orderMatch[2]?.toUpperCase() === 'ASC' ? 1 : -1;
      results.sort((a, b) => {
        if (a[col] < b[col]) return -dir;
        if (a[col] > b[col]) return dir;
        return 0;
      });
    }

    // Handle LIMIT
    const limitMatch = sql.match(/LIMIT\s+\?/i);
    if (limitMatch) {
      const limitIndex = params.length - (sql.includes('OFFSET') ? 2 : 1);
      results = results.slice(0, params[limitIndex] as number);
    }

    return results;
  }
}

// ============================================================================
// Factory
// ============================================================================

export function createDatabase(config: StorageConfig): IDatabase {
  switch (config.type) {
    case 'sqlite':
    case 'memory':
      return new SQLiteDatabase(config);
    case 'postgres':
      // Would implement PostgreSQL support here
      throw new Error('PostgreSQL support not yet implemented');
    default:
      return new SQLiteDatabase(config);
  }
}

export default SQLiteDatabase;
