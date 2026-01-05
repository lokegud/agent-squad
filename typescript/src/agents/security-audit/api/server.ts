/**
 * REST API Server
 *
 * Provides HTTP API for:
 * - Running scans remotely
 * - Querying audit results
 * - Managing findings
 * - Webhook integration
 * - Health checks
 *
 * Can run standalone or integrate with Express
 */

import * as http from 'http';
import { URL } from 'url';
import { SecurityAuditAgent } from '../securityAuditAgent';
import { IDatabase, StoredFinding, QueryOptions } from '../storage/database';
import { ReportExporter } from '../reports/reportExporter';
import { eventBus, SourceLogger } from '../utils/eventBus';
import { FullAuditResult } from '../types';

// ============================================================================
// Types
// ============================================================================

export interface APIServerConfig {
  /** Port to listen on */
  port: number;
  /** Host to bind to */
  host: string;
  /** Enable CORS */
  cors: boolean;
  /** Allowed origins for CORS */
  corsOrigins?: string[];
  /** API key for authentication */
  apiKey?: string;
  /** Rate limit (requests per minute) */
  rateLimit?: number;
  /** Enable webhook endpoints */
  enableWebhooks: boolean;
  /** Webhook secret for validation */
  webhookSecret?: string;
}

export interface APIRequest {
  method: string;
  path: string;
  query: Record<string, string>;
  body: unknown;
  headers: Record<string, string>;
}

export interface APIResponse {
  status: number;
  body: unknown;
  headers?: Record<string, string>;
}

export interface WebhookConfig {
  id: string;
  url: string;
  events: string[];
  secret?: string;
  enabled: boolean;
}

type RouteHandler = (req: APIRequest) => Promise<APIResponse>;

// ============================================================================
// API Server Implementation
// ============================================================================

export class APIServer {
  private config: APIServerConfig;
  private agent: SecurityAuditAgent;
  private database: IDatabase;
  private server?: http.Server;
  private logger: SourceLogger;
  private routes: Map<string, Map<string, RouteHandler>> = new Map();
  private webhooks: Map<string, WebhookConfig> = new Map();
  private rateLimitMap: Map<string, number[]> = new Map();

  constructor(
    agent: SecurityAuditAgent,
    database: IDatabase,
    config?: Partial<APIServerConfig>
  ) {
    this.agent = agent;
    this.database = database;
    this.logger = eventBus.createLogger('APIServer');

    this.config = {
      port: config?.port ?? 8080,
      host: config?.host ?? '0.0.0.0',
      cors: config?.cors ?? true,
      corsOrigins: config?.corsOrigins ?? ['*'],
      apiKey: config?.apiKey,
      rateLimit: config?.rateLimit ?? 100,
      enableWebhooks: config?.enableWebhooks ?? true,
      webhookSecret: config?.webhookSecret
    };

    this.registerRoutes();
  }

  /**
   * Start the API server
   */
  async start(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server = http.createServer(async (req, res) => {
        try {
          await this.handleRequest(req, res);
        } catch (error) {
          this.logger.error('api', 'request_error', 'Error handling request', {}, error as Error);
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Internal server error' }));
        }
      });

      this.server.listen(this.config.port, this.config.host, () => {
        this.logger.info('api', 'started', `API server listening on ${this.config.host}:${this.config.port}`);
        resolve();
      });

      this.server.on('error', reject);
    });
  }

  /**
   * Stop the API server
   */
  async stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => {
          this.logger.info('api', 'stopped', 'API server stopped');
          resolve();
        });
      } else {
        resolve();
      }
    });
  }

  /**
   * Register all API routes
   */
  private registerRoutes(): void {
    // Health & Info
    this.route('GET', '/health', this.handleHealth.bind(this));
    this.route('GET', '/info', this.handleInfo.bind(this));
    this.route('GET', '/stats', this.handleStats.bind(this));

    // Scans
    this.route('POST', '/scan/full', this.handleFullScan.bind(this));
    this.route('POST', '/scan/config', this.handleConfigScan.bind(this));
    this.route('POST', '/scan/network', this.handleNetworkScan.bind(this));
    this.route('POST', '/scan/container', this.handleContainerScan.bind(this));
    this.route('POST', '/scan/auth', this.handleAuthScan.bind(this));
    this.route('POST', '/scan/log', this.handleLogScan.bind(this));

    // Audits
    this.route('GET', '/audits', this.handleListAudits.bind(this));
    this.route('GET', '/audits/:id', this.handleGetAudit.bind(this));
    this.route('DELETE', '/audits/:id', this.handleDeleteAudit.bind(this));
    this.route('GET', '/audits/:id/report', this.handleGetReport.bind(this));

    // Findings
    this.route('GET', '/findings', this.handleListFindings.bind(this));
    this.route('GET', '/findings/:id', this.handleGetFinding.bind(this));
    this.route('PATCH', '/findings/:id', this.handleUpdateFinding.bind(this));
    this.route('GET', '/findings/open', this.handleOpenFindings.bind(this));

    // Trends
    this.route('GET', '/trends', this.handleTrends.bind(this));
    this.route('GET', '/trends/risk', this.handleRiskTrends.bind(this));

    // Alerts
    this.route('GET', '/alerts', this.handleListAlerts.bind(this));
    this.route('GET', '/alerts/unacknowledged', this.handleUnacknowledgedAlerts.bind(this));
    this.route('POST', '/alerts/:id/acknowledge', this.handleAcknowledgeAlert.bind(this));

    // Monitoring
    this.route('POST', '/monitor/start', this.handleStartMonitoring.bind(this));
    this.route('POST', '/monitor/stop', this.handleStopMonitoring.bind(this));
    this.route('GET', '/monitor/status', this.handleMonitorStatus.bind(this));

    // Webhooks
    if (this.config.enableWebhooks) {
      this.route('GET', '/webhooks', this.handleListWebhooks.bind(this));
      this.route('POST', '/webhooks', this.handleCreateWebhook.bind(this));
      this.route('DELETE', '/webhooks/:id', this.handleDeleteWebhook.bind(this));
    }
  }

  /**
   * Register a route
   */
  private route(method: string, path: string, handler: RouteHandler): void {
    if (!this.routes.has(method)) {
      this.routes.set(method, new Map());
    }
    this.routes.get(method)!.set(path, handler);
  }

  /**
   * Handle incoming HTTP request
   */
  private async handleRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const url = new URL(req.url || '/', `http://${req.headers.host}`);
    const method = req.method || 'GET';
    const path = url.pathname;

    // CORS
    if (this.config.cors) {
      const origin = req.headers.origin || '*';
      if (this.config.corsOrigins?.includes('*') || this.config.corsOrigins?.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key');
      }
    }

    // Handle preflight
    if (method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    // Rate limiting
    if (this.config.rateLimit) {
      const clientIp = req.socket.remoteAddress || 'unknown';
      if (!this.checkRateLimit(clientIp)) {
        res.writeHead(429, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Rate limit exceeded' }));
        return;
      }
    }

    // Authentication
    if (this.config.apiKey) {
      const providedKey = req.headers['x-api-key'] || url.searchParams.get('api_key');
      if (providedKey !== this.config.apiKey) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthorized' }));
        return;
      }
    }

    // Parse request body
    let body: unknown = {};
    if (['POST', 'PUT', 'PATCH'].includes(method)) {
      body = await this.parseBody(req);
    }

    // Build API request object
    const apiReq: APIRequest = {
      method,
      path,
      query: Object.fromEntries(url.searchParams),
      body,
      headers: Object.fromEntries(
        Object.entries(req.headers)
          .filter(([, v]) => typeof v === 'string')
          .map(([k, v]) => [k, v as string])
      )
    };

    // Find matching route
    const { handler, params } = this.matchRoute(method, path);

    if (!handler) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found' }));
      return;
    }

    // Add params to query
    Object.assign(apiReq.query, params);

    // Execute handler
    try {
      const response = await handler(apiReq);

      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        ...response.headers
      };

      res.writeHead(response.status, headers);

      if (typeof response.body === 'string') {
        res.end(response.body);
      } else {
        res.end(JSON.stringify(response.body));
      }
    } catch (error) {
      this.logger.error('api', 'handler_error', `Error in ${method} ${path}`, {}, error as Error);
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Internal server error' }));
    }
  }

  /**
   * Match a route with path parameters
   */
  private matchRoute(method: string, path: string): { handler?: RouteHandler; params: Record<string, string> } {
    const methodRoutes = this.routes.get(method);
    if (!methodRoutes) return { params: {} };

    // Try exact match first
    if (methodRoutes.has(path)) {
      return { handler: methodRoutes.get(path), params: {} };
    }

    // Try pattern matching
    for (const [pattern, handler] of methodRoutes) {
      const params = this.matchPath(pattern, path);
      if (params) {
        return { handler, params };
      }
    }

    return { params: {} };
  }

  /**
   * Match path against pattern with :param placeholders
   */
  private matchPath(pattern: string, path: string): Record<string, string> | null {
    const patternParts = pattern.split('/');
    const pathParts = path.split('/');

    if (patternParts.length !== pathParts.length) return null;

    const params: Record<string, string> = {};

    for (let i = 0; i < patternParts.length; i++) {
      if (patternParts[i].startsWith(':')) {
        params[patternParts[i].slice(1)] = pathParts[i];
      } else if (patternParts[i] !== pathParts[i]) {
        return null;
      }
    }

    return params;
  }

  /**
   * Parse request body
   */
  private parseBody(req: http.IncomingMessage): Promise<unknown> {
    return new Promise((resolve, reject) => {
      let body = '';
      req.on('data', chunk => body += chunk);
      req.on('end', () => {
        try {
          resolve(body ? JSON.parse(body) : {});
        } catch {
          resolve({});
        }
      });
      req.on('error', reject);
    });
  }

  /**
   * Check rate limit
   */
  private checkRateLimit(clientIp: string): boolean {
    const now = Date.now();
    const windowMs = 60000; // 1 minute

    let requests = this.rateLimitMap.get(clientIp) || [];
    requests = requests.filter(t => now - t < windowMs);

    if (requests.length >= this.config.rateLimit!) {
      return false;
    }

    requests.push(now);
    this.rateLimitMap.set(clientIp, requests);
    return true;
  }

  // ==========================================================================
  // Route Handlers
  // ==========================================================================

  private async handleHealth(): Promise<APIResponse> {
    return { status: 200, body: { status: 'healthy', timestamp: new Date().toISOString() } };
  }

  private async handleInfo(): Promise<APIResponse> {
    return {
      status: 200,
      body: {
        name: 'Security Audit Agent API',
        version: '1.0.0',
        endpoints: Array.from(this.routes.entries()).flatMap(([method, routes]) =>
          Array.from(routes.keys()).map(path => `${method} ${path}`)
        )
      }
    };
  }

  private async handleStats(): Promise<APIResponse> {
    const stats = await this.database.getStats();
    return { status: 200, body: stats };
  }

  private async handleFullScan(): Promise<APIResponse> {
    this.logger.info('api', 'scan_started', 'Full scan initiated via API');

    const result = await this.agent.processRequest(
      'full audit',
      'api-user',
      'api-session',
      []
    );

    // Trigger webhooks
    await this.triggerWebhooks('scan.completed', { type: 'full' });

    return { status: 200, body: { message: 'Scan completed', result: result.content } };
  }

  private async handleConfigScan(): Promise<APIResponse> {
    const result = await this.agent.processRequest('config audit', 'api-user', 'api-session', []);
    return { status: 200, body: { message: 'Config scan completed', result: result.content } };
  }

  private async handleNetworkScan(): Promise<APIResponse> {
    const result = await this.agent.processRequest('network map', 'api-user', 'api-session', []);
    return { status: 200, body: { message: 'Network scan completed', result: result.content } };
  }

  private async handleContainerScan(): Promise<APIResponse> {
    const result = await this.agent.processRequest('container scan', 'api-user', 'api-session', []);
    return { status: 200, body: { message: 'Container scan completed', result: result.content } };
  }

  private async handleAuthScan(): Promise<APIResponse> {
    const result = await this.agent.processRequest('auth review', 'api-user', 'api-session', []);
    return { status: 200, body: { message: 'Auth scan completed', result: result.content } };
  }

  private async handleLogScan(): Promise<APIResponse> {
    const result = await this.agent.processRequest('log analysis', 'api-user', 'api-session', []);
    return { status: 200, body: { message: 'Log scan completed', result: result.content } };
  }

  private async handleListAudits(req: APIRequest): Promise<APIResponse> {
    const options: QueryOptions = {
      limit: parseInt(req.query.limit) || 50,
      offset: parseInt(req.query.offset) || 0,
      orderBy: req.query.orderBy || 'timestamp',
      orderDir: (req.query.orderDir as 'asc' | 'desc') || 'desc'
    };

    const audits = await this.database.listAudits(options);
    return { status: 200, body: { audits, count: audits.length } };
  }

  private async handleGetAudit(req: APIRequest): Promise<APIResponse> {
    const audit = await this.database.getAudit(req.query.id);
    if (!audit) {
      return { status: 404, body: { error: 'Audit not found' } };
    }
    return { status: 200, body: audit };
  }

  private async handleDeleteAudit(req: APIRequest): Promise<APIResponse> {
    const deleted = await this.database.deleteAudit(req.query.id);
    if (!deleted) {
      return { status: 404, body: { error: 'Audit not found' } };
    }
    return { status: 200, body: { message: 'Audit deleted' } };
  }

  private async handleGetReport(req: APIRequest): Promise<APIResponse> {
    const audit = await this.database.getAudit(req.query.id);
    if (!audit) {
      return { status: 404, body: { error: 'Audit not found' } };
    }

    const format = (req.query.format || 'html') as 'html' | 'pdf' | 'json' | 'markdown';
    const findings = await this.database.listFindings({ filters: { auditId: req.query.id } });

    // Reconstruct FullAuditResult from stored data
    const fullResult: FullAuditResult = {
      auditId: audit.id,
      status: audit.status as any,
      startTime: audit.timestamp,
      endTime: new Date(audit.timestamp.getTime() + audit.duration),
      overallSummary: {
        totalFindings: audit.totalFindings,
        criticalCount: audit.criticalCount,
        highCount: audit.highCount,
        mediumCount: audit.mediumCount,
        lowCount: audit.lowCount,
        infoCount: audit.infoCount,
        passedChecks: 0,
        failedChecks: audit.totalFindings,
        skippedChecks: 0,
        riskScore: audit.riskScore,
        recommendations: []
      },
      complianceStatus: { frameworks: [], overallCompliance: 0, criticalGaps: [] }
    };

    const exporter = new ReportExporter({ title: `Security Audit ${audit.id}` });
    const report = await exporter.generate(fullResult, format);

    const contentTypes: Record<string, string> = {
      html: 'text/html',
      pdf: 'application/pdf',
      json: 'application/json',
      markdown: 'text/markdown'
    };

    return {
      status: 200,
      body: report.content,
      headers: {
        'Content-Type': contentTypes[format],
        'Content-Disposition': `attachment; filename="${report.filename}"`
      }
    };
  }

  private async handleListFindings(req: APIRequest): Promise<APIResponse> {
    const options: QueryOptions = {
      limit: parseInt(req.query.limit) || 100,
      offset: parseInt(req.query.offset) || 0,
      filters: {}
    };

    if (req.query.severity) options.filters!.severity = req.query.severity;
    if (req.query.status) options.filters!.status = req.query.status;
    if (req.query.category) options.filters!.category = req.query.category;

    const findings = await this.database.listFindings(options);
    return { status: 200, body: { findings, count: findings.length } };
  }

  private async handleGetFinding(req: APIRequest): Promise<APIResponse> {
    const finding = await this.database.getFinding(req.query.id);
    if (!finding) {
      return { status: 404, body: { error: 'Finding not found' } };
    }
    return { status: 200, body: finding };
  }

  private async handleUpdateFinding(req: APIRequest): Promise<APIResponse> {
    const body = req.body as { status?: StoredFinding['status']; notes?: string };

    if (body.status) {
      const updated = await this.database.updateFindingStatus(
        req.query.id,
        body.status,
        req.headers['x-user'] || 'api',
        body.notes
      );

      if (!updated) {
        return { status: 404, body: { error: 'Finding not found' } };
      }

      await this.triggerWebhooks('finding.updated', { id: req.query.id, status: body.status });
    }

    return { status: 200, body: { message: 'Finding updated' } };
  }

  private async handleOpenFindings(): Promise<APIResponse> {
    const findings = await this.database.getOpenFindings();
    return { status: 200, body: { findings, count: findings.length } };
  }

  private async handleTrends(req: APIRequest): Promise<APIResponse> {
    const days = parseInt(req.query.days) || 30;
    const trends = await this.database.getTrends(days);
    return { status: 200, body: { trends, days } };
  }

  private async handleRiskTrends(req: APIRequest): Promise<APIResponse> {
    const days = parseInt(req.query.days) || 30;
    const history = await this.database.getRiskScoreHistory(days);
    return { status: 200, body: { history, days } };
  }

  private async handleListAlerts(req: APIRequest): Promise<APIResponse> {
    const options: QueryOptions = {
      limit: parseInt(req.query.limit) || 100,
      offset: parseInt(req.query.offset) || 0
    };
    const alerts = await this.database.listAlerts(options);
    return { status: 200, body: { alerts, count: alerts.length } };
  }

  private async handleUnacknowledgedAlerts(): Promise<APIResponse> {
    const alerts = await this.database.getUnacknowledgedAlerts();
    return { status: 200, body: { alerts, count: alerts.length } };
  }

  private async handleAcknowledgeAlert(req: APIRequest): Promise<APIResponse> {
    const by = req.headers['x-user'] || 'api';
    const acknowledged = await this.database.acknowledgeAlert(req.query.id, by);

    if (!acknowledged) {
      return { status: 404, body: { error: 'Alert not found' } };
    }

    return { status: 200, body: { message: 'Alert acknowledged' } };
  }

  private async handleStartMonitoring(): Promise<APIResponse> {
    await this.agent.processRequest('start monitoring', 'api-user', 'api-session', []);
    return { status: 200, body: { message: 'Monitoring started' } };
  }

  private async handleStopMonitoring(): Promise<APIResponse> {
    await this.agent.processRequest('stop monitoring', 'api-user', 'api-session', []);
    return { status: 200, body: { message: 'Monitoring stopped' } };
  }

  private async handleMonitorStatus(): Promise<APIResponse> {
    const result = await this.agent.processRequest('status', 'api-user', 'api-session', []);
    return { status: 200, body: { status: result.content } };
  }

  private async handleListWebhooks(): Promise<APIResponse> {
    const webhooks = Array.from(this.webhooks.values());
    return { status: 200, body: { webhooks } };
  }

  private async handleCreateWebhook(req: APIRequest): Promise<APIResponse> {
    const body = req.body as { url: string; events: string[]; secret?: string };

    if (!body.url || !body.events) {
      return { status: 400, body: { error: 'url and events required' } };
    }

    const webhook: WebhookConfig = {
      id: `wh-${Date.now()}`,
      url: body.url,
      events: body.events,
      secret: body.secret,
      enabled: true
    };

    this.webhooks.set(webhook.id, webhook);
    return { status: 201, body: webhook };
  }

  private async handleDeleteWebhook(req: APIRequest): Promise<APIResponse> {
    const deleted = this.webhooks.delete(req.query.id);
    if (!deleted) {
      return { status: 404, body: { error: 'Webhook not found' } };
    }
    return { status: 200, body: { message: 'Webhook deleted' } };
  }

  // ==========================================================================
  // Webhooks
  // ==========================================================================

  /**
   * Trigger webhooks for an event
   */
  private async triggerWebhooks(event: string, data: unknown): Promise<void> {
    for (const webhook of this.webhooks.values()) {
      if (!webhook.enabled || !webhook.events.includes(event)) continue;

      try {
        const payload = JSON.stringify({
          event,
          timestamp: new Date().toISOString(),
          data
        });

        const url = new URL(webhook.url);
        const options: http.RequestOptions = {
          hostname: url.hostname,
          port: url.port || (url.protocol === 'https:' ? 443 : 80),
          path: url.pathname,
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload),
            'X-Webhook-Event': event
          }
        };

        if (webhook.secret) {
          const crypto = require('crypto');
          const signature = crypto
            .createHmac('sha256', webhook.secret)
            .update(payload)
            .digest('hex');
          options.headers!['X-Webhook-Signature'] = signature;
        }

        await new Promise<void>((resolve, reject) => {
          const req = http.request(options, (res) => {
            if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
              resolve();
            } else {
              reject(new Error(`Webhook failed: ${res.statusCode}`));
            }
          });

          req.on('error', reject);
          req.write(payload);
          req.end();
        });

        this.logger.debug('api', 'webhook_sent', `Webhook sent for ${event}`, { webhookId: webhook.id });
      } catch (error) {
        this.logger.warning('api', 'webhook_failed', `Webhook failed for ${event}`, { webhookId: webhook.id },
          error instanceof Error ? error : undefined);
      }
    }
  }

  /**
   * Register webhook programmatically
   */
  registerWebhook(config: WebhookConfig): void {
    this.webhooks.set(config.id, config);
  }
}

/**
 * Create and start API server
 */
export async function createAPIServer(
  agent: SecurityAuditAgent,
  database: IDatabase,
  config?: Partial<APIServerConfig>
): Promise<APIServer> {
  const server = new APIServer(agent, database, config);
  await server.start();
  return server;
}

export default APIServer;
