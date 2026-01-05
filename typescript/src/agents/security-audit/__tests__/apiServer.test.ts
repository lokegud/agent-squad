/**
 * API Server Tests
 */

import * as http from 'http';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import { APIServer, APIServerConfig } from '../api/server';
import { SecurityAuditAgent } from '../securityAuditAgent';
import { SQLiteDatabase } from '../storage/database';

describe('APIServer', () => {
  let server: APIServer;
  let agent: SecurityAuditAgent;
  let database: SQLiteDatabase;
  let tempDir: string;
  let baseUrl: string;
  const testPort = 18080 + Math.floor(Math.random() * 1000);

  beforeAll(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'api-test-'));

    agent = new SecurityAuditAgent({
      name: 'TestAgent',
      description: 'Test security agent'
    });

    database = new SQLiteDatabase({
      type: 'sqlite',
      connectionString: path.join(tempDir, 'test.db'),
      retentionDays: 30,
      encryptAtRest: false
    });
    await database.initialize();

    server = new APIServer(agent, database, {
      port: testPort,
      host: '127.0.0.1',
      cors: true,
      enableWebhooks: true
    });

    await server.start();
    baseUrl = `http://127.0.0.1:${testPort}`;
  });

  afterAll(async () => {
    await server.stop();
    await database.close();
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  const request = (
    method: string,
    path: string,
    body?: unknown,
    headers?: Record<string, string>
  ): Promise<{ status: number; body: unknown; headers: http.IncomingHttpHeaders }> => {
    return new Promise((resolve, reject) => {
      const url = new URL(path, baseUrl);
      const options: http.RequestOptions = {
        hostname: url.hostname,
        port: url.port,
        path: url.pathname + url.search,
        method,
        headers: {
          'Content-Type': 'application/json',
          ...headers
        }
      };

      const req = http.request(options, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          let parsedBody: unknown;
          try {
            parsedBody = JSON.parse(data);
          } catch {
            parsedBody = data;
          }
          resolve({
            status: res.statusCode || 0,
            body: parsedBody,
            headers: res.headers
          });
        });
      });

      req.on('error', reject);

      if (body) {
        req.write(JSON.stringify(body));
      }
      req.end();
    });
  };

  describe('health and info endpoints', () => {
    it('GET /health should return healthy status', async () => {
      const res = await request('GET', '/health');

      expect(res.status).toBe(200);
      expect((res.body as any).status).toBe('healthy');
      expect((res.body as any).timestamp).toBeDefined();
    });

    it('GET /info should return API information', async () => {
      const res = await request('GET', '/info');

      expect(res.status).toBe(200);
      expect((res.body as any).name).toBe('Security Audit Agent API');
      expect((res.body as any).version).toBeDefined();
      expect((res.body as any).endpoints).toBeInstanceOf(Array);
    });

    it('GET /stats should return database stats', async () => {
      const res = await request('GET', '/stats');

      expect(res.status).toBe(200);
      expect(typeof (res.body as any).audits).toBe('number');
      expect(typeof (res.body as any).findings).toBe('number');
      expect(typeof (res.body as any).alerts).toBe('number');
    });
  });

  describe('audits endpoints', () => {
    it('GET /audits should return empty list initially', async () => {
      const res = await request('GET', '/audits');

      expect(res.status).toBe(200);
      expect((res.body as any).audits).toBeInstanceOf(Array);
    });

    it('GET /audits should support pagination', async () => {
      const res = await request('GET', '/audits?limit=10&offset=0');

      expect(res.status).toBe(200);
      expect((res.body as any).audits).toBeDefined();
    });

    it('GET /audits/:id should return 404 for non-existent', async () => {
      const res = await request('GET', '/audits/non-existent');

      expect(res.status).toBe(404);
      expect((res.body as any).error).toBe('Audit not found');
    });

    it('DELETE /audits/:id should return 404 for non-existent', async () => {
      const res = await request('DELETE', '/audits/non-existent');

      expect(res.status).toBe(404);
    });
  });

  describe('findings endpoints', () => {
    it('GET /findings should return list', async () => {
      const res = await request('GET', '/findings');

      expect(res.status).toBe(200);
      expect((res.body as any).findings).toBeInstanceOf(Array);
    });

    it('GET /findings should support severity filter', async () => {
      const res = await request('GET', '/findings?severity=critical');

      expect(res.status).toBe(200);
    });

    it('GET /findings should support status filter', async () => {
      const res = await request('GET', '/findings?status=open');

      expect(res.status).toBe(200);
    });

    it('GET /findings/open should return open findings', async () => {
      const res = await request('GET', '/findings/open');

      expect(res.status).toBe(200);
      expect((res.body as any).findings).toBeInstanceOf(Array);
    });

    it('GET /findings/:id should return 404 for non-existent', async () => {
      const res = await request('GET', '/findings/non-existent');

      expect(res.status).toBe(404);
    });

    it('PATCH /findings/:id should return 404 for non-existent', async () => {
      const res = await request('PATCH', '/findings/non-existent', { status: 'resolved' });

      expect(res.status).toBe(404);
    });
  });

  describe('trends endpoints', () => {
    it('GET /trends should return trend data', async () => {
      const res = await request('GET', '/trends');

      expect(res.status).toBe(200);
      expect((res.body as any).trends).toBeInstanceOf(Array);
      expect((res.body as any).days).toBe(30); // default
    });

    it('GET /trends should accept days parameter', async () => {
      const res = await request('GET', '/trends?days=7');

      expect(res.status).toBe(200);
      expect((res.body as any).days).toBe(7);
    });

    it('GET /trends/risk should return risk history', async () => {
      const res = await request('GET', '/trends/risk');

      expect(res.status).toBe(200);
      expect((res.body as any).history).toBeInstanceOf(Array);
    });
  });

  describe('alerts endpoints', () => {
    it('GET /alerts should return list', async () => {
      const res = await request('GET', '/alerts');

      expect(res.status).toBe(200);
      expect((res.body as any).alerts).toBeInstanceOf(Array);
    });

    it('GET /alerts/unacknowledged should return unacked alerts', async () => {
      const res = await request('GET', '/alerts/unacknowledged');

      expect(res.status).toBe(200);
      expect((res.body as any).alerts).toBeInstanceOf(Array);
    });

    it('POST /alerts/:id/acknowledge should return 404 for non-existent', async () => {
      const res = await request('POST', '/alerts/non-existent/acknowledge');

      expect(res.status).toBe(404);
    });
  });

  describe('monitoring endpoints', () => {
    it('GET /monitor/status should return status', async () => {
      const res = await request('GET', '/monitor/status');

      expect(res.status).toBe(200);
      expect((res.body as any).status).toBeDefined();
    });

    it('POST /monitor/start should start monitoring', async () => {
      const res = await request('POST', '/monitor/start');

      expect(res.status).toBe(200);
      expect((res.body as any).message).toContain('started');
    });

    it('POST /monitor/stop should stop monitoring', async () => {
      const res = await request('POST', '/monitor/stop');

      expect(res.status).toBe(200);
      expect((res.body as any).message).toContain('stopped');
    });
  });

  describe('webhooks endpoints', () => {
    it('GET /webhooks should return list', async () => {
      const res = await request('GET', '/webhooks');

      expect(res.status).toBe(200);
      expect((res.body as any).webhooks).toBeInstanceOf(Array);
    });

    it('POST /webhooks should create webhook', async () => {
      const res = await request('POST', '/webhooks', {
        url: 'https://example.com/webhook',
        events: ['scan.completed', 'alert.created']
      });

      expect(res.status).toBe(201);
      expect((res.body as any).id).toBeDefined();
      expect((res.body as any).url).toBe('https://example.com/webhook');
    });

    it('POST /webhooks should require url and events', async () => {
      const res = await request('POST', '/webhooks', {});

      expect(res.status).toBe(400);
      expect((res.body as any).error).toContain('required');
    });

    it('DELETE /webhooks/:id should delete webhook', async () => {
      // First create
      const createRes = await request('POST', '/webhooks', {
        url: 'https://example.com/delete-me',
        events: ['test']
      });
      const id = (createRes.body as any).id;

      // Then delete
      const deleteRes = await request('DELETE', `/webhooks/${id}`);
      expect(deleteRes.status).toBe(200);
    });

    it('DELETE /webhooks/:id should return 404 for non-existent', async () => {
      const res = await request('DELETE', '/webhooks/non-existent');

      expect(res.status).toBe(404);
    });
  });

  describe('CORS', () => {
    it('should include CORS headers', async () => {
      const res = await request('GET', '/health', undefined, {
        'Origin': 'http://localhost:3000'
      });

      expect(res.headers['access-control-allow-origin']).toBeDefined();
    });

    it('should handle OPTIONS preflight', async () => {
      const res = await request('OPTIONS', '/health');

      expect(res.status).toBe(204);
    });
  });

  describe('404 handling', () => {
    it('should return 404 for unknown routes', async () => {
      const res = await request('GET', '/unknown/route');

      expect(res.status).toBe(404);
      expect((res.body as any).error).toBe('Not found');
    });
  });
});

describe('APIServer with authentication', () => {
  let server: APIServer;
  let agent: SecurityAuditAgent;
  let database: SQLiteDatabase;
  let tempDir: string;
  const testPort = 19080 + Math.floor(Math.random() * 1000);
  const apiKey = 'test-api-key-12345';

  beforeAll(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'api-auth-test-'));

    agent = new SecurityAuditAgent({ name: 'TestAgent' });
    database = new SQLiteDatabase({
      type: 'sqlite',
      connectionString: path.join(tempDir, 'test.db'),
      retentionDays: 30,
      encryptAtRest: false
    });
    await database.initialize();

    server = new APIServer(agent, database, {
      port: testPort,
      host: '127.0.0.1',
      apiKey
    });

    await server.start();
  });

  afterAll(async () => {
    await server.stop();
    await database.close();
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  const request = (
    method: string,
    path: string,
    headers?: Record<string, string>
  ): Promise<{ status: number; body: unknown }> => {
    return new Promise((resolve, reject) => {
      const url = new URL(path, `http://127.0.0.1:${testPort}`);
      const req = http.request({
        hostname: url.hostname,
        port: url.port,
        path: url.pathname,
        method,
        headers
      }, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          resolve({
            status: res.statusCode || 0,
            body: data ? JSON.parse(data) : null
          });
        });
      });
      req.on('error', reject);
      req.end();
    });
  };

  it('should reject requests without API key', async () => {
    const res = await request('GET', '/health');

    expect(res.status).toBe(401);
    expect((res.body as any).error).toBe('Unauthorized');
  });

  it('should reject requests with invalid API key', async () => {
    const res = await request('GET', '/health', { 'X-API-Key': 'wrong-key' });

    expect(res.status).toBe(401);
  });

  it('should accept requests with valid API key in header', async () => {
    const res = await request('GET', '/health', { 'X-API-Key': apiKey });

    expect(res.status).toBe(200);
  });

  it('should accept requests with valid API key in query', async () => {
    const res = await request('GET', `/health?api_key=${apiKey}`);

    expect(res.status).toBe(200);
  });
});
