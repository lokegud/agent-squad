/**
 * ConfigLoader Tests
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import { ConfigLoader, loadConfig, generateSampleConfig } from '../config/configLoader';

describe('ConfigLoader', () => {
  let tempDir: string;

  beforeAll(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'config-test-'));
  });

  afterAll(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
  });

  describe('loadConfig', () => {
    it('should return default config when no file exists', async () => {
      const loader = new ConfigLoader({
        searchPaths: [tempDir],
        allowEnvOverrides: false
      });

      const { config, source, warnings } = await loader.load();

      expect(source).toBe('default');
      expect(warnings.length).toBeGreaterThan(0);
      expect(config.name).toBe('SecurityAuditAgent');
      expect(config.modelConfig).toBeDefined();
      expect(config.monitoringConfig).toBeDefined();
    });

    it('should load config from YAML file', async () => {
      const yamlContent = `
name: TestAgent
description: Test security agent
modelConfig:
  temperature: 0.5
  maxTokens: 2048
monitoringConfig:
  enabled: false
  intervalSeconds: 120
`;
      const configPath = path.join(tempDir, 'security-audit.yaml');
      await fs.writeFile(configPath, yamlContent);

      const loader = new ConfigLoader({
        searchPaths: [tempDir],
        allowEnvOverrides: false
      });

      const { config, source, filePath } = await loader.load();

      expect(source).toBe('file');
      expect(filePath).toBe(configPath);
      expect(config.name).toBe('TestAgent');
      expect(config.description).toBe('Test security agent');
      expect(config.modelConfig.temperature).toBe(0.5);
      expect(config.modelConfig.maxTokens).toBe(2048);
      expect(config.monitoringConfig.enabled).toBe(false);
      expect(config.monitoringConfig.intervalSeconds).toBe(120);

      await fs.unlink(configPath);
    });

    it('should load config from JSON file', async () => {
      const jsonContent = {
        name: 'JSONAgent',
        modelConfig: {
          modelId: 'custom-model',
          temperature: 0.2
        }
      };
      const configPath = path.join(tempDir, 'security-audit.json');
      await fs.writeFile(configPath, JSON.stringify(jsonContent));

      const loader = new ConfigLoader({
        searchPaths: [tempDir],
        allowEnvOverrides: false
      });

      const { config, source } = await loader.load();

      expect(source).toBe('file');
      expect(config.name).toBe('JSONAgent');
      expect(config.modelConfig.modelId).toBe('custom-model');
      expect(config.modelConfig.temperature).toBe(0.2);

      await fs.unlink(configPath);
    });

    it('should merge file config with defaults', async () => {
      const yamlContent = `
name: PartialAgent
`;
      const configPath = path.join(tempDir, 'config.yaml');
      await fs.writeFile(configPath, yamlContent);

      const loader = new ConfigLoader({
        searchPaths: [tempDir],
        allowEnvOverrides: false
      });

      const { config } = await loader.load();

      // Custom value
      expect(config.name).toBe('PartialAgent');
      // Default values should be preserved
      expect(config.modelConfig).toBeDefined();
      expect(config.modelConfig.streaming).toBe(true);
      expect(config.sanitizationConfig).toBeDefined();
      expect(config.storageConfig).toBeDefined();

      await fs.unlink(configPath);
    });

    it('should load from explicit configPath', async () => {
      const customDir = path.join(tempDir, 'custom');
      await fs.mkdir(customDir, { recursive: true });

      const configPath = path.join(customDir, 'my-config.yaml');
      await fs.writeFile(configPath, 'name: ExplicitPathAgent');

      const loader = new ConfigLoader({
        configPath,
        allowEnvOverrides: false
      });

      const { config, filePath } = await loader.load();

      expect(config.name).toBe('ExplicitPathAgent');
      expect(filePath).toBe(configPath);

      await fs.rm(customDir, { recursive: true });
    });
  });

  describe('environment variable overrides', () => {
    const originalEnv = process.env;

    beforeEach(() => {
      process.env = { ...originalEnv };
    });

    afterAll(() => {
      process.env = originalEnv;
    });

    it('should apply environment variable overrides', async () => {
      process.env.SECURITY_AUDIT_NAME = 'EnvAgent';
      process.env.SECURITY_AUDIT_MODEL_TEMPERATURE = '0.7';
      process.env.SECURITY_AUDIT_MONITORING_ENABLED = 'false';

      const loader = new ConfigLoader({
        searchPaths: [tempDir],
        allowEnvOverrides: true
      });

      const { config } = await loader.load();

      expect(config.name).toBe('EnvAgent');
      expect(config.modelConfig.temperature).toBe(0.7);
      expect(config.monitoringConfig.enabled).toBe(false);
    });

    it('should override file config with env vars', async () => {
      const configPath = path.join(tempDir, 'security-audit.yaml');
      await fs.writeFile(configPath, 'name: FileAgent\nmodelConfig:\n  temperature: 0.3');

      process.env.SECURITY_AUDIT_NAME = 'EnvOverrideAgent';

      const loader = new ConfigLoader({
        searchPaths: [tempDir],
        allowEnvOverrides: true
      });

      const { config } = await loader.load();

      expect(config.name).toBe('EnvOverrideAgent');
      expect(config.modelConfig.temperature).toBe(0.3); // From file

      await fs.unlink(configPath);
    });

    it('should not apply env overrides when disabled', async () => {
      process.env.SECURITY_AUDIT_NAME = 'EnvAgent';

      const loader = new ConfigLoader({
        searchPaths: [tempDir],
        allowEnvOverrides: false
      });

      const { config } = await loader.load();

      expect(config.name).toBe('SecurityAuditAgent'); // Default, not env
    });
  });

  describe('validation', () => {
    it('should warn on invalid temperature', async () => {
      const configPath = path.join(tempDir, 'security-audit.yaml');
      await fs.writeFile(configPath, `
name: TestAgent
modelConfig:
  temperature: 1.5
`);

      const loader = new ConfigLoader({
        searchPaths: [tempDir],
        validate: true
      });

      const { warnings } = await loader.load();

      expect(warnings.some(w => w.includes('temperature'))).toBe(true);

      await fs.unlink(configPath);
    });

    it('should warn when Vertex enabled without projectId', async () => {
      const configPath = path.join(tempDir, 'security-audit.yaml');
      await fs.writeFile(configPath, `
name: TestAgent
vertexConfig:
  enabled: true
  projectId: ''
`);

      const loader = new ConfigLoader({
        searchPaths: [tempDir],
        validate: true
      });

      const { warnings } = await loader.load();

      expect(warnings.some(w => w.includes('projectId'))).toBe(true);

      await fs.unlink(configPath);
    });

    it('should warn on too low monitoring interval', async () => {
      const configPath = path.join(tempDir, 'security-audit.yaml');
      await fs.writeFile(configPath, `
name: TestAgent
monitoringConfig:
  intervalSeconds: 2
`);

      const loader = new ConfigLoader({
        searchPaths: [tempDir],
        validate: true
      });

      const { warnings } = await loader.load();

      expect(warnings.some(w => w.includes('intervalSeconds'))).toBe(true);

      await fs.unlink(configPath);
    });
  });

  describe('save', () => {
    it('should save config to YAML file', async () => {
      const loader = new ConfigLoader();
      const config = {
        name: 'SavedAgent',
        description: 'Test save',
        modelConfig: {
          modelId: 'test-model',
          temperature: 0,
          maxTokens: 4096,
          streaming: true
        },
        localModelConfig: { enabled: false, modelPath: '', modelType: 'ollama' as const, endpoint: '', capabilities: [] },
        vertexConfig: { enabled: false, projectId: '', location: '', modelId: '', useForPatternAnalysis: false, useForAnomalyDetection: false },
        scanConfigs: [],
        monitoringConfig: { enabled: true, intervalSeconds: 60, alertThresholds: [], notificationChannels: [] },
        sanitizationConfig: { enabled: true, patterns: [], preserveFormat: true, hashSensitiveValues: false },
        storageConfig: { type: 'memory' as const, retentionDays: 30, encryptAtRest: false }
      };

      const savePath = path.join(tempDir, 'saved-config.yaml');
      await loader.save(config, savePath);

      const content = await fs.readFile(savePath, 'utf-8');
      expect(content).toContain('name: SavedAgent');
      expect(content).toContain('description: Test save');

      await fs.unlink(savePath);
    });

    it('should save config to JSON file', async () => {
      const loader = new ConfigLoader();
      const config = {
        name: 'JSONSavedAgent',
        description: 'Test JSON save',
        modelConfig: { modelId: 'test', temperature: 0, maxTokens: 1000, streaming: false },
        localModelConfig: { enabled: false, modelPath: '', modelType: 'ollama' as const, endpoint: '', capabilities: [] },
        vertexConfig: { enabled: false, projectId: '', location: '', modelId: '', useForPatternAnalysis: false, useForAnomalyDetection: false },
        scanConfigs: [],
        monitoringConfig: { enabled: false, intervalSeconds: 60, alertThresholds: [], notificationChannels: [] },
        sanitizationConfig: { enabled: true, patterns: [], preserveFormat: true, hashSensitiveValues: false },
        storageConfig: { type: 'memory' as const, retentionDays: 30, encryptAtRest: false }
      };

      const savePath = path.join(tempDir, 'saved-config.json');
      await loader.save(config, savePath);

      const content = await fs.readFile(savePath, 'utf-8');
      const parsed = JSON.parse(content);
      expect(parsed.name).toBe('JSONSavedAgent');

      await fs.unlink(savePath);
    });
  });

  describe('generateSampleConfig', () => {
    it('should generate valid YAML sample config', () => {
      const sample = generateSampleConfig();

      expect(sample).toContain('# Security Audit Agent Configuration');
      expect(sample).toContain('name:');
      expect(sample).toContain('modelConfig:');
      expect(sample).toContain('monitoringConfig:');
      expect(sample).toContain('storageConfig:');
    });
  });
});
