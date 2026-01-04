/**
 * AI Security Audit Agent - Type Definitions
 * Comprehensive types for security auditing, monitoring, and analysis
 */

// ============================================================================
// Core Enums
// ============================================================================

export enum SeverityLevel {
  CRITICAL = 'critical',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low',
  INFO = 'info'
}

export enum AuditStatus {
  PENDING = 'pending',
  RUNNING = 'running',
  COMPLETED = 'completed',
  FAILED = 'failed',
  REQUIRES_REVIEW = 'requires_review'
}

export enum ScanType {
  CONFIG_AUDIT = 'config_audit',
  NETWORK_MAPPING = 'network_mapping',
  CONTAINER_SECURITY = 'container_security',
  AUTH_REVIEW = 'auth_review',
  LOG_ANALYSIS = 'log_analysis',
  FULL_AUDIT = 'full_audit'
}

// ============================================================================
// Finding Types
// ============================================================================

export interface SecurityFinding {
  id: string;
  type: string;
  severity: SeverityLevel;
  title: string;
  description: string;
  location: string;
  evidence: string[];
  remediation: string;
  cweId?: string;
  cvssScore?: number;
  detectedAt: Date;
  status: 'open' | 'acknowledged' | 'mitigated' | 'false_positive';
}

export interface ConfigFinding extends SecurityFinding {
  configType: 'credentials' | 'ports' | 'auth' | 'permissions' | 'encryption';
  serviceName: string;
  configPath: string;
  currentValue: string;
  recommendedValue: string;
}

export interface NetworkFinding extends SecurityFinding {
  sourceHost: string;
  destinationHost?: string;
  port: number;
  protocol: string;
  exposureType: 'internal' | 'external' | 'public';
  serviceIdentified?: string;
}

export interface ContainerFinding extends SecurityFinding {
  containerId: string;
  containerName: string;
  imageName: string;
  imageTag: string;
  riskCategory: 'privileged' | 'volumes' | 'network' | 'capabilities' | 'secrets' | 'image';
}

export interface AuthFinding extends SecurityFinding {
  authType: 'shared_credentials' | 'weak_password' | 'missing_mfa' | 'excessive_permissions' | 'stale_credentials';
  affectedUsers?: string[];
  affectedServices?: string[];
  isolationLevel: 'none' | 'partial' | 'full';
}

export interface LogFinding extends SecurityFinding {
  logSource: string;
  patternType: 'brute_force' | 'data_exfil' | 'privilege_escalation' | 'lateral_movement' | 'unusual_access' | 'imsi_related';
  timeRange: { start: Date; end: Date };
  eventCount: number;
  affectedResources: string[];
  iocIndicators?: string[];
}

// ============================================================================
// Scan Configuration
// ============================================================================

export interface ScanConfig {
  scanType: ScanType;
  targets: string[];
  excludePatterns?: string[];
  sensitivePatterns?: string[];
  maxDepth?: number;
  timeout?: number;
  parallelism?: number;
  enableLocalProcessing?: boolean;
  enableCloudAnalysis?: boolean;
  sanitizeBeforeCloud?: boolean;
}

export interface ConfigAuditConfig extends ScanConfig {
  scanType: ScanType.CONFIG_AUDIT;
  checkDefaultCredentials: boolean;
  checkExposedPorts: boolean;
  checkWeakAuth: boolean;
  credentialPatterns?: RegExp[];
  knownDefaultCredentials?: DefaultCredential[];
}

export interface NetworkMappingConfig extends ScanConfig {
  scanType: ScanType.NETWORK_MAPPING;
  discoverHosts: boolean;
  scanPorts: boolean;
  portRange?: { start: number; end: number };
  detectServices: boolean;
  mapTopology: boolean;
}

export interface ContainerSecurityConfig extends ScanConfig {
  scanType: ScanType.CONTAINER_SECURITY;
  checkPrivileged: boolean;
  checkVolumes: boolean;
  checkNetwork: boolean;
  checkCapabilities: boolean;
  checkSecrets: boolean;
  checkImages: boolean;
  registryCredentials?: { registry: string; username: string; password: string }[];
}

export interface AuthReviewConfig extends ScanConfig {
  scanType: ScanType.AUTH_REVIEW;
  checkSharedCredentials: boolean;
  checkPasswordStrength: boolean;
  checkMFA: boolean;
  checkPermissions: boolean;
  checkCredentialAge: boolean;
  maxCredentialAgeDays?: number;
}

export interface LogAnalysisConfig extends ScanConfig {
  scanType: ScanType.LOG_ANALYSIS;
  logSources: string[];
  timeRange: { start: Date; end: Date };
  patterns: LogPattern[];
  enableAnomalyDetection: boolean;
  baselineWindow?: number;
  imsiPatterns?: RegExp[];
}

// ============================================================================
// Supporting Types
// ============================================================================

export interface DefaultCredential {
  service: string;
  username: string;
  password: string;
  port?: number;
}

export interface LogPattern {
  name: string;
  pattern: RegExp;
  severity: SeverityLevel;
  description: string;
  category: string;
}

export interface NetworkTopology {
  nodes: NetworkNode[];
  edges: NetworkEdge[];
  zones: NetworkZone[];
}

export interface NetworkNode {
  id: string;
  hostname: string;
  ipAddress: string;
  type: 'server' | 'container' | 'service' | 'gateway' | 'database' | 'unknown';
  ports: PortInfo[];
  metadata?: Record<string, unknown>;
}

export interface NetworkEdge {
  source: string;
  target: string;
  port: number;
  protocol: string;
  encrypted: boolean;
  bidirectional: boolean;
}

export interface NetworkZone {
  id: string;
  name: string;
  type: 'public' | 'dmz' | 'private' | 'restricted';
  nodes: string[];
}

export interface PortInfo {
  port: number;
  protocol: 'tcp' | 'udp';
  state: 'open' | 'closed' | 'filtered';
  service?: string;
  version?: string;
  exposed: boolean;
}

export interface ContainerInfo {
  id: string;
  name: string;
  image: string;
  tag: string;
  status: string;
  created: Date;
  privileged: boolean;
  capabilities: string[];
  volumes: VolumeMount[];
  networkMode: string;
  ports: PortMapping[];
  environment: { key: string; value: string; sensitive: boolean }[];
  labels: Record<string, string>;
}

export interface VolumeMount {
  source: string;
  destination: string;
  mode: 'ro' | 'rw';
  type: 'bind' | 'volume' | 'tmpfs';
  sensitive: boolean;
}

export interface PortMapping {
  containerPort: number;
  hostPort: number;
  hostIp: string;
  protocol: string;
}

// ============================================================================
// Audit Results
// ============================================================================

export interface AuditResult {
  auditId: string;
  scanType: ScanType;
  status: AuditStatus;
  startTime: Date;
  endTime?: Date;
  duration?: number;
  findings: SecurityFinding[];
  summary: AuditSummary;
  metadata: Record<string, unknown>;
}

export interface AuditSummary {
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  passedChecks: number;
  failedChecks: number;
  skippedChecks: number;
  riskScore: number;
  recommendations: string[];
}

export interface FullAuditResult {
  auditId: string;
  status: AuditStatus;
  startTime: Date;
  endTime?: Date;
  configAudit?: AuditResult;
  networkMapping?: AuditResult;
  containerSecurity?: AuditResult;
  authReview?: AuditResult;
  logAnalysis?: AuditResult;
  overallSummary: AuditSummary;
  complianceStatus: ComplianceStatus;
}

export interface ComplianceStatus {
  frameworks: ComplianceFramework[];
  overallCompliance: number;
  criticalGaps: string[];
}

export interface ComplianceFramework {
  name: string;
  version: string;
  complianceScore: number;
  passedControls: string[];
  failedControls: string[];
  notApplicable: string[];
}

// ============================================================================
// Monitoring Types
// ============================================================================

export interface MonitoringConfig {
  enabled: boolean;
  intervalSeconds: number;
  alertThresholds: AlertThreshold[];
  notificationChannels: NotificationChannel[];
}

export interface AlertThreshold {
  metric: string;
  operator: 'gt' | 'lt' | 'eq' | 'gte' | 'lte';
  value: number;
  severity: SeverityLevel;
  cooldownSeconds: number;
}

export interface NotificationChannel {
  type: 'email' | 'slack' | 'webhook' | 'pagerduty';
  config: Record<string, string>;
  severityFilter: SeverityLevel[];
}

export interface ChangeEvent {
  id: string;
  timestamp: Date;
  changeType: 'config' | 'network' | 'container' | 'auth' | 'deployment';
  resourceId: string;
  resourceType: string;
  previousState: Record<string, unknown>;
  newState: Record<string, unknown>;
  changedBy?: string;
  validated: boolean;
  validationResult?: ValidationResult;
}

export interface ValidationResult {
  passed: boolean;
  errors: string[];
  warnings: string[];
  securityImpact: SeverityLevel;
}

export interface DependencyMap {
  services: ServiceDependency[];
  lastUpdated: Date;
}

export interface ServiceDependency {
  serviceId: string;
  serviceName: string;
  dependencies: string[];
  dependents: string[];
  criticalityScore: number;
  impactOnFailure: string[];
}

// ============================================================================
// Data Sanitization Types
// ============================================================================

export interface SanitizationConfig {
  enabled: boolean;
  patterns: SanitizationPattern[];
  preserveFormat: boolean;
  hashSensitiveValues: boolean;
}

export interface SanitizationPattern {
  name: string;
  pattern: RegExp;
  replacement: string | ((match: string) => string);
  category: 'pii' | 'credentials' | 'network' | 'internal' | 'custom';
}

export interface SanitizedData<T> {
  data: T;
  sanitizationLog: SanitizationLogEntry[];
  originalHash: string;
}

export interface SanitizationLogEntry {
  field: string;
  category: string;
  originalLength: number;
  replaced: boolean;
}

// ============================================================================
// Agent Configuration Types
// ============================================================================

export interface SecurityAuditAgentConfig {
  name: string;
  description: string;
  modelConfig: ModelConfig;
  localModelConfig?: LocalModelConfig;
  vertexConfig?: VertexConfig;
  scanConfigs: ScanConfig[];
  monitoringConfig: MonitoringConfig;
  sanitizationConfig: SanitizationConfig;
  storageConfig: StorageConfig;
}

export interface ModelConfig {
  modelId: string;
  temperature: number;
  maxTokens: number;
  streaming: boolean;
}

export interface LocalModelConfig {
  enabled: boolean;
  modelPath: string;
  modelType: 'ollama' | 'llamacpp' | 'custom';
  endpoint?: string;
  capabilities: ('scan' | 'analyze' | 'classify')[];
}

export interface VertexConfig {
  enabled: boolean;
  projectId: string;
  location: string;
  modelId: string;
  useForPatternAnalysis: boolean;
  useForAnomalyDetection: boolean;
}

export interface StorageConfig {
  type: 'memory' | 'file' | 'database';
  path?: string;
  retentionDays: number;
  encryptAtRest: boolean;
}
