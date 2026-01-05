/**
 * AI Security Audit Agent
 * Comprehensive security auditing for infrastructure
 *
 * @module security-audit
 */

// Main agent export
export { SecurityAuditAgent, SecurityAuditAgentOptions } from './securityAuditAgent';

// Type exports
export * from './types';

// Scanner exports
export { ConfigScanner } from './scanners/configScanner';
export { NetworkMapper } from './scanners/networkMapper';
export { ContainerScanner } from './scanners/containerScanner';
export { AuthScanner } from './scanners/authScanner';
export { LogAnalyzer } from './scanners/logAnalyzer';
export { ClamAVScanner, ClamAVConfig, ClamAVScanResult, MalwareFinding, MalwareResearchResult, MalwareOrigin, EmailConfig, MalwareResearchConfig } from './scanners/clamavScanner';
export {
  NetworkTrafficMonitor,
  NetworkMonitorConfig,
  NetworkConnection,
  PhoneHomeAlert,
  DnsQuery
} from './scanners/networkTrafficMonitor';

// Analyzer exports
export { HybridAIProcessor } from './analyzers/hybridAIProcessor';
export { ContinuousMonitor } from './analyzers/continuousMonitor';

// Integration exports
export { MatrixClient, MatrixConfig, MatrixMessage, MatrixRoom } from './integrations/matrixClient';
export { MatrixLogger, MatrixLoggerConfig, createMatrixLogger } from './integrations/matrixLogger';

// Event system exports
export {
  AgentEventBus,
  SourceLogger,
  AgentEvent,
  EventSeverity,
  EventCategory,
  EventFilter,
  EventSubscriber,
  StreamOptions,
  eventBus,
  attachConsoleLogger
} from './utils/eventBus';

// Utility exports
export { DataSanitizer } from './utils/sanitizer';
export {
  CommandSafetyWrapper,
  CommandSafetyConfig,
  CommandRiskAssessment,
  CodeLinter,
  LintConfig,
  LintResult,
  LintIssue,
  MCPMemory,
  MCPConfig,
  MemoryEntry
} from './utils/safetyWrappers';
export { IdentityGenerator, GeneratedIdentity, GeneratorOptions } from './utils/identityGenerator';

// Default export
export { SecurityAuditAgent as default } from './securityAuditAgent';
