/**
 * Central Event Bus for Agent Activity Logging
 *
 * Provides a unified event system that:
 * - Streams all agent activity to subscribers
 * - Routes noteworthy events to Matrix/other destinations
 * - Maintains event history for debugging
 * - Supports multiple severity levels and filtering
 */

import { EventEmitter } from 'events';

// ============================================================================
// Event Types
// ============================================================================

export type EventSeverity = 'debug' | 'info' | 'notice' | 'warning' | 'error' | 'critical';

export type EventCategory =
  | 'command'      // Command execution events
  | 'security'     // Security findings and alerts
  | 'lint'         // Code linting results
  | 'scan'         // Scanner activity
  | 'network'      // Network operations
  | 'container'    // Container scanning
  | 'auth'         // Auth/credential events
  | 'memory'       // Memory operations
  | 'system'       // System-level events
  | 'matrix'       // Matrix communication
  | 'agent';       // Agent lifecycle events

export interface AgentEvent {
  id: string;
  timestamp: Date;
  severity: EventSeverity;
  category: EventCategory;
  source: string;
  action: string;
  message: string;
  details?: Record<string, unknown>;
  error?: Error | string;
  correlationId?: string;
  sessionId?: string;
}

export interface EventFilter {
  severity?: EventSeverity[];
  category?: EventCategory[];
  source?: string[];
  minSeverity?: EventSeverity;
}

export interface EventSubscriber {
  id: string;
  filter?: EventFilter;
  handler: (event: AgentEvent) => void | Promise<void>;
}

export interface StreamOptions {
  /** Include historical events */
  includeHistory?: boolean;
  /** Max historical events to include */
  historyLimit?: number;
  /** Filter criteria */
  filter?: EventFilter;
  /** Format output as JSON or text */
  format?: 'json' | 'text' | 'compact';
}

// ============================================================================
// Severity Ordering
// ============================================================================

const SEVERITY_ORDER: Record<EventSeverity, number> = {
  debug: 0,
  info: 1,
  notice: 2,
  warning: 3,
  error: 4,
  critical: 5
};

// ============================================================================
// Event Bus Implementation
// ============================================================================

export class AgentEventBus extends EventEmitter {
  private static instance: AgentEventBus;

  private eventHistory: AgentEvent[] = [];
  private maxHistorySize: number = 10000;
  private subscribers: Map<string, EventSubscriber> = new Map();
  private sessionId: string;
  private correlationStack: string[] = [];

  private constructor() {
    super();
    this.sessionId = this.generateId();
    this.setMaxListeners(100);
  }

  /**
   * Get singleton instance
   */
  static getInstance(): AgentEventBus {
    if (!AgentEventBus.instance) {
      AgentEventBus.instance = new AgentEventBus();
    }
    return AgentEventBus.instance;
  }

  /**
   * Create a new event bus (for testing or isolated contexts)
   */
  static create(): AgentEventBus {
    const bus = new AgentEventBus();
    return bus;
  }

  /**
   * Emit an event
   */
  log(
    severity: EventSeverity,
    category: EventCategory,
    source: string,
    action: string,
    message: string,
    details?: Record<string, unknown>,
    error?: Error | string
  ): AgentEvent {
    const event: AgentEvent = {
      id: this.generateId(),
      timestamp: new Date(),
      severity,
      category,
      source,
      action,
      message,
      details,
      error,
      correlationId: this.correlationStack[this.correlationStack.length - 1],
      sessionId: this.sessionId
    };

    // Store in history
    this.eventHistory.push(event);
    if (this.eventHistory.length > this.maxHistorySize) {
      this.eventHistory.shift();
    }

    // Emit to all listeners
    this.emit('event', event);
    this.emit(severity, event);
    this.emit(`${category}:${action}`, event);

    // Notify subscribers
    this.notifySubscribers(event);

    return event;
  }

  // Convenience methods
  debug(category: EventCategory, source: string, action: string, message: string, details?: Record<string, unknown>) {
    return this.log('debug', category, source, action, message, details);
  }

  info(category: EventCategory, source: string, action: string, message: string, details?: Record<string, unknown>) {
    return this.log('info', category, source, action, message, details);
  }

  notice(category: EventCategory, source: string, action: string, message: string, details?: Record<string, unknown>) {
    return this.log('notice', category, source, action, message, details);
  }

  warning(category: EventCategory, source: string, action: string, message: string, details?: Record<string, unknown>) {
    return this.log('warning', category, source, action, message, details);
  }

  error(category: EventCategory, source: string, action: string, message: string, details?: Record<string, unknown>, error?: Error | string) {
    return this.log('error', category, source, action, message, details, error);
  }

  critical(category: EventCategory, source: string, action: string, message: string, details?: Record<string, unknown>, error?: Error | string) {
    return this.log('critical', category, source, action, message, details, error);
  }

  /**
   * Start a correlation context (for grouping related events)
   */
  startCorrelation(label?: string): string {
    const id = label ? `${label}:${this.generateId()}` : this.generateId();
    this.correlationStack.push(id);
    return id;
  }

  /**
   * End current correlation context
   */
  endCorrelation(): void {
    this.correlationStack.pop();
  }

  /**
   * Subscribe to events
   */
  subscribe(
    id: string,
    handler: (event: AgentEvent) => void | Promise<void>,
    filter?: EventFilter
  ): () => void {
    const subscriber: EventSubscriber = { id, handler, filter };
    this.subscribers.set(id, subscriber);

    // Return unsubscribe function
    return () => this.unsubscribe(id);
  }

  /**
   * Unsubscribe from events
   */
  unsubscribe(id: string): void {
    this.subscribers.delete(id);
  }

  /**
   * Get event history
   */
  getHistory(filter?: EventFilter, limit?: number): AgentEvent[] {
    let events = this.eventHistory;

    if (filter) {
      events = events.filter(e => this.matchesFilter(e, filter));
    }

    if (limit) {
      events = events.slice(-limit);
    }

    return events;
  }

  /**
   * Stream events to a callback
   */
  stream(options: StreamOptions, callback: (output: string) => void): () => void {
    const { includeHistory, historyLimit, filter, format } = options;

    // Send historical events if requested
    if (includeHistory) {
      const history = this.getHistory(filter, historyLimit);
      for (const event of history) {
        callback(this.formatEvent(event, format || 'text'));
      }
    }

    // Subscribe to new events
    const streamId = `stream:${this.generateId()}`;
    this.subscribe(streamId, (event) => {
      if (!filter || this.matchesFilter(event, filter)) {
        callback(this.formatEvent(event, format || 'text'));
      }
    });

    // Return stop function
    return () => this.unsubscribe(streamId);
  }

  /**
   * Create a child logger for a specific source
   */
  createLogger(source: string): SourceLogger {
    return new SourceLogger(this, source);
  }

  /**
   * Clear event history
   */
  clearHistory(): void {
    this.eventHistory = [];
  }

  /**
   * Get current session ID
   */
  getSessionId(): string {
    return this.sessionId;
  }

  /**
   * Set max history size
   */
  setMaxHistorySize(size: number): void {
    this.maxHistorySize = size;
    while (this.eventHistory.length > size) {
      this.eventHistory.shift();
    }
  }

  /**
   * Check if event matches filter
   */
  private matchesFilter(event: AgentEvent, filter: EventFilter): boolean {
    if (filter.severity && !filter.severity.includes(event.severity)) {
      return false;
    }

    if (filter.category && !filter.category.includes(event.category)) {
      return false;
    }

    if (filter.source && !filter.source.includes(event.source)) {
      return false;
    }

    if (filter.minSeverity) {
      if (SEVERITY_ORDER[event.severity] < SEVERITY_ORDER[filter.minSeverity]) {
        return false;
      }
    }

    return true;
  }

  /**
   * Notify subscribers of an event
   */
  private async notifySubscribers(event: AgentEvent): Promise<void> {
    for (const subscriber of this.subscribers.values()) {
      if (!subscriber.filter || this.matchesFilter(event, subscriber.filter)) {
        try {
          await subscriber.handler(event);
        } catch (error) {
          // Don't let subscriber errors crash the bus
          console.error(`Subscriber ${subscriber.id} error:`, error);
        }
      }
    }
  }

  /**
   * Format event for output
   */
  private formatEvent(event: AgentEvent, format: 'json' | 'text' | 'compact'): string {
    if (format === 'json') {
      return JSON.stringify(event);
    }

    if (format === 'compact') {
      const ts = event.timestamp.toISOString().slice(11, 23);
      const sev = event.severity.toUpperCase().padEnd(8);
      return `${ts} ${sev} [${event.source}] ${event.action}: ${event.message}`;
    }

    // Full text format
    const ts = event.timestamp.toISOString();
    const sev = event.severity.toUpperCase();
    let output = `[${ts}] ${sev} [${event.category}/${event.source}] ${event.action}\n`;
    output += `  ${event.message}\n`;

    if (event.details) {
      output += `  Details: ${JSON.stringify(event.details)}\n`;
    }

    if (event.error) {
      const errMsg = event.error instanceof Error ? event.error.message : event.error;
      output += `  Error: ${errMsg}\n`;
    }

    return output;
  }

  /**
   * Generate unique ID
   */
  private generateId(): string {
    return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
  }
}

// ============================================================================
// Source-specific Logger
// ============================================================================

export class SourceLogger {
  constructor(
    private bus: AgentEventBus,
    private source: string
  ) {}

  debug(category: EventCategory, action: string, message: string, details?: Record<string, unknown>) {
    return this.bus.debug(category, this.source, action, message, details);
  }

  info(category: EventCategory, action: string, message: string, details?: Record<string, unknown>) {
    return this.bus.info(category, this.source, action, message, details);
  }

  notice(category: EventCategory, action: string, message: string, details?: Record<string, unknown>) {
    return this.bus.notice(category, this.source, action, message, details);
  }

  warning(category: EventCategory, action: string, message: string, details?: Record<string, unknown>) {
    return this.bus.warning(category, this.source, action, message, details);
  }

  error(category: EventCategory, action: string, message: string, details?: Record<string, unknown>, error?: Error | string) {
    return this.bus.error(category, this.source, action, message, details, error);
  }

  critical(category: EventCategory, action: string, message: string, details?: Record<string, unknown>, error?: Error | string) {
    return this.bus.critical(category, this.source, action, message, details, error);
  }

  startCorrelation(label?: string): string {
    return this.bus.startCorrelation(label);
  }

  endCorrelation(): void {
    this.bus.endCorrelation();
  }
}

// ============================================================================
// Console Log Subscriber (for debugging)
// ============================================================================

export function attachConsoleLogger(
  bus: AgentEventBus,
  options?: {
    minSeverity?: EventSeverity;
    format?: 'json' | 'text' | 'compact';
    colorize?: boolean;
  }
): () => void {
  const { minSeverity = 'info', format = 'compact', colorize = true } = options || {};

  const colors: Record<EventSeverity, string> = {
    debug: '\x1b[90m',    // Gray
    info: '\x1b[36m',     // Cyan
    notice: '\x1b[34m',   // Blue
    warning: '\x1b[33m',  // Yellow
    error: '\x1b[31m',    // Red
    critical: '\x1b[35m'  // Magenta
  };
  const reset = '\x1b[0m';

  return bus.subscribe('console-logger', (event) => {
    let output: string;

    if (format === 'compact') {
      const ts = event.timestamp.toISOString().slice(11, 23);
      const sev = event.severity.toUpperCase().padEnd(8);
      output = `${ts} ${sev} [${event.source}] ${event.action}: ${event.message}`;
    } else if (format === 'json') {
      output = JSON.stringify(event);
    } else {
      output = `[${event.timestamp.toISOString()}] ${event.severity.toUpperCase()}\n`;
      output += `  Source: ${event.source}\n`;
      output += `  Action: ${event.action}\n`;
      output += `  Message: ${event.message}\n`;
      if (event.details) {
        output += `  Details: ${JSON.stringify(event.details, null, 2)}\n`;
      }
    }

    if (colorize) {
      const color = colors[event.severity] || '';
      console.log(`${color}${output}${reset}`);
    } else {
      console.log(output);
    }
  }, { minSeverity });
}

// Export singleton accessor
export const eventBus = AgentEventBus.getInstance();

export default AgentEventBus;
