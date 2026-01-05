/**
 * Matrix Logger Integration
 *
 * Subscribes to the agent event bus and forwards noteworthy events
 * to Matrix chat rooms. Supports:
 * - Configurable severity thresholds
 * - Multiple room routing (alerts vs general logs)
 * - Rate limiting to prevent spam
 * - Batching of rapid events
 * - Formatted alert messages
 */

import { MatrixClient, MatrixConfig } from './matrixClient';
import {
  AgentEventBus,
  AgentEvent,
  EventSeverity,
  EventCategory,
  EventFilter,
  eventBus
} from '../utils/eventBus';

// ============================================================================
// Configuration
// ============================================================================

export interface MatrixLoggerConfig {
  /** Matrix client configuration */
  matrix: Partial<MatrixConfig>;

  /** Room for all log streaming (optional) */
  logRoom?: string;

  /** Room for alerts only (warning+) */
  alertRoom?: string;

  /** Room for critical alerts only */
  criticalRoom?: string;

  /** Minimum severity to log */
  minLogSeverity: EventSeverity;

  /** Minimum severity for alerts */
  minAlertSeverity: EventSeverity;

  /** Enable rate limiting */
  rateLimiting: boolean;

  /** Max events per minute */
  maxEventsPerMinute: number;

  /** Batch rapid events (within ms) */
  batchWindowMs: number;

  /** Categories to always alert regardless of severity */
  alwaysAlertCategories: EventCategory[];

  /** Categories to never log */
  ignoreCategories: EventCategory[];

  /** Format: 'full', 'compact', or 'minimal' */
  format: 'full' | 'compact' | 'minimal';

  /** Include stack traces for errors */
  includeStackTraces: boolean;

  /** Prefix for all messages */
  messagePrefix?: string;

  /** Custom event filter */
  customFilter?: (event: AgentEvent) => boolean;
}

interface EventBatch {
  events: AgentEvent[];
  timer: NodeJS.Timeout | null;
}

interface RateLimitState {
  count: number;
  windowStart: number;
  suppressed: number;
}

// ============================================================================
// Severity to emoji mapping
// ============================================================================

const SEVERITY_EMOJI: Record<EventSeverity, string> = {
  debug: '🔍',
  info: 'ℹ️',
  notice: '📝',
  warning: '⚠️',
  error: '❌',
  critical: '🚨'
};

const SEVERITY_ORDER: Record<EventSeverity, number> = {
  debug: 0,
  info: 1,
  notice: 2,
  warning: 3,
  error: 4,
  critical: 5
};

const CATEGORY_EMOJI: Record<EventCategory, string> = {
  command: '💻',
  security: '🔒',
  lint: '📋',
  scan: '🔎',
  network: '🌐',
  container: '📦',
  auth: '🔑',
  memory: '💾',
  system: '⚙️',
  matrix: '💬',
  agent: '🤖'
};

// ============================================================================
// Matrix Logger Implementation
// ============================================================================

export class MatrixLogger {
  private client: MatrixClient;
  private config: MatrixLoggerConfig;
  private bus: AgentEventBus;
  private connected: boolean = false;

  private logBatch: EventBatch = { events: [], timer: null };
  private alertBatch: EventBatch = { events: [], timer: null };

  private logRateLimit: RateLimitState = { count: 0, windowStart: Date.now(), suppressed: 0 };
  private alertRateLimit: RateLimitState = { count: 0, windowStart: Date.now(), suppressed: 0 };

  private unsubscribe?: () => void;

  constructor(config: Partial<MatrixLoggerConfig>, bus?: AgentEventBus) {
    this.config = {
      matrix: config.matrix || {},
      logRoom: config.logRoom,
      alertRoom: config.alertRoom,
      criticalRoom: config.criticalRoom,
      minLogSeverity: config.minLogSeverity ?? 'info',
      minAlertSeverity: config.minAlertSeverity ?? 'warning',
      rateLimiting: config.rateLimiting ?? true,
      maxEventsPerMinute: config.maxEventsPerMinute ?? 60,
      batchWindowMs: config.batchWindowMs ?? 1000,
      alwaysAlertCategories: config.alwaysAlertCategories ?? ['security', 'command'],
      ignoreCategories: config.ignoreCategories ?? [],
      format: config.format ?? 'compact',
      includeStackTraces: config.includeStackTraces ?? false,
      messagePrefix: config.messagePrefix,
      customFilter: config.customFilter
    };

    this.bus = bus || eventBus;
    this.client = new MatrixClient(this.config.matrix);
  }

  /**
   * Start the Matrix logger
   */
  async start(): Promise<void> {
    // Connect to Matrix
    await this.client.connect();
    this.connected = true;

    // Join configured rooms
    if (this.config.logRoom) {
      await this.client.joinRoom(this.config.logRoom);
    }
    if (this.config.alertRoom) {
      await this.client.joinRoom(this.config.alertRoom);
    }
    if (this.config.criticalRoom) {
      await this.client.joinRoom(this.config.criticalRoom);
    }

    // Subscribe to events
    this.unsubscribe = this.bus.subscribe('matrix-logger', (event) => {
      this.handleEvent(event);
    });

    // Log startup
    this.bus.info('matrix', 'MatrixLogger', 'started', 'Matrix logger connected and listening', {
      logRoom: this.config.logRoom,
      alertRoom: this.config.alertRoom,
      criticalRoom: this.config.criticalRoom
    });
  }

  /**
   * Stop the Matrix logger
   */
  async stop(): Promise<void> {
    // Flush pending batches
    await this.flushBatch(this.logBatch, 'log');
    await this.flushBatch(this.alertBatch, 'alert');

    // Unsubscribe from events
    if (this.unsubscribe) {
      this.unsubscribe();
    }

    // Disconnect from Matrix
    await this.client.disconnect();
    this.connected = false;
  }

  /**
   * Handle an incoming event
   */
  private handleEvent(event: AgentEvent): void {
    if (!this.connected) return;

    // Check if ignored
    if (this.config.ignoreCategories.includes(event.category)) {
      return;
    }

    // Check custom filter
    if (this.config.customFilter && !this.config.customFilter(event)) {
      return;
    }

    // Determine where to send
    const shouldLog = this.shouldLog(event);
    const shouldAlert = this.shouldAlert(event);
    const shouldCritical = event.severity === 'critical';

    // Route to appropriate destinations
    if (shouldLog && this.config.logRoom) {
      this.queueEvent(event, this.logBatch, 'log');
    }

    if (shouldAlert && this.config.alertRoom) {
      this.queueEvent(event, this.alertBatch, 'alert');
    }

    if (shouldCritical && this.config.criticalRoom) {
      // Critical events are sent immediately
      this.sendCriticalAlert(event);
    }
  }

  /**
   * Check if event should be logged
   */
  private shouldLog(event: AgentEvent): boolean {
    return SEVERITY_ORDER[event.severity] >= SEVERITY_ORDER[this.config.minLogSeverity];
  }

  /**
   * Check if event should trigger an alert
   */
  private shouldAlert(event: AgentEvent): boolean {
    // Always alert for configured categories
    if (this.config.alwaysAlertCategories.includes(event.category)) {
      return SEVERITY_ORDER[event.severity] >= SEVERITY_ORDER['notice'];
    }

    return SEVERITY_ORDER[event.severity] >= SEVERITY_ORDER[this.config.minAlertSeverity];
  }

  /**
   * Queue an event for batched sending
   */
  private queueEvent(event: AgentEvent, batch: EventBatch, type: 'log' | 'alert'): void {
    // Check rate limiting
    if (this.config.rateLimiting) {
      const rateLimit = type === 'log' ? this.logRateLimit : this.alertRateLimit;
      const now = Date.now();

      // Reset window if expired
      if (now - rateLimit.windowStart > 60000) {
        rateLimit.count = 0;
        rateLimit.windowStart = now;

        // Report suppressed events
        if (rateLimit.suppressed > 0) {
          this.bus.warning('matrix', 'MatrixLogger', 'rate_limited',
            `Rate limit lifted, ${rateLimit.suppressed} events were suppressed`,
            { suppressed: rateLimit.suppressed, type });
          rateLimit.suppressed = 0;
        }
      }

      // Check if over limit
      if (rateLimit.count >= this.config.maxEventsPerMinute) {
        rateLimit.suppressed++;
        return;
      }

      rateLimit.count++;
    }

    // Add to batch
    batch.events.push(event);

    // Start batch timer if not running
    if (!batch.timer) {
      batch.timer = setTimeout(() => {
        this.flushBatch(batch, type);
      }, this.config.batchWindowMs);
    }
  }

  /**
   * Flush a batch of events
   */
  private async flushBatch(batch: EventBatch, type: 'log' | 'alert'): Promise<void> {
    if (batch.timer) {
      clearTimeout(batch.timer);
      batch.timer = null;
    }

    if (batch.events.length === 0) return;

    const events = [...batch.events];
    batch.events = [];

    const room = type === 'log' ? this.config.logRoom : this.config.alertRoom;
    if (!room) return;

    try {
      if (events.length === 1) {
        // Single event
        await this.sendEvent(room, events[0]);
      } else {
        // Multiple events - send as batch
        await this.sendEventBatch(room, events);
      }
    } catch (error) {
      // Re-emit as error so it's not lost
      this.bus.error('matrix', 'MatrixLogger', 'send_failed',
        `Failed to send ${events.length} events to Matrix`,
        { type, eventCount: events.length },
        error instanceof Error ? error : String(error));
    }
  }

  /**
   * Send a single event to Matrix
   */
  private async sendEvent(room: string, event: AgentEvent): Promise<void> {
    const message = this.formatEvent(event);
    const prefix = this.config.messagePrefix ? `${this.config.messagePrefix} ` : '';
    await this.client.sendMessage(room, `${prefix}${message}`);
  }

  /**
   * Send a batch of events as a single message
   */
  private async sendEventBatch(room: string, events: AgentEvent[]): Promise<void> {
    const prefix = this.config.messagePrefix ? `${this.config.messagePrefix}\n` : '';

    // Group by severity for summary
    const bySeverity = new Map<EventSeverity, number>();
    for (const event of events) {
      bySeverity.set(event.severity, (bySeverity.get(event.severity) || 0) + 1);
    }

    let message = `${prefix}📊 **${events.length} events** (`;
    message += Array.from(bySeverity.entries())
      .map(([sev, count]) => `${count} ${sev}`)
      .join(', ');
    message += ')\n\n';

    // Add each event
    for (const event of events) {
      message += this.formatEvent(event, 'minimal') + '\n';
    }

    await this.client.sendMessage(room, message);
  }

  /**
   * Send a critical alert immediately
   */
  private async sendCriticalAlert(event: AgentEvent): Promise<void> {
    if (!this.config.criticalRoom) return;

    try {
      const emoji = SEVERITY_EMOJI.critical;
      const catEmoji = CATEGORY_EMOJI[event.category] || '';

      let message = `${emoji}${emoji}${emoji} **CRITICAL ALERT** ${emoji}${emoji}${emoji}\n\n`;
      message += `${catEmoji} **${event.category.toUpperCase()}** - ${event.source}\n`;
      message += `**Action:** ${event.action}\n`;
      message += `**Message:** ${event.message}\n`;

      if (event.details) {
        message += `\n**Details:**\n\`\`\`json\n${JSON.stringify(event.details, null, 2)}\n\`\`\`\n`;
      }

      if (event.error) {
        const errMsg = event.error instanceof Error ? event.error.stack || event.error.message : event.error;
        message += `\n**Error:**\n\`\`\`\n${errMsg}\n\`\`\`\n`;
      }

      message += `\n*Time: ${event.timestamp.toISOString()}*`;
      message += `\n*Correlation: ${event.correlationId || 'N/A'}*`;

      await this.client.sendMessage(this.config.criticalRoom, message);
    } catch (error) {
      console.error('Failed to send critical alert:', error);
    }
  }

  /**
   * Format an event for Matrix
   */
  private formatEvent(event: AgentEvent, format?: 'full' | 'compact' | 'minimal'): string {
    const fmt = format || this.config.format;
    const emoji = SEVERITY_EMOJI[event.severity];
    const catEmoji = CATEGORY_EMOJI[event.category] || '';

    if (fmt === 'minimal') {
      const time = event.timestamp.toISOString().slice(11, 19);
      return `${emoji} \`${time}\` [${event.source}] ${event.message}`;
    }

    if (fmt === 'compact') {
      const time = event.timestamp.toISOString().slice(11, 19);
      let msg = `${emoji} ${catEmoji} \`${time}\` **${event.source}** - ${event.action}\n`;
      msg += `> ${event.message}`;

      if (event.details && Object.keys(event.details).length > 0) {
        const detailStr = Object.entries(event.details)
          .map(([k, v]) => `${k}=${JSON.stringify(v)}`)
          .join(' ');
        msg += `\n> \`${detailStr}\``;
      }

      return msg;
    }

    // Full format
    let msg = `${emoji} ${catEmoji} **${event.severity.toUpperCase()}** - ${event.category}/${event.source}\n`;
    msg += `**Action:** ${event.action}\n`;
    msg += `**Message:** ${event.message}\n`;
    msg += `**Time:** ${event.timestamp.toISOString()}\n`;

    if (event.correlationId) {
      msg += `**Correlation:** ${event.correlationId}\n`;
    }

    if (event.details && Object.keys(event.details).length > 0) {
      msg += `**Details:**\n\`\`\`json\n${JSON.stringify(event.details, null, 2)}\n\`\`\`\n`;
    }

    if (event.error) {
      const errMsg = event.error instanceof Error
        ? (this.config.includeStackTraces ? event.error.stack : event.error.message)
        : event.error;
      msg += `**Error:** ${errMsg}\n`;
    }

    return msg;
  }

  /**
   * Send a manual alert
   */
  async sendAlert(
    severity: EventSeverity,
    title: string,
    message: string,
    details?: Record<string, unknown>
  ): Promise<void> {
    const room = severity === 'critical'
      ? (this.config.criticalRoom || this.config.alertRoom)
      : this.config.alertRoom;

    if (!room) return;

    const emoji = SEVERITY_EMOJI[severity];
    let formatted = `${emoji} **${title}**\n${message}`;

    if (details) {
      formatted += `\n\`\`\`json\n${JSON.stringify(details, null, 2)}\n\`\`\``;
    }

    await this.client.sendMessage(room, formatted);
  }

  /**
   * Get the underlying Matrix client
   */
  getClient(): MatrixClient {
    return this.client;
  }

  /**
   * Check if connected
   */
  isConnected(): boolean {
    return this.connected;
  }
}

// ============================================================================
// Factory function
// ============================================================================

/**
 * Create and start a Matrix logger
 */
export async function createMatrixLogger(
  config: Partial<MatrixLoggerConfig>,
  bus?: AgentEventBus
): Promise<MatrixLogger> {
  const logger = new MatrixLogger(config, bus);
  await logger.start();
  return logger;
}

export default MatrixLogger;
