/**
 * Matrix Chat Integration
 * Enables the Security Audit Agent to join Matrix chat rooms
 * for real-time alerts, commands, and collaboration
 */

import { EventEmitter } from 'events';
import { exec } from 'child_process';
import { promisify } from 'util';
import * as https from 'https';
import * as http from 'http';

const execAsync = promisify(exec);

export interface MatrixConfig {
  /** Matrix homeserver URL (e.g., https://matrix.org) */
  homeserver: string;
  /** User ID (e.g., @bot:matrix.org) */
  userId?: string;
  /** Access token for authentication */
  accessToken?: string;
  /** Username for login */
  username?: string;
  /** Password for login */
  password?: string;
  /** Device ID */
  deviceId?: string;
  /** Rooms to auto-join */
  autoJoinRooms?: string[];
  /** Enable end-to-end encryption */
  enableEncryption?: boolean;
  /** Command prefix for bot commands */
  commandPrefix?: string;
  /** Allowed users/rooms for commands */
  allowedUsers?: string[];
  allowedRooms?: string[];
}

export interface MatrixMessage {
  roomId: string;
  sender: string;
  body: string;
  formatted?: string;
  timestamp: number;
  eventId: string;
  isCommand: boolean;
  command?: string;
  args?: string[];
}

export interface MatrixRoom {
  roomId: string;
  name?: string;
  topic?: string;
  memberCount: number;
  joined: boolean;
}

type MessageHandler = (message: MatrixMessage) => void | Promise<void>;
type CommandHandler = (command: string, args: string[], message: MatrixMessage) => void | Promise<void>;

export class MatrixClient extends EventEmitter {
  private config: MatrixConfig;
  private accessToken?: string;
  private userId?: string;
  private syncToken?: string;
  private isRunning: boolean = false;
  private syncInterval?: NodeJS.Timeout;
  private messageHandlers: MessageHandler[] = [];
  private commandHandlers: Map<string, CommandHandler> = new Map();
  private joinedRooms: Set<string> = new Set();

  constructor(config: MatrixConfig) {
    super();

    this.config = {
      homeserver: config.homeserver.replace(/\/$/, ''),
      userId: config.userId,
      accessToken: config.accessToken,
      username: config.username,
      password: config.password,
      deviceId: config.deviceId || `SecurityAuditAgent_${Date.now()}`,
      autoJoinRooms: config.autoJoinRooms || [],
      enableEncryption: config.enableEncryption ?? false,
      commandPrefix: config.commandPrefix || '!security',
      allowedUsers: config.allowedUsers,
      allowedRooms: config.allowedRooms
    };

    this.accessToken = config.accessToken;
    this.userId = config.userId;
  }

  /**
   * Initialize and connect to Matrix
   */
  async connect(): Promise<void> {
    // Login if we don't have an access token
    if (!this.accessToken) {
      if (!this.config.username || !this.config.password) {
        throw new Error('Either accessToken or username/password required');
      }
      await this.login();
    }

    // Verify the token works
    await this.whoami();

    // Join configured rooms
    for (const roomId of this.config.autoJoinRooms || []) {
      try {
        await this.joinRoom(roomId);
      } catch (error) {
        this.emit('error', { type: 'join_failed', roomId, error });
      }
    }

    // Start sync loop
    this.startSync();

    this.emit('connected', { userId: this.userId });
  }

  /**
   * Login with username/password
   */
  private async login(): Promise<void> {
    const response = await this.request('POST', '/_matrix/client/v3/login', {
      type: 'm.login.password',
      identifier: {
        type: 'm.id.user',
        user: this.config.username
      },
      password: this.config.password,
      device_id: this.config.deviceId,
      initial_device_display_name: 'Security Audit Agent'
    });

    this.accessToken = response.access_token;
    this.userId = response.user_id;
    this.config.deviceId = response.device_id;
  }

  /**
   * Verify token and get user info
   */
  private async whoami(): Promise<{ userId: string }> {
    const response = await this.request('GET', '/_matrix/client/v3/account/whoami');
    this.userId = response.user_id;
    return { userId: this.userId };
  }

  /**
   * Join a room
   */
  async joinRoom(roomIdOrAlias: string): Promise<string> {
    const response = await this.request(
      'POST',
      `/_matrix/client/v3/join/${encodeURIComponent(roomIdOrAlias)}`
    );

    const roomId = response.room_id;
    this.joinedRooms.add(roomId);
    this.emit('room_joined', { roomId, alias: roomIdOrAlias });

    return roomId;
  }

  /**
   * Leave a room
   */
  async leaveRoom(roomId: string): Promise<void> {
    await this.request('POST', `/_matrix/client/v3/rooms/${encodeURIComponent(roomId)}/leave`);
    this.joinedRooms.delete(roomId);
    this.emit('room_left', { roomId });
  }

  /**
   * Send a text message to a room
   */
  async sendMessage(roomId: string, message: string): Promise<string> {
    const txnId = `${Date.now()}_${Math.random().toString(36).slice(2)}`;

    const response = await this.request(
      'PUT',
      `/_matrix/client/v3/rooms/${encodeURIComponent(roomId)}/send/m.room.message/${txnId}`,
      {
        msgtype: 'm.text',
        body: message
      }
    );

    return response.event_id;
  }

  /**
   * Send a formatted (HTML) message
   */
  async sendFormattedMessage(roomId: string, plain: string, html: string): Promise<string> {
    const txnId = `${Date.now()}_${Math.random().toString(36).slice(2)}`;

    const response = await this.request(
      'PUT',
      `/_matrix/client/v3/rooms/${encodeURIComponent(roomId)}/send/m.room.message/${txnId}`,
      {
        msgtype: 'm.text',
        body: plain,
        format: 'org.matrix.custom.html',
        formatted_body: html
      }
    );

    return response.event_id;
  }

  /**
   * Send a notice (bot message that doesn't trigger notifications)
   */
  async sendNotice(roomId: string, message: string): Promise<string> {
    const txnId = `${Date.now()}_${Math.random().toString(36).slice(2)}`;

    const response = await this.request(
      'PUT',
      `/_matrix/client/v3/rooms/${encodeURIComponent(roomId)}/send/m.room.message/${txnId}`,
      {
        msgtype: 'm.notice',
        body: message
      }
    );

    return response.event_id;
  }

  /**
   * Send a security alert
   */
  async sendAlert(
    roomId: string,
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info',
    title: string,
    details: string
  ): Promise<string> {
    const severityEmoji: Record<string, string> = {
      critical: '🔴',
      high: '🟠',
      medium: '🟡',
      low: '🟢',
      info: 'ℹ️'
    };

    const plain = `${severityEmoji[severity]} [${severity.toUpperCase()}] ${title}\n\n${details}`;

    const html = `
      <p><strong>${severityEmoji[severity]} [${severity.toUpperCase()}] ${title}</strong></p>
      <pre>${this.escapeHtml(details)}</pre>
    `;

    return this.sendFormattedMessage(roomId, plain, html);
  }

  /**
   * Send an audit report
   */
  async sendAuditReport(roomId: string, report: {
    title: string;
    summary: string;
    findings: Array<{ severity: string; title: string; location: string }>;
    riskScore: number;
  }): Promise<string> {
    const plain = `
📋 ${report.title}

Risk Score: ${report.riskScore}/100
${report.summary}

Findings (${report.findings.length}):
${report.findings.slice(0, 10).map(f => `- [${f.severity}] ${f.title}`).join('\n')}
${report.findings.length > 10 ? `\n... and ${report.findings.length - 10} more` : ''}
    `.trim();

    const html = `
      <h3>📋 ${this.escapeHtml(report.title)}</h3>
      <p><strong>Risk Score:</strong> ${report.riskScore}/100</p>
      <p>${this.escapeHtml(report.summary)}</p>
      <h4>Findings (${report.findings.length}):</h4>
      <ul>
        ${report.findings.slice(0, 10).map(f =>
          `<li><strong>[${f.severity}]</strong> ${this.escapeHtml(f.title)}</li>`
        ).join('')}
        ${report.findings.length > 10 ? `<li><em>... and ${report.findings.length - 10} more</em></li>` : ''}
      </ul>
    `;

    return this.sendFormattedMessage(roomId, plain, html);
  }

  /**
   * Register a message handler
   */
  onMessage(handler: MessageHandler): void {
    this.messageHandlers.push(handler);
  }

  /**
   * Register a command handler
   */
  onCommand(command: string, handler: CommandHandler): void {
    this.commandHandlers.set(command.toLowerCase(), handler);
  }

  /**
   * Start the sync loop
   */
  private startSync(): void {
    if (this.isRunning) return;

    this.isRunning = true;
    this.sync();
  }

  /**
   * Stop the sync loop
   */
  stop(): void {
    this.isRunning = false;
    if (this.syncInterval) {
      clearTimeout(this.syncInterval);
      this.syncInterval = undefined;
    }
  }

  /**
   * Sync with the Matrix server
   */
  private async sync(): Promise<void> {
    if (!this.isRunning) return;

    try {
      const params = new URLSearchParams({
        timeout: '30000',
        ...(this.syncToken && { since: this.syncToken })
      });

      const response = await this.request(
        'GET',
        `/_matrix/client/v3/sync?${params.toString()}`
      );

      this.syncToken = response.next_batch;

      // Process room events
      if (response.rooms?.join) {
        for (const [roomId, roomData] of Object.entries(response.rooms.join)) {
          await this.processRoomEvents(roomId, roomData as RoomData);
        }
      }

      // Process invites
      if (response.rooms?.invite) {
        for (const [roomId, inviteData] of Object.entries(response.rooms.invite)) {
          await this.handleInvite(roomId, inviteData as InviteData);
        }
      }

    } catch (error) {
      this.emit('error', { type: 'sync_error', error });
    }

    // Schedule next sync
    if (this.isRunning) {
      this.syncInterval = setTimeout(() => this.sync(), 100);
    }
  }

  /**
   * Process events from a room
   */
  private async processRoomEvents(roomId: string, roomData: RoomData): Promise<void> {
    const events = roomData.timeline?.events || [];

    for (const event of events) {
      if (event.type !== 'm.room.message') continue;
      if (event.sender === this.userId) continue; // Ignore our own messages

      const content = event.content;
      if (content.msgtype !== 'm.text') continue;

      const message: MatrixMessage = {
        roomId,
        sender: event.sender,
        body: content.body,
        formatted: content.formatted_body,
        timestamp: event.origin_server_ts,
        eventId: event.event_id,
        isCommand: content.body.startsWith(this.config.commandPrefix!),
        command: undefined,
        args: undefined
      };

      // Check permissions
      if (!this.isAuthorized(message)) continue;

      // Parse command if applicable
      if (message.isCommand) {
        const parts = content.body.slice(this.config.commandPrefix!.length).trim().split(/\s+/);
        message.command = parts[0]?.toLowerCase();
        message.args = parts.slice(1);

        // Handle command
        const handler = this.commandHandlers.get(message.command || '');
        if (handler) {
          try {
            await handler(message.command!, message.args!, message);
          } catch (error) {
            this.emit('error', { type: 'command_error', command: message.command, error });
          }
        }
      }

      // Call message handlers
      for (const handler of this.messageHandlers) {
        try {
          await handler(message);
        } catch (error) {
          this.emit('error', { type: 'handler_error', error });
        }
      }
    }
  }

  /**
   * Handle room invites
   */
  private async handleInvite(roomId: string, inviteData: InviteData): Promise<void> {
    // Auto-accept invites if room is in allowed list
    if (this.config.allowedRooms?.includes(roomId)) {
      await this.joinRoom(roomId);
    } else {
      this.emit('invite', { roomId, inviteData });
    }
  }

  /**
   * Check if a message sender is authorized
   */
  private isAuthorized(message: MatrixMessage): boolean {
    // Check room restrictions
    if (this.config.allowedRooms && this.config.allowedRooms.length > 0) {
      if (!this.config.allowedRooms.includes(message.roomId)) {
        return false;
      }
    }

    // Check user restrictions for commands
    if (message.isCommand && this.config.allowedUsers && this.config.allowedUsers.length > 0) {
      if (!this.config.allowedUsers.includes(message.sender)) {
        return false;
      }
    }

    return true;
  }

  /**
   * Make a request to the Matrix API
   */
  private request(
    method: string,
    path: string,
    body?: Record<string, unknown>
  ): Promise<Record<string, unknown>> {
    return new Promise((resolve, reject) => {
      const url = new URL(this.config.homeserver + path);
      const isHttps = url.protocol === 'https:';

      const options = {
        hostname: url.hostname,
        port: url.port || (isHttps ? 443 : 80),
        path: url.pathname + url.search,
        method,
        headers: {
          'Content-Type': 'application/json',
          ...(this.accessToken && { Authorization: `Bearer ${this.accessToken}` })
        }
      };

      const req = (isHttps ? https : http).request(options, (res) => {
        let data = '';

        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            const parsed = JSON.parse(data);

            if (res.statusCode && res.statusCode >= 400) {
              reject(new Error(parsed.error || `HTTP ${res.statusCode}`));
            } else {
              resolve(parsed);
            }
          } catch {
            reject(new Error(`Invalid response: ${data}`));
          }
        });
      });

      req.on('error', reject);

      if (body) {
        req.write(JSON.stringify(body));
      }

      req.end();
    });
  }

  /**
   * Escape HTML for safe display
   */
  private escapeHtml(text: string): string {
    return text
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  /**
   * Get list of joined rooms
   */
  async getJoinedRooms(): Promise<string[]> {
    const response = await this.request('GET', '/_matrix/client/v3/joined_rooms');
    return response.joined_rooms as string[];
  }

  /**
   * Get room info
   */
  async getRoomInfo(roomId: string): Promise<MatrixRoom> {
    const [state, members] = await Promise.all([
      this.request('GET', `/_matrix/client/v3/rooms/${encodeURIComponent(roomId)}/state`),
      this.request('GET', `/_matrix/client/v3/rooms/${encodeURIComponent(roomId)}/members`)
    ]);

    const stateEvents = state as Array<{ type: string; content: Record<string, unknown> }>;
    const nameEvent = stateEvents.find(e => e.type === 'm.room.name');
    const topicEvent = stateEvents.find(e => e.type === 'm.room.topic');

    return {
      roomId,
      name: nameEvent?.content?.name as string | undefined,
      topic: topicEvent?.content?.topic as string | undefined,
      memberCount: ((members as { chunk: unknown[] }).chunk || []).length,
      joined: this.joinedRooms.has(roomId)
    };
  }

  /**
   * Disconnect from Matrix
   */
  async disconnect(): Promise<void> {
    this.stop();

    // Optionally logout (invalidates token)
    // await this.request('POST', '/_matrix/client/v3/logout');

    this.emit('disconnected');
  }
}

// Type definitions for Matrix API responses
interface RoomData {
  timeline?: {
    events: Array<{
      type: string;
      sender: string;
      content: Record<string, unknown>;
      origin_server_ts: number;
      event_id: string;
    }>;
  };
}

interface InviteData {
  invite_state?: {
    events: Array<Record<string, unknown>>;
  };
}

export default MatrixClient;
