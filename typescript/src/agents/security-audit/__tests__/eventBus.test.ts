/**
 * Event Bus Tests
 */

import {
  AgentEventBus,
  SourceLogger,
  EventSeverity,
  EventCategory,
  AgentEvent
} from '../utils/eventBus';

describe('AgentEventBus', () => {
  let bus: AgentEventBus;

  beforeEach(() => {
    bus = new AgentEventBus();
  });

  describe('emit', () => {
    it('should emit events', () => {
      const events: AgentEvent[] = [];
      bus.subscribe((event) => events.push(event));

      bus.emit({
        severity: EventSeverity.INFO,
        category: EventCategory.SCAN,
        action: 'started',
        message: 'Test scan started',
        source: 'TestScanner'
      });

      expect(events.length).toBe(1);
      expect(events[0].message).toBe('Test scan started');
    });

    it('should assign event ID and timestamp', () => {
      let capturedEvent: AgentEvent | null = null;
      bus.subscribe((event) => { capturedEvent = event; });

      bus.emit({
        severity: EventSeverity.INFO,
        category: EventCategory.SCAN,
        action: 'test',
        message: 'Test',
        source: 'Test'
      });

      expect(capturedEvent).not.toBeNull();
      expect(capturedEvent!.id).toBeDefined();
      expect(capturedEvent!.timestamp).toBeInstanceOf(Date);
    });
  });

  describe('subscribe', () => {
    it('should support multiple subscribers', () => {
      const events1: AgentEvent[] = [];
      const events2: AgentEvent[] = [];

      bus.subscribe((event) => events1.push(event));
      bus.subscribe((event) => events2.push(event));

      bus.emit({
        severity: EventSeverity.INFO,
        category: EventCategory.SCAN,
        action: 'test',
        message: 'Test',
        source: 'Test'
      });

      expect(events1.length).toBe(1);
      expect(events2.length).toBe(1);
    });

    it('should return unsubscribe function', () => {
      const events: AgentEvent[] = [];
      const unsubscribe = bus.subscribe((event) => events.push(event));

      bus.emit({ severity: EventSeverity.INFO, category: EventCategory.SCAN, action: 'test1', message: 'Test1', source: 'Test' });
      unsubscribe();
      bus.emit({ severity: EventSeverity.INFO, category: EventCategory.SCAN, action: 'test2', message: 'Test2', source: 'Test' });

      expect(events.length).toBe(1);
      expect(events[0].action).toBe('test1');
    });

    it('should filter by severity', () => {
      const events: AgentEvent[] = [];
      bus.subscribe((event) => events.push(event), {
        severity: [EventSeverity.ERROR, EventSeverity.CRITICAL]
      });

      bus.emit({ severity: EventSeverity.INFO, category: EventCategory.SCAN, action: 'info', message: 'Info', source: 'Test' });
      bus.emit({ severity: EventSeverity.ERROR, category: EventCategory.SCAN, action: 'error', message: 'Error', source: 'Test' });
      bus.emit({ severity: EventSeverity.CRITICAL, category: EventCategory.SCAN, action: 'critical', message: 'Critical', source: 'Test' });

      expect(events.length).toBe(2);
      expect(events.map(e => e.severity)).toEqual([EventSeverity.ERROR, EventSeverity.CRITICAL]);
    });

    it('should filter by category', () => {
      const events: AgentEvent[] = [];
      bus.subscribe((event) => events.push(event), {
        category: [EventCategory.SECURITY]
      });

      bus.emit({ severity: EventSeverity.INFO, category: EventCategory.SCAN, action: 'scan', message: 'Scan', source: 'Test' });
      bus.emit({ severity: EventSeverity.INFO, category: EventCategory.SECURITY, action: 'security', message: 'Security', source: 'Test' });

      expect(events.length).toBe(1);
      expect(events[0].category).toBe(EventCategory.SECURITY);
    });

    it('should filter by source', () => {
      const events: AgentEvent[] = [];
      bus.subscribe((event) => events.push(event), {
        source: ['Scanner1']
      });

      bus.emit({ severity: EventSeverity.INFO, category: EventCategory.SCAN, action: 'test', message: 'From Scanner1', source: 'Scanner1' });
      bus.emit({ severity: EventSeverity.INFO, category: EventCategory.SCAN, action: 'test', message: 'From Scanner2', source: 'Scanner2' });

      expect(events.length).toBe(1);
      expect(events[0].source).toBe('Scanner1');
    });

    it('should combine filters with AND logic', () => {
      const events: AgentEvent[] = [];
      bus.subscribe((event) => events.push(event), {
        severity: [EventSeverity.ERROR],
        category: [EventCategory.SECURITY]
      });

      bus.emit({ severity: EventSeverity.ERROR, category: EventCategory.SCAN, action: 'test', message: 'Wrong category', source: 'Test' });
      bus.emit({ severity: EventSeverity.INFO, category: EventCategory.SECURITY, action: 'test', message: 'Wrong severity', source: 'Test' });
      bus.emit({ severity: EventSeverity.ERROR, category: EventCategory.SECURITY, action: 'test', message: 'Match', source: 'Test' });

      expect(events.length).toBe(1);
      expect(events[0].message).toBe('Match');
    });
  });

  describe('history', () => {
    it('should keep event history', () => {
      bus.emit({ severity: EventSeverity.INFO, category: EventCategory.SCAN, action: 'test1', message: 'Test1', source: 'Test' });
      bus.emit({ severity: EventSeverity.INFO, category: EventCategory.SCAN, action: 'test2', message: 'Test2', source: 'Test' });

      const history = bus.getHistory();
      expect(history.length).toBe(2);
    });

    it('should limit history size', () => {
      const smallBus = new AgentEventBus(5);

      for (let i = 0; i < 10; i++) {
        smallBus.emit({ severity: EventSeverity.INFO, category: EventCategory.SCAN, action: `test${i}`, message: `Test${i}`, source: 'Test' });
      }

      const history = smallBus.getHistory();
      expect(history.length).toBe(5);
      expect(history[0].action).toBe('test5'); // Oldest kept
    });

    it('should filter history', () => {
      bus.emit({ severity: EventSeverity.INFO, category: EventCategory.SCAN, action: 'info', message: 'Info', source: 'Test' });
      bus.emit({ severity: EventSeverity.ERROR, category: EventCategory.SCAN, action: 'error', message: 'Error', source: 'Test' });

      const filtered = bus.getHistory({ severity: [EventSeverity.ERROR] });
      expect(filtered.length).toBe(1);
      expect(filtered[0].severity).toBe(EventSeverity.ERROR);
    });

    it('should clear history', () => {
      bus.emit({ severity: EventSeverity.INFO, category: EventCategory.SCAN, action: 'test', message: 'Test', source: 'Test' });
      bus.clearHistory();

      const history = bus.getHistory();
      expect(history.length).toBe(0);
    });
  });
});

describe('SourceLogger', () => {
  let bus: AgentEventBus;
  let logger: SourceLogger;

  beforeEach(() => {
    bus = new AgentEventBus();
    logger = bus.createLogger('TestComponent');
  });

  it('should create logger with source', () => {
    const events: AgentEvent[] = [];
    bus.subscribe((e) => events.push(e));

    logger.info('test', 'action', 'Test message');

    expect(events.length).toBe(1);
    expect(events[0].source).toBe('TestComponent');
  });

  describe('severity methods', () => {
    let events: AgentEvent[];

    beforeEach(() => {
      events = [];
      bus.subscribe((e) => events.push(e));
    });

    it('should log debug', () => {
      logger.debug('test', 'action', 'Debug message');
      expect(events[0].severity).toBe(EventSeverity.DEBUG);
    });

    it('should log info', () => {
      logger.info('test', 'action', 'Info message');
      expect(events[0].severity).toBe(EventSeverity.INFO);
    });

    it('should log warning', () => {
      logger.warning('test', 'action', 'Warning message');
      expect(events[0].severity).toBe(EventSeverity.WARNING);
    });

    it('should log error', () => {
      logger.error('test', 'action', 'Error message');
      expect(events[0].severity).toBe(EventSeverity.ERROR);
    });

    it('should log critical', () => {
      logger.critical('test', 'action', 'Critical message');
      expect(events[0].severity).toBe(EventSeverity.CRITICAL);
    });
  });

  it('should include data in events', () => {
    const events: AgentEvent[] = [];
    bus.subscribe((e) => events.push(e));

    logger.info('test', 'action', 'Test with data', { key: 'value', count: 42 });

    expect(events[0].data).toEqual({ key: 'value', count: 42 });
  });

  it('should include error in events', () => {
    const events: AgentEvent[] = [];
    bus.subscribe((e) => events.push(e));

    const error = new Error('Test error');
    logger.error('test', 'action', 'Error occurred', {}, error);

    expect(events[0].error).toBe(error);
  });

  it('should map category from string', () => {
    const events: AgentEvent[] = [];
    bus.subscribe((e) => events.push(e));

    logger.info('security', 'alert', 'Security alert');
    logger.info('network', 'scan', 'Network scan');
    logger.info('storage', 'save', 'Storage operation');

    expect(events[0].category).toBe(EventCategory.SECURITY);
    expect(events[1].category).toBe(EventCategory.NETWORK);
    expect(events[2].category).toBe(EventCategory.STORAGE);
  });
});
