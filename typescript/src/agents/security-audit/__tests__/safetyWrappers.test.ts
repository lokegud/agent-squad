/**
 * Safety Wrappers Tests
 */

import {
  CommandSafetyWrapper,
  CommandRiskAssessment,
  CodeLinter,
  MCPMemory
} from '../utils/safetyWrappers';

describe('CommandSafetyWrapper', () => {
  let wrapper: CommandSafetyWrapper;

  beforeEach(() => {
    wrapper = new CommandSafetyWrapper();
  });

  describe('assessRisk', () => {
    describe('safe commands', () => {
      const safeCommands = [
        'ls -la',
        'pwd',
        'cat /etc/hostname',
        'echo "hello"',
        'grep pattern file.txt',
        'find . -name "*.js"',
        'ps aux',
        'df -h',
        'whoami',
        'date'
      ];

      test.each(safeCommands)('should classify "%s" as safe', (cmd) => {
        const assessment = wrapper.assessRisk(cmd);
        expect(assessment.risk).toBe('safe');
        expect(assessment.requiresVerification).toBe(false);
      });
    });

    describe('dangerous commands requiring verification', () => {
      const dangerousCommands = [
        { cmd: 'rm -rf /tmp/test', reason: 'rm command' },
        { cmd: 'sudo apt update', reason: 'sudo command' },
        { cmd: 'chmod 777 file.txt', reason: 'chmod command' },
        { cmd: 'chown root:root file', reason: 'chown command' },
        { cmd: 'dd if=/dev/zero of=/dev/sda', reason: 'dd command' },
        { cmd: 'mkfs.ext4 /dev/sdb1', reason: 'mkfs command' },
        { cmd: 'iptables -F', reason: 'iptables command' },
        { cmd: 'systemctl stop nginx', reason: 'systemctl command' },
        { cmd: 'git push origin main', reason: 'git push command' },
        { cmd: 'npm publish', reason: 'npm publish command' },
        { cmd: 'docker rm container', reason: 'docker rm command' },
        { cmd: 'kubectl delete pod', reason: 'kubectl delete command' }
      ];

      test.each(dangerousCommands)('should classify "$cmd" as dangerous ($reason)', ({ cmd }) => {
        const assessment = wrapper.assessRisk(cmd);
        expect(assessment.risk).toBe('dangerous');
        expect(assessment.requiresVerification).toBe(true);
        expect(assessment.reasons.length).toBeGreaterThan(0);
      });
    });

    describe('SQL commands', () => {
      const sqlCommands = [
        'DROP DATABASE production',
        'DROP TABLE users',
        'TRUNCATE TABLE logs',
        'DELETE FROM users WHERE 1=1',
        'ALTER TABLE users DROP COLUMN email'
      ];

      test.each(sqlCommands)('should classify "%s" as dangerous', (cmd) => {
        const assessment = wrapper.assessRisk(cmd);
        expect(assessment.risk).toBe('dangerous');
        expect(assessment.requiresVerification).toBe(true);
      });
    });

    describe('alternatives', () => {
      it('should suggest alternatives for rm', () => {
        const assessment = wrapper.assessRisk('rm -rf important_folder');
        expect(assessment.alternatives).toBeDefined();
        expect(assessment.alternatives?.some(a => a.includes('trash') || a.includes('mv'))).toBe(true);
      });

      it('should suggest alternatives for chmod 777', () => {
        const assessment = wrapper.assessRisk('chmod 777 script.sh');
        expect(assessment.alternatives).toBeDefined();
        expect(assessment.alternatives?.some(a => a.includes('chmod'))).toBe(true);
      });
    });
  });

  describe('execute', () => {
    it('should execute safe commands directly', async () => {
      const result = await wrapper.execute('echo "test"');

      expect(result.executed).toBe(true);
      expect(result.output).toContain('test');
    });

    it('should not execute dangerous commands without verification', async () => {
      const result = await wrapper.execute('rm -rf /tmp/nonexistent');

      expect(result.executed).toBe(false);
      expect(result.requiresVerification).toBe(true);
    });

    it('should execute dangerous commands with verification', async () => {
      const verifier = jest.fn().mockResolvedValue(true);
      const wrapperWithVerifier = new CommandSafetyWrapper({
        verifyCallback: verifier
      });

      const result = await wrapperWithVerifier.execute('echo "verified"');

      expect(result.executed).toBe(true);
    });

    it('should not execute if verifier rejects', async () => {
      const verifier = jest.fn().mockResolvedValue(false);
      const wrapperWithVerifier = new CommandSafetyWrapper({
        verifyCallback: verifier
      });

      const result = await wrapperWithVerifier.execute('rm test.txt');

      expect(result.executed).toBe(false);
      expect(verifier).toHaveBeenCalled();
    });

    it('should handle command execution errors', async () => {
      const result = await wrapper.execute('nonexistent_command_xyz');

      expect(result.executed).toBe(true); // Attempted execution
      expect(result.error).toBeDefined();
    });
  });

  describe('configuration', () => {
    it('should allow custom dangerous patterns', () => {
      const customWrapper = new CommandSafetyWrapper({
        additionalDangerousPatterns: [/custom_danger/i]
      });

      const assessment = customWrapper.assessRisk('custom_danger --flag');
      expect(assessment.risk).toBe('dangerous');
    });

    it('should respect dry run mode', async () => {
      const dryRunWrapper = new CommandSafetyWrapper({
        dryRun: true
      });

      const result = await dryRunWrapper.execute('echo "test"');

      expect(result.dryRun).toBe(true);
    });
  });
});

describe('CodeLinter', () => {
  let linter: CodeLinter;

  beforeEach(() => {
    linter = new CodeLinter();
  });

  describe('lint', () => {
    describe('security issues', () => {
      it('should detect eval usage', async () => {
        const code = `
          const userInput = req.body.code;
          eval(userInput);
        `;

        const result = await linter.lint(code, 'javascript');

        expect(result.issues.some(i => i.rule.includes('eval'))).toBe(true);
        expect(result.issues.some(i => i.severity === 'critical' || i.severity === 'high')).toBe(true);
      });

      it('should detect SQL injection patterns', async () => {
        const code = `
          const query = "SELECT * FROM users WHERE id = " + userId;
          db.query(query);
        `;

        const result = await linter.lint(code, 'javascript');

        expect(result.issues.some(i => i.message.toLowerCase().includes('sql'))).toBe(true);
      });

      it('should detect hardcoded secrets', async () => {
        const code = `
          const apiKey = "sk-1234567890abcdef";
          const password = "supersecret123";
        `;

        const result = await linter.lint(code, 'javascript');

        expect(result.issues.some(i =>
          i.message.toLowerCase().includes('secret') ||
          i.message.toLowerCase().includes('credential') ||
          i.message.toLowerCase().includes('hardcoded')
        )).toBe(true);
      });

      it('should detect command injection', async () => {
        const code = `
          const cmd = "ls " + userInput;
          exec(cmd);
        `;

        const result = await linter.lint(code, 'javascript');

        expect(result.issues.some(i =>
          i.message.toLowerCase().includes('command') ||
          i.message.toLowerCase().includes('injection')
        )).toBe(true);
      });
    });

    describe('TypeScript', () => {
      it('should lint TypeScript code', async () => {
        const code = `
          function unsafeEval(code: string): any {
            return eval(code);
          }
        `;

        const result = await linter.lint(code, 'typescript');

        expect(result.issues.length).toBeGreaterThan(0);
      });
    });

    describe('Python', () => {
      it('should detect Python security issues', async () => {
        const code = `
          import pickle
          user_data = pickle.loads(untrusted_input)
          exec(user_code)
        `;

        const result = await linter.lint(code, 'python');

        expect(result.issues.some(i =>
          i.message.toLowerCase().includes('pickle') ||
          i.message.toLowerCase().includes('exec')
        )).toBe(true);
      });
    });

    describe('clean code', () => {
      it('should pass clean code', async () => {
        const code = `
          function add(a: number, b: number): number {
            return a + b;
          }

          const result = add(1, 2);
          console.log(result);
        `;

        const result = await linter.lint(code, 'typescript');

        const criticalIssues = result.issues.filter(i =>
          i.severity === 'critical' || i.severity === 'high'
        );
        expect(criticalIssues.length).toBe(0);
      });
    });
  });

  describe('result summary', () => {
    it('should provide issue counts by severity', async () => {
      const code = `
        eval(input);
        const secret = "password123";
      `;

      const result = await linter.lint(code, 'javascript');

      expect(typeof result.summary.critical).toBe('number');
      expect(typeof result.summary.high).toBe('number');
      expect(typeof result.summary.medium).toBe('number');
      expect(typeof result.summary.low).toBe('number');
    });

    it('should indicate if code passed', async () => {
      const cleanCode = 'const x = 1 + 2;';
      const dirtyCode = 'eval(userInput);';

      const cleanResult = await linter.lint(cleanCode, 'javascript');
      const dirtyResult = await linter.lint(dirtyCode, 'javascript');

      expect(cleanResult.passed).toBe(true);
      expect(dirtyResult.passed).toBe(false);
    });
  });
});

describe('MCPMemory', () => {
  let memory: MCPMemory;

  beforeEach(() => {
    memory = new MCPMemory();
  });

  describe('store and retrieve', () => {
    it('should store and retrieve values', () => {
      memory.store('test-key', { data: 'test value' });

      const retrieved = memory.retrieve('test-key');
      expect(retrieved).toEqual({ data: 'test value' });
    });

    it('should return undefined for non-existent keys', () => {
      const retrieved = memory.retrieve('non-existent');
      expect(retrieved).toBeUndefined();
    });

    it('should overwrite existing values', () => {
      memory.store('key', { version: 1 });
      memory.store('key', { version: 2 });

      const retrieved = memory.retrieve('key');
      expect(retrieved).toEqual({ version: 2 });
    });
  });

  describe('namespaces', () => {
    it('should support namespaced storage', () => {
      memory.store('key', 'value1', 'namespace1');
      memory.store('key', 'value2', 'namespace2');

      expect(memory.retrieve('key', 'namespace1')).toBe('value1');
      expect(memory.retrieve('key', 'namespace2')).toBe('value2');
    });

    it('should list keys in namespace', () => {
      memory.store('key1', 'value1', 'ns');
      memory.store('key2', 'value2', 'ns');

      const keys = memory.listKeys('ns');
      expect(keys).toContain('key1');
      expect(keys).toContain('key2');
    });
  });

  describe('delete', () => {
    it('should delete stored values', () => {
      memory.store('key', 'value');
      memory.delete('key');

      expect(memory.retrieve('key')).toBeUndefined();
    });

    it('should return true if key existed', () => {
      memory.store('key', 'value');
      const deleted = memory.delete('key');

      expect(deleted).toBe(true);
    });

    it('should return false if key did not exist', () => {
      const deleted = memory.delete('non-existent');

      expect(deleted).toBe(false);
    });
  });

  describe('clear', () => {
    it('should clear all values', () => {
      memory.store('key1', 'value1');
      memory.store('key2', 'value2');
      memory.clear();

      expect(memory.retrieve('key1')).toBeUndefined();
      expect(memory.retrieve('key2')).toBeUndefined();
    });

    it('should clear specific namespace', () => {
      memory.store('key', 'value1', 'ns1');
      memory.store('key', 'value2', 'ns2');
      memory.clear('ns1');

      expect(memory.retrieve('key', 'ns1')).toBeUndefined();
      expect(memory.retrieve('key', 'ns2')).toBe('value2');
    });
  });

  describe('TTL', () => {
    it('should expire entries after TTL', async () => {
      const shortTtlMemory = new MCPMemory({ defaultTtl: 100 }); // 100ms
      shortTtlMemory.store('key', 'value');

      expect(shortTtlMemory.retrieve('key')).toBe('value');

      await new Promise(resolve => setTimeout(resolve, 150));

      expect(shortTtlMemory.retrieve('key')).toBeUndefined();
    });

    it('should support per-entry TTL', async () => {
      memory.store('short', 'value', 'default', 50);
      memory.store('long', 'value', 'default', 500);

      await new Promise(resolve => setTimeout(resolve, 100));

      expect(memory.retrieve('short')).toBeUndefined();
      expect(memory.retrieve('long')).toBe('value');
    });
  });

  describe('size limits', () => {
    it('should enforce max entries', () => {
      const smallMemory = new MCPMemory({ maxEntries: 3 });

      smallMemory.store('key1', 'value1');
      smallMemory.store('key2', 'value2');
      smallMemory.store('key3', 'value3');
      smallMemory.store('key4', 'value4');

      // Should have evicted oldest
      expect(smallMemory.retrieve('key1')).toBeUndefined();
      expect(smallMemory.retrieve('key4')).toBe('value4');
    });
  });

  describe('getEntry', () => {
    it('should return full entry with metadata', () => {
      memory.store('key', 'value');
      const entry = memory.getEntry('key');

      expect(entry).toBeDefined();
      expect(entry?.value).toBe('value');
      expect(entry?.createdAt).toBeInstanceOf(Date);
      expect(entry?.accessCount).toBeGreaterThanOrEqual(0);
    });

    it('should track access count', () => {
      memory.store('key', 'value');
      memory.retrieve('key');
      memory.retrieve('key');
      memory.retrieve('key');

      const entry = memory.getEntry('key');
      expect(entry?.accessCount).toBe(3);
    });
  });
});
