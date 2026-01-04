#!/usr/bin/env node
/**
 * Security Audit Agent CLI
 * Command-line interface for the AI Security Audit Agent
 */

import { SecurityAuditAgent } from './securityAuditAgent';
import { createInterface } from 'readline';

const VERSION = '1.0.0';

interface CLIOptions {
  interactive: boolean;
  command?: string;
  targets?: string[];
  output?: 'json' | 'text' | 'markdown';
  monitoring?: boolean;
  verbose?: boolean;
}

function parseArgs(args: string[]): CLIOptions {
  const options: CLIOptions = {
    interactive: false,
    output: 'markdown',
    verbose: false
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    switch (arg) {
      case '-i':
      case '--interactive':
        options.interactive = true;
        break;

      case '-c':
      case '--command':
        options.command = args[++i];
        break;

      case '-t':
      case '--target':
        options.targets = options.targets || [];
        options.targets.push(args[++i]);
        break;

      case '-o':
      case '--output':
        options.output = args[++i] as 'json' | 'text' | 'markdown';
        break;

      case '-m':
      case '--monitor':
        options.monitoring = true;
        break;

      case '-v':
      case '--verbose':
        options.verbose = true;
        break;

      case '-h':
      case '--help':
        printHelp();
        process.exit(0);

      case '--version':
        console.log(`Security Audit Agent v${VERSION}`);
        process.exit(0);

      default:
        if (!arg.startsWith('-')) {
          options.command = arg;
        }
    }
  }

  return options;
}

function printHelp(): void {
  console.log(`
Security Audit Agent v${VERSION}
AI-powered infrastructure security auditing

USAGE:
  security-audit [OPTIONS] [COMMAND]

COMMANDS:
  full-audit       Run complete security audit
  config-audit     Scan for configuration issues
  network-map      Map network topology
  container-scan   Check container security
  auth-review      Review authentication setup
  log-analysis     Analyze logs for anomalies
  monitor          Start continuous monitoring

OPTIONS:
  -i, --interactive   Run in interactive mode
  -c, --command       Specify command to run
  -t, --target        Add target path/host to scan
  -o, --output        Output format: json, text, markdown (default)
  -m, --monitor       Enable continuous monitoring
  -v, --verbose       Verbose output
  -h, --help          Show this help
  --version           Show version

EXAMPLES:
  # Run a full security audit
  security-audit full-audit

  # Scan specific targets
  security-audit config-audit -t /path/to/project -t /etc

  # Interactive mode
  security-audit -i

  # JSON output for automation
  security-audit full-audit -o json

  # Start continuous monitoring
  security-audit monitor
`);
}

async function runCommand(agent: SecurityAuditAgent, command: string): Promise<string> {
  const response = await agent.processRequest(
    command,
    'cli-user',
    'cli-session',
    []
  );

  return response.content[0]?.text || 'No response';
}

async function runInteractive(agent: SecurityAuditAgent): Promise<void> {
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: 'security-audit> '
  });

  console.log(`
╔═══════════════════════════════════════════════════════════╗
║           AI Security Audit Agent v${VERSION}                ║
║                                                           ║
║  Type 'help' for available commands                       ║
║  Type 'exit' or Ctrl+C to quit                            ║
╚═══════════════════════════════════════════════════════════╝
`);

  rl.prompt();

  rl.on('line', async (line) => {
    const input = line.trim();

    if (input.toLowerCase() === 'exit' || input.toLowerCase() === 'quit') {
      console.log('Goodbye!');
      rl.close();
      process.exit(0);
    }

    if (input) {
      try {
        const response = await runCommand(agent, input);
        console.log('\n' + response + '\n');
      } catch (error) {
        console.error('Error:', error);
      }
    }

    rl.prompt();
  });

  rl.on('close', () => {
    process.exit(0);
  });
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));

  // Initialize the agent
  const agent = new SecurityAuditAgent({
    name: 'CLISecurityAuditAgent',
    description: 'Command-line security audit agent'
  });

  // Configure targets if specified
  if (options.targets) {
    // Targets would be passed through config
  }

  if (options.interactive) {
    await runInteractive(agent);
  } else if (options.command) {
    try {
      const response = await runCommand(agent, options.command);

      if (options.output === 'json') {
        // Try to parse and re-format as JSON
        console.log(JSON.stringify({ response }, null, 2));
      } else {
        console.log(response);
      }

      if (options.monitoring) {
        console.log('\nContinuous monitoring enabled. Press Ctrl+C to stop.');
        await runCommand(agent, 'start monitoring');

        // Keep the process alive
        await new Promise(() => {});
      }
    } catch (error) {
      console.error('Error:', error);
      process.exit(1);
    }
  } else {
    // Default to help if no command specified
    printHelp();
  }
}

// Run CLI
main().catch(error => {
  console.error('Fatal error:', error);
  process.exit(1);
});
