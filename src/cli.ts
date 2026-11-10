import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { scanPrompt } from './scanner.js';
import { sanitizePrompt } from './sanitizer.js';
import type { ScanResult } from './types.js';

const VERSION = '0.1.0';

function printHelp(): void {
  console.log(`
promptshield v${VERSION}
Zero-dependency heuristic prompt injection and AI security scanner

USAGE:
  promptshield scan <prompt> [options]
  promptshield scan -f <filepath> [options]
  promptshield sanitize <prompt> [options]
  promptshield sanitize -f <filepath> [options]
  cat prompt.txt | promptshield scan [options]

COMMANDS:
  scan <prompt>       Scan text for prompt injections, jailbreaks, and leaks
  sanitize <prompt>   Sanitize and defang prompt text

OPTIONS:
  -f, --file <path>   Read prompt from file
  --json              Output results as JSON
  --github-actions    Output annotations for GitHub Actions CI
  --threshold <num>   Risk score threshold to consider unsafe (default: 25)
  -h, --help          Show this help message
  -v, --version       Show version number

EXIT CODES:
  0                   Scan passed (SAFE) or sanitize completed
  1                   Scan detected security violations (UNSAFE) or CLI error
`);
}

async function readStdin(): Promise<string> {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf-8');
    process.stdin.on('data', (chunk) => {
      data += chunk;
    });
    process.stdin.on('end', () => {
      resolve(data.trim());
    });
    // In case stdin is already ended or not piped
    if (process.stdin.isTTY) {
      resolve('');
    }
  });
}

export async function runCli(argv: string[] = process.argv.slice(2)): Promise<void> {
  if (argv.length === 0 || argv.includes('-h') || argv.includes('--help')) {
    printHelp();
    process.exit(0);
  }

  if (argv.includes('-v') || argv.includes('--version')) {
    console.log(`promptshield v${VERSION}`);
    process.exit(0);
  }

  const isJson = argv.includes('--json');
  const isGithubActions = argv.includes('--github-actions');

  let threshold = 25;
  const thresholdIdx = argv.indexOf('--threshold');
  if (thresholdIdx !== -1 && argv[thresholdIdx + 1]) {
    threshold = parseInt(argv[thresholdIdx + 1], 10) || 25;
  }

  // File argument
  let filePath: string | null = null;
  const fileIdx = argv.indexOf('-f') !== -1 ? argv.indexOf('-f') : argv.indexOf('--file');
  if (fileIdx !== -1 && argv[fileIdx + 1]) {
    filePath = argv[fileIdx + 1];
  }

  const command = argv[0];

  // Extract inline prompt text
  let promptText = '';
  if (filePath) {
    try {
      promptText = readFileSync(resolve(process.cwd(), filePath), 'utf-8');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`Error reading file "${filePath}": ${msg}`);
      process.exit(1);
    }
  } else {
    // Non-flag arguments after command
    const nonFlags = argv.slice(1).filter((arg) => !arg.startsWith('-'));
    if (nonFlags.length > 0) {
      promptText = nonFlags.join(' ');
    } else {
      // Read from stdin if piped
      promptText = await readStdin();
    }
  }

  if (!promptText && command !== 'help') {
    console.error('Error: No prompt text or file provided.');
    printHelp();
    process.exit(1);
  }

  if (command === 'sanitize') {
    const sanitized = sanitizePrompt(promptText);
    if (isJson) {
      console.log(JSON.stringify({ original: promptText, sanitized }, null, 2));
    } else {
      console.log(sanitized);
    }
    process.exit(0);
  }

  if (command === 'scan') {
    const result: ScanResult = scanPrompt(promptText, { threshold });

    if (isGithubActions) {
      outputGithubActions(result);
    }

    if (isJson) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      outputHumanReadable(result);
    }

    // Exit code: 0 if safe, 1 if unsafe
    process.exit(result.safe ? 0 : 1);
  }

  console.error(`Unknown command: ${command}`);
  printHelp();
  process.exit(1);
}

function outputHumanReadable(result: ScanResult): void {
  const badge = result.safe ? '[SAFE]' : `[${result.riskLevel}]`;
  console.log(`\n========================================`);
  console.log(`PromptShield Security Scan: ${badge}`);
  console.log(`========================================`);
  console.log(`Status:      ${result.safe ? 'PASSED (Safe)' : 'FAILED (Unsafe)'}`);
  console.log(`Risk Level:  ${result.riskLevel}`);
  console.log(`Risk Score:  ${result.riskScore} / 100`);
  console.log(`Scan Time:   ${result.scanTimeMs} ms`);
  console.log(`Text Length: ${result.textLength} chars`);
  console.log(`Violations:  ${result.violations.length}`);

  if (result.violations.length > 0) {
    console.log(`\nDetected Security Violations:`);
    result.violations.forEach((v, i) => {
      console.log(`  ${i + 1}. [${v.severity}] ${v.ruleId} (${v.category})`);
      console.log(`     Desc:    ${v.description}`);
      console.log(`     Sample:  "${v.matched}"`);
    });
  }
  console.log('');
}

function outputGithubActions(result: ScanResult): void {
  if (result.safe) {
    console.log(`::notice title=PromptShield Scan Passed::Prompt is safe (Score: ${result.riskScore}/100)`);
    return;
  }

  for (const v of result.violations) {
    const level = v.severity === 'CRITICAL' || v.severity === 'HIGH' ? 'error' : 'warning';
    console.log(`::${level} title=PromptShield [${v.ruleId}]::${v.description} | Matched: ${v.matched}`);
  }
}
