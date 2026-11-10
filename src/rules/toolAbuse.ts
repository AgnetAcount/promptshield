import type { Rule, Violation } from '../types.js';

interface ToolAbusePattern {
  id: string;
  name: string;
  regex: RegExp;
  severity: 'HIGH' | 'CRITICAL';
  score: number;
  description: string;
}

const TOOL_ABUSE_PATTERNS: ToolAbusePattern[] = [
  {
    id: 'TOOL-001',
    name: 'direct-destructive-rm',
    // rm -rf, rm -fr, rmdir /s /q, del /f /q
    regex: /\brm\s+-(?:r[fF]|f[rR]|rf|fr)\b|\brmdir\s+\/[sS]\s+\/[qQ]\b|\bdel\s+\/[fF]\s+\/[qQ]\b/i,
    severity: 'CRITICAL',
    score: 95,
    description: 'Destructive filesystem deletion command targeting terminal/tool execution (rm -rf)',
  },
  {
    id: 'TOOL-002',
    name: 'pipe-download-to-shell',
    // curl ... | sh, wget ... | bash
    regex: /\b(?:curl|wget|fetch)\s+[^\n|]+\|\s*(?:ba)?sh\b/i,
    severity: 'CRITICAL',
    score: 95,
    description: 'Remote payload download piped directly into shell execution (curl/wget | sh)',
  },
  {
    id: 'TOOL-003',
    name: 'interactive-or-netcat-shell',
    // bash -i, nc -e, /dev/tcp
    regex: /\bbash\s+-i\b|\bnc\s+(?:-e|-c)\b|\/dev\/tcp\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d+/i,
    severity: 'CRITICAL',
    score: 95,
    description: 'Interactive or netcat reverse shell command payload (bash -i / nc -e)',
  },
  {
    id: 'TOOL-004',
    name: 'semicolon-command-chaining',
    // ;(?:\s*\/|\s*rm|\s*curl|\s*kill)
    regex: /;(?:\s*\/|\s*rm\b|\s*curl\b|\s*kill\b|\s*wget\b)/i,
    severity: 'CRITICAL',
    score: 95,
    description: 'Semicolon command chaining targeting unauthorized shell execution',
  },
  {
    id: 'TOOL-005',
    name: 'powershell-bypass-or-encoded',
    // powershell.*?-[eE]
    regex: /\bpowershell(?:\.exe)?\s+.*?(?:-[eE]xecution[pP]olicy|-[eE][pP]|-[eE]nc(?:oded[cC]ommand)?)\b/i,
    severity: 'CRITICAL',
    score: 95,
    description: 'PowerShell execution policy bypass or encoded command invocation',
  },
  {
    id: 'TOOL-006',
    name: 'chmod-permission-escalation',
    // chmod +x, chmod 777
    regex: /\bchmod\s+(?:\+x|[0-7]{3,4}|u\+s|g\+s)\b/i,
    severity: 'HIGH',
    score: 80,
    description: 'Executable permission elevation command (chmod +x)',
  },
  {
    id: 'TOOL-007',
    name: 'tool-confirmation-bypass-en',
    // /(without|skip|bypass|do not ask for|suppress|auto(matically)? accept)\b.*?\b(confirmation|approval|permission|prompt|asking)/i
    regex: /(?:without|skip|bypass|do\s+not\s+ask\s+for|suppress|auto(?:matically)?\s+accept)\b.*?\b(?:confirmation|approval|permission|prompt|asking)/i,
    severity: 'CRITICAL',
    score: 95,
    description: 'Attempt to bypass human-in-the-loop tool confirmation or suppress authorization prompt',
  },
  {
    id: 'TOOL-008',
    name: 'tool-confirmation-bypass-tr',
    // Turkish: /(onay|izin)\b.*?\b(almadan|sormadan|istemeden|atlayarak)\b.*?\b(çalıştır|uygula|yürüt)/i
    regex: /(?:onay|izin)\b.*?\b(?:almadan|sormadan|istemeden|atlayarak)\b.*?\b(?:çalıştır|uygula|yürüt)/iu,
    severity: 'CRITICAL',
    score: 95,
    description: 'Turkish tool confirmation bypass directive (onay/izin almadan çalıştır/yürüt)',
  },
  {
    id: 'TOOL-009',
    name: 'destructive-tool-execution',
    // /(execute|run|invoke|call)\b.*?\b(command|terminal|bash|shell|script|function|tool)\b.*?\b(delete|drop|wipe|remove|kill|destroy|truncate|format)/i
    regex: /(?:execute|run|invoke|call)\b.*?\b(?:command|terminal|bash|shell|script|function|tool)\b.*?\b(?:delete|drop|wipe|remove|kill|destroy|truncate|format)/i,
    severity: 'CRITICAL',
    score: 95,
    description: 'Destructive tool or terminal execution directive targeting database or files',
  },
  {
    id: 'TOOL-010',
    name: 'tool-manipulation-call',
    // "call tool execute_command with", "execute tool run_terminal with"
    regex: /\b(?:call|invoke|execute|trigger|run)\s+(?:the\s+)?(?:tool|function|action|api)\s+['"`]?([a-zA-Z0-9_-]*(?:command|shell|exec|delete|drop|terminal|eval|system|code)[a-zA-Z0-9_-]*)['"`]?\s+with\b/i,
    severity: 'CRITICAL',
    score: 90,
    description: 'Direct model manipulation directing invocation of dangerous tools (call tool execute_command)',
  },
  {
    id: 'TOOL-011',
    name: 'sql-injection-tool-payload',
    // /(\bOR\b\s+['"]?1['"]?\s*=\s*['"]?1|UNION\s+SELECT|DROP\s+TABLE|ALTER\s+TABLE|DELETE\s+FROM)/i
    regex: /(?:\bOR\b\s+['"]?1['"]?\s*=\s*['"]?1|UNION\s+SELECT|DROP\s+TABLE|ALTER\s+TABLE|DELETE\s+FROM)/i,
    severity: 'CRITICAL',
    score: 95,
    description: 'SQL injection attack pattern (tautology / UNION / DDL) targeting database tool inputs',
  },
];

export const toolAbuseRule: Rule = {
  id: 'TOOL_ABUSE_SCANNER',
  category: 'tool_abuse',
  severity: 'CRITICAL',
  score: 95,
  description: 'Detects terminal command injection, tool confirmation bypass, destructive actions, and SQL injection payloads',
  check(text: string): Violation[] | null {
    const violations: Violation[] = [];
    const maxSampleLength = 80;

    for (const pattern of TOOL_ABUSE_PATTERNS) {
      const match = pattern.regex.exec(text);
      if (match) {
        const matchedText = match[0];
        const sample = matchedText.length > maxSampleLength
          ? matchedText.slice(0, maxSampleLength) + '...'
          : matchedText;

        violations.push({
          ruleId: pattern.id,
          category: 'tool_abuse',
          severity: pattern.severity,
          score: pattern.score,
          description: pattern.description,
          matched: sample,
          index: match.index,
        });
      }
    }

    return violations.length > 0 ? violations : null;
  },
};
