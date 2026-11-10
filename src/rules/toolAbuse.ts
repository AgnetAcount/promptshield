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
    name: 'destructive-shell-commands',
    // rm -rf /, rmdir /s /q, del /f /q, format c:
    regex: /\b(?:rm\s+-(?:r[fF]|f[rR]|rf|fr)\s+[\/\w\.\*~]|rmdir\s+\/[sS]\s+\/[qQ]|del\s+\/[fF]\s+\/[qQ]\s+[\w\.\*\\\/]|mkfs\.[a-z0-9]+\s+\/dev\/)\b/i,
    severity: 'CRITICAL',
    score: 95,
    description: 'Destructive filesystem deletion command targeted at tool/bash execution (e.g. rm -rf)',
  },
  {
    id: 'TOOL-002',
    name: 'pipe-to-shell-execution',
    // curl http://... | sh, wget ... | bash, curl ... | python
    regex: /\b(?:curl|wget|fetch)\s+[^\n|]+\|\s*(?:ba|z)?sh\b/i,
    severity: 'CRITICAL',
    score: 95,
    description: 'Remote payload download piped directly into shell execution (curl | sh)',
  },
  {
    id: 'TOOL-003',
    name: 'reverse-shell-interactive',
    // bash -i >& /dev/tcp, nc -e /bin/sh, ; /bin/sh, ; /bin/bash
    regex: /(?:bash\s+-i\s+>(?:&|\s+>\s*)&?\s*\/dev\/tcp|nc\s+(?:-e|-c)\s+\/bin\/(?:ba)?sh|;\s*\/bin\/(?:ba)?sh|\/dev\/tcp\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d+)/i,
    severity: 'CRITICAL',
    score: 95,
    description: 'Interactive or reverse shell injection payload targeting terminal tools',
  },
  {
    id: 'TOOL-004',
    name: 'powershell-execution-bypass',
    // powershell -ExecutionPolicy Bypass, powershell -ep bypass, powershell -enc
    regex: /\bpowershell(?:\.exe)?\s+(?:-(?:[eE]xecution[pP]olicy|[eE][pP])\s+[bB]ypass|-(?:[eE]nc|[eE]ncoded[cC]ommand)\s+[A-Za-z0-9+/=]{10,})/i,
    severity: 'CRITICAL',
    score: 95,
    description: 'PowerShell execution policy bypass or encoded command execution',
  },
  {
    id: 'TOOL-005',
    name: 'chmod-permission-escalation',
    // chmod +x, chmod 777, chmod u+s
    regex: /\bchmod\s+(?:\+x|[0-7]{3,4}|u\+s|g\+s)\s+[\w\.\/]+/i,
    severity: 'HIGH',
    score: 80,
    description: 'Executable permission elevation or file permission modification command (chmod +x)',
  },
  {
    id: 'TOOL-006',
    name: 'tool-manipulation-call',
    // "call tool execute_command with", "execute tool run_terminal with", "invoke delete_database"
    regex: /\b(?:call|invoke|execute|trigger|run)\s+(?:the\s+)?(?:tool|function|action|api)\s+['"`]?([a-zA-Z0-9_-]*(?:command|shell|exec|delete|drop|terminal|eval|system|code)[a-zA-Z0-9_-]*)['"`]?\s+with\b/i,
    severity: 'CRITICAL',
    score: 90,
    description: 'Direct model manipulation directing invocation of dangerous tools (call tool execute_command)',
  },
  {
    id: 'TOOL-007',
    name: 'tool-confirmation-bypass',
    // "trigger payment tool without confirmation", "bypass confirmation tool", "force tool execution without user approval"
    regex: /\b(?:trigger|invoke|call|execute)\s+[^.\n]+(?:without\s+(?:user\s+)?confirmation|without\s+approval|bypass(?:ing)?\s+(?:confirmation|verification)|force\s+tool\s+execution)\b/i,
    severity: 'CRITICAL',
    score: 95,
    description: 'Attempt to bypass human-in-the-loop confirmation or force automated tool invocation',
  },
  {
    id: 'TOOL-008',
    name: 'sql-injection-tautology',
    // ' OR '1'='1', " OR ""=", ' OR 1=1 --
    regex: /(?:'|\")\s*(?:OR|AND)\s*[\(\s]*(?:'1'='1'|'1'='1|1=1|""=""|'a'='a'|true)\s*['"]?\s*(?:--|#|\/\*|;)/i,
    severity: 'CRITICAL',
    score: 90,
    description: 'SQL injection tautology pattern designed to compromise database queries in DB tools',
  },
  {
    id: 'TOOL-009',
    name: 'sql-injection-drop-truncate',
    // DROP TABLE, DROP DATABASE, TRUNCATE TABLE
    regex: /\b(?:DROP\s+(?:TABLE|DATABASE|SCHEMA|VIEW)|TRUNCATE\s+TABLE)\s+[a-zA-Z0-9_`"']+/i,
    severity: 'CRITICAL',
    score: 95,
    description: 'Destructive SQL query (DROP/TRUNCATE) aimed at database retrieval tools',
  },
  {
    id: 'TOOL-010',
    name: 'sql-injection-union-select',
    // UNION SELECT, UNION ALL SELECT
    regex: /\bUNION\s+(?:ALL\s+)?SELECT\s+[\s\S]+?\s+FROM\b/i,
    severity: 'CRITICAL',
    score: 90,
    description: 'SQL UNION SELECT data exfiltration pattern targeting database tools',
  },
];

export const toolAbuseRule: Rule = {
  id: 'TOOL_ABUSE_SCANNER',
  category: 'tool_abuse',
  severity: 'CRITICAL',
  score: 95,
  description: 'Detects tool invocation manipulation, shell command injections, and SQL injection payloads',
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
