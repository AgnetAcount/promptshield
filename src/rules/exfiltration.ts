import type { Rule, Violation } from '../types.js';

interface ExfilPattern {
  id: string;
  name: string;
  regex: RegExp;
  severity: 'MEDIUM' | 'HIGH';
  score: number;
  description: string;
}

const EXFIL_PATTERNS: ExfilPattern[] = [
  {
    id: 'EXFIL-001',
    name: 'markdown-image-remote',
    // Matches markdown image pointing to remote URL: ![leak](https://...)
    regex: /!\[[^\]]*\]\((https?:\/\/[^\s\)]+)\)/i,
    severity: 'HIGH',
    score: 70,
    description: 'Markdown image with remote URL capable of automatic out-of-band data exfiltration',
  },
  {
    id: 'EXFIL-002',
    name: 'url-sensitive-query-param',
    // Matches URLs with sensitive data exfiltration query parameters (?leak=, ?data=, ?secret=, ?token=, etc.)
    regex: /https?:\/\/[^\s\)"'<>]+[?&](?:leak|data|secret|token|key|prompt|sys|context|cookie|exfil|history|session|cred)=/i,
    severity: 'HIGH',
    score: 75,
    description: 'URL containing sensitive exfiltration query parameters',
  },
  {
    id: 'EXFIL-003',
    name: 'html-img-exfiltration',
    // Matches HTML img tag with remote URL: <img src="https://...">
    regex: /<img\b[^>]*?\bsrc=["'](https?:\/\/[^"'\s>]+)["']/i,
    severity: 'HIGH',
    score: 65,
    description: 'HTML image tag with remote source used for blind data transmission',
  },
  {
    id: 'EXFIL-004',
    name: 'exfiltration-instruction',
    // Matches explicit instructions to send or fetch URL with sensitive contents
    regex: /\b(?:send|exfiltrate|transmit|forward|post|fetch|ping)\s+(?:the\s+)?(?:secret|password|conversation|prompt|history|data|context)\s+(?:to|via|into)\s+https?:\/\//i,
    severity: 'HIGH',
    score: 75,
    description: 'Instruction ordering transmission of internal context or secrets to remote server',
  },
];

export const exfiltrationRule: Rule = {
  id: 'EXFILTRATION_SCANNER',
  category: 'exfiltration',
  severity: 'HIGH',
  score: 70,
  description: 'Detects data exfiltration channels including markdown images, tracking links, and external endpoints',
  check(text: string): Violation[] | null {
    const violations: Violation[] = [];
    const maxSampleLength = 80;

    for (const pattern of EXFIL_PATTERNS) {
      const match = pattern.regex.exec(text);
      if (match) {
        const matchedText = match[0];
        const sample = matchedText.length > maxSampleLength
          ? matchedText.slice(0, maxSampleLength) + '...'
          : matchedText;

        violations.push({
          ruleId: pattern.id,
          category: 'exfiltration',
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
