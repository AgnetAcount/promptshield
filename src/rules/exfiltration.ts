import type { Rule, Violation } from '../types.js';

interface ExfilPattern {
  id: string;
  name: string;
  regex: RegExp;
  severity: 'MEDIUM' | 'HIGH' | 'CRITICAL';
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
    score: 75,
    description: 'Markdown image with remote URL capable of automatic out-of-band data exfiltration',
  },
  {
    id: 'EXFIL-002',
    name: 'url-sensitive-query-param',
    // Matches URLs with sensitive data exfiltration query parameters (?leak=, ?data=, ?secret=, ?token=, etc.)
    regex: /https?:\/\/[^\s\)"'<>]+[?&](?:leak|data|secret|token|key|prompt|sys|context|cookie|exfil|history|session|cred)=/i,
    severity: 'HIGH',
    score: 80,
    description: 'URL containing sensitive exfiltration query parameters',
  },
  {
    id: 'EXFIL-003',
    name: 'html-img-exfiltration',
    // Matches HTML img tag with remote URL: <img src="https://...">
    regex: /<img\b[^>]*?\bsrc=["'](https?:\/\/[^"'\s>]+)["']/i,
    severity: 'HIGH',
    score: 70,
    description: 'HTML image tag with remote source used for blind data transmission',
  },
  {
    id: 'EXFIL-004',
    name: 'exfiltration-instruction',
    // Matches explicit instructions to send or fetch URL with sensitive contents
    regex: /\b(?:send|exfiltrate|transmit|forward|post|fetch|ping|upload)\s+(?:the\s+)?(?:secret|password|conversation|prompt|history|data|context|credentials|keys?)\s+(?:to|via|into)\s+https?:\/\//i,
    severity: 'CRITICAL',
    score: 90,
    description: 'Instruction ordering transmission of internal context or secrets to remote server',
  },
  {
    id: 'EXFIL-005',
    name: 'dns-subdomain-tunneling',
    // Subdomain tunneling exfiltration: e.g. send to ${secret}.evil.com or secret.dns.attacker.com
    regex: /\bhttps?:\/\/(?:[a-zA-Z0-9_\-]+\.)?(?:attacker|burpcollaborator|oastify|canarytokens|pipedream|requestbin|ngrok)\b/i,
    severity: 'HIGH',
    score: 85,
    description: 'Out-of-band tracking domain or collaborator service URL detected',
  },
  {
    id: 'EXFIL-006',
    name: 'webhook-exfiltration-target',
    // Webhook exfiltration: discord webhook, slack webhook, generic webhook url
    regex: /https?:\/\/(?:discord(?:app)?\.com\/api\/webhooks|hooks\.slack\.com\/services|webhook\.site)\/[a-zA-Z0-9_\-\/]+/i,
    severity: 'CRITICAL',
    score: 90,
    description: 'Preconfigured webhook URL (Discord/Slack/Webhook.site) used for data exfiltration',
  },
];

export const exfiltrationRule: Rule = {
  id: 'EXFILTRATION_SCANNER',
  category: 'exfiltration',
  severity: 'HIGH',
  score: 75,
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
