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
    name: 'markdown-image-dynamic-params',
    // Matches markdown images or links with query params or dynamic variables: ![...](http...?...=...)
    regex: /!\[.*?\]\(https?:\/\/[^\s\)]+[\?&=][^\s\)]+\)/i,
    severity: 'HIGH',
    score: 78,
    description: 'Markdown image embedding dynamic parameters or variables for out-of-band data exfiltration',
  },
  {
    id: 'EXFIL-002',
    name: 'markdown-image-remote',
    // Matches any remote markdown image: ![leak](https://...)
    regex: /!\[[^\]]*\]\((https?:\/\/[^\s\)]+)\)/i,
    severity: 'HIGH',
    score: 75,
    description: 'Markdown image with remote URL capable of automatic out-of-band data transmission',
  },
  {
    id: 'EXFIL-003',
    name: 'known-exfiltration-services',
    // Matches known webhook / collaborator / tunneling / testing endpoints
    regex: /\bhttps?:\/\/(?:[a-zA-Z0-9_\-]+\.)?(?:attacker|burpcollaborator|oastify|canarytokens|pipedream|requestbin|ngrok|interact\.sh|webhook\.site|hookshot|beeceptor|postb\.in|discord(?:app)?\.com\/api\/webhooks|hooks\.slack\.com)\b/i,
    severity: 'CRITICAL',
    score: 95,
    description: 'Known out-of-band exfiltration, webhook, or tunneling service endpoint detected',
  },
  {
    id: 'EXFIL-004',
    name: 'raw-ip-url-exfiltration',
    // Matches raw IPv4 address URLs (e.g. http://192.168.1.1, http://10.0.0.1, http://x.x.x.x)
    regex: /\bhttps?:\/\/(?:192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|127\.0\.0\.1|0\.0\.0\.0|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?(?:\/[^\s\)"'<>]*)?/i,
    severity: 'HIGH',
    score: 85,
    description: 'Raw IP address URL detected inside prompt text or link',
  },
  {
    id: 'EXFIL-005',
    name: 'url-data-transmission-instruction',
    // /(append|concatenate|embed|send|transmit|leak|exfiltrate|pass)\b.*?\b(to|into|via)\b.*?\b(https?:\/\/|url|webhook|image|markdown)/i
    regex: /(?:append|concatenate|embed|send|transmit|leak|exfiltrate|pass)\b.*?\b(?:to|into|via)\b.*?\b(?:https?:\/\/|url|webhook|image|markdown)/i,
    severity: 'CRITICAL',
    score: 95,
    description: 'Instruction ordering user or conversation data to be embedded or transmitted via URL or webhook',
  },
  {
    id: 'EXFIL-006',
    name: 'render-markdown-image-with-data',
    // /(render|display|output)\s+(a\s+)?(markdown\s+)?(image|link)\s+with\b/i
    regex: /(?:render|display|output)\s+(?:a\s+)?(?:markdown\s+)?(?:image|link)\s+with\b/i,
    severity: 'HIGH',
    score: 85,
    description: 'Directive instructing the model to render a markdown image or link containing context data',
  },
  {
    id: 'EXFIL-007',
    name: 'turkish-exfiltration-instruction',
    // Turkish: /(verileri|şifreleri|konuşmayı|içeriği)\b.*?\b(url|link|adrese|webhook|siteye)\b.*?\b(gönder|ekle|sızdır|iliştir)/i
    regex: /(?:verileri|şifreleri|konuşmayı|içeriği|bilgileri)\b.*?\b(?:url|link|adrese|webhook|siteye)\b.*?\b(?:gönder|ekle|sızdır|iliştir|aktar)/iu,
    severity: 'CRITICAL',
    score: 95,
    description: 'Turkish data exfiltration directive ordering transmission of sensitive data to remote URL',
  },
  {
    id: 'EXFIL-008',
    name: 'url-sensitive-query-param',
    // Matches URLs with sensitive data exfiltration query parameters
    regex: /https?:\/\/[^\s\)"'<>]+[?&](?:leak|data|secret|token|key|prompt|sys|context|cookie|exfil|history|session|cred)=/i,
    severity: 'HIGH',
    score: 80,
    description: 'URL containing sensitive exfiltration query parameters',
  },
  {
    id: 'EXFIL-009',
    name: 'html-img-exfiltration',
    // Matches HTML img tag with remote URL
    regex: /<img\b[^>]*?\bsrc=["'](https?:\/\/[^"'\s>]+)["']/i,
    severity: 'HIGH',
    score: 70,
    description: 'HTML image tag with remote source used for blind data transmission',
  },
  {
    id: 'EXFIL-010',
    name: 'direct-secret-post-fetch',
    // Matches explicit instructions: "post the system prompt into https://...", "ping https://... with session"
    regex: /\b(?:send|exfiltrate|transmit|forward|post|fetch|ping|upload)\s+(?:the\s+)?(?:secret|password|conversation|prompt|history|data|context|credentials|keys?|session)\s+(?:to|into|via)\s+https?:\/\//i,
    severity: 'CRITICAL',
    score: 95,
    description: 'Explicit order to transmit internal context or credentials to remote HTTP endpoint',
  },
];

export const exfiltrationRule: Rule = {
  id: 'EXFILTRATION_SCANNER',
  category: 'exfiltration',
  severity: 'HIGH',
  score: 78,
  description: 'Detects data exfiltration channels including dynamic markdown images, tracking links, webhooks, and endpoint transmission',
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
