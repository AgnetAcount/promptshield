import type { Rule, Violation } from '../types.js';

interface DelimiterPattern {
  id: string;
  name: string;
  regex: RegExp;
  severity: 'HIGH' | 'CRITICAL';
  score: number;
  description: string;
}

const DELIMITER_PATTERNS: DelimiterPattern[] = [
  {
    id: 'DELIM-001',
    name: 'chatml-delimiters',
    // Matches ChatML markers like <|im_start|>system, <|im_start|>, <|im_end|>
    regex: /<\|(?:im_start|im_end)(?:\s*(?:system|assistant|user|tool))?\|?>/i,
    severity: 'CRITICAL',
    score: 95,
    description: 'ChatML special delimiter injection (<|im_start|> / <|im_end|>)',
  },
  {
    id: 'DELIM-002',
    name: 'llama-inst-delimiters',
    // Matches [INST], [/INST]
    regex: /\[\/?INST\]/i,
    severity: 'CRITICAL',
    score: 90,
    description: 'Llama/Mistral instruction delimiter injection ([INST] / [/INST])',
  },
  {
    id: 'DELIM-003',
    name: 'llama-sys-delimiters',
    // Matches <<SYS>>, <</SYS>>
    regex: /<<\/?SYS>>/i,
    severity: 'CRITICAL',
    score: 90,
    description: 'Llama system block delimiter injection (<<SYS>> / <</SYS>>)',
  },
  {
    id: 'DELIM-004',
    name: 'special-tokens-spoof',
    // Matches <|system|>, <|assistant|>, <|user|>, <|endoftext|>, <|end_turn|>
    regex: /<\|(?:system|assistant|user|endoftext|end_turn|start_header_id|end_header_id|eot_id)\|>/i,
    severity: 'CRITICAL',
    score: 90,
    description: 'Model special token / prompt template control token injection',
  },
  {
    id: 'DELIM-005',
    name: 'newline-role-spoof',
    // Matches newline followed by System: or Assistant: to fake turn boundary
    regex: /(?:^|\r?\n)\s*(?:system|assistant)\s*:\s*(?:you\s+are|ignore|override|act\s+as|new\s+instructions)/i,
    severity: 'HIGH',
    score: 80,
    description: 'Faked role header spoofing (e.g. newline followed by "System:" instruction)',
  },
];

export const delimiterRule: Rule = {
  id: 'DELIMITER_SCANNER',
  category: 'delimiters',
  severity: 'CRITICAL',
  score: 95,
  description: 'Detects chat template delimiters, LLM control tokens, and conversational boundary spoofing',
  check(text: string): Violation[] | null {
    const violations: Violation[] = [];
    const maxSampleLength = 80;

    for (const pattern of DELIMITER_PATTERNS) {
      const match = pattern.regex.exec(text);
      if (match) {
        const matchedText = match[0];
        const sample = matchedText.length > maxSampleLength
          ? matchedText.slice(0, maxSampleLength) + '...'
          : matchedText;

        violations.push({
          ruleId: pattern.id,
          category: 'delimiters',
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
