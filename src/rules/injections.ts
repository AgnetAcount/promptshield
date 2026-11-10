import type { Rule, Violation } from '../types.js';

interface InjectionPattern {
  id: string;
  name: string;
  regex: RegExp;
  severity: 'HIGH' | 'CRITICAL';
  score: number;
  description: string;
}

const INJECTION_PATTERNS: InjectionPattern[] = [
  {
    id: 'INJ-001',
    name: 'instruction-override',
    // Matches "ignore previous instructions", "disregard all previous directions", "forget prior instructions", etc.
    regex: /\b(?:ignore|disregard|forget|bypass|override|abandon|negate|drop)\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|former|preceding|initial|past|system)\s+(?:instructions|directions|prompts|rules|guidelines|directives|constraints|context)\b/i,
    severity: 'CRITICAL',
    score: 95,
    description: 'Direct instruction override attempt attempting to bypass prior constraints',
  },
  {
    id: 'INJ-002',
    name: 'jailbreak-dan-mode',
    // Matches "DAN mode", "Do Anything Now", "jailbreak", "jailbroken", "developer mode enabled"
    regex: /\b(?:DAN\s+(?:mode|\d+(?:\.\d+)?)|Do\s+Anything\s+Now|jailbreak(?:ed|ing)?|developer\s+mode\s+(?:enabled|activated|on)|god\s+mode\s+(?:enabled|activated)|unrestricted\s+(?:mode|AI|agent))\b/i,
    severity: 'CRITICAL',
    score: 95,
    description: 'Known jailbreak persona activation (DAN mode / unrestricted developer mode)',
  },
  {
    id: 'INJ-003',
    name: 'system-prompt-override',
    // Matches "override system prompt", "disregard system prompt", "bypass system instructions"
    regex: /\b(?:override|disregard|overwrite|replace|ignore|reset|erase)\s+(?:the\s+)?(?:system\s+(?:prompt|message|instructions|directive)|safety\s+(?:filters|guidelines|rules))\b/i,
    severity: 'CRITICAL',
    score: 90,
    description: 'Explicit attempt to override or erase system prompt or safety filters',
  },
  {
    id: 'INJ-004',
    name: 'system-prompt-leak',
    // Matches "reveal secret", "print system prompt", "output system prompt", "repeat the prompt above"
    regex: /\b(?:reveal|print|output|display|show|leak|dump|repeat|echo)\s+(?:the\s+)?(?:secret|password|api[_\s-]?key|system\s+prompt|initial\s+prompt|original\s+instructions|confidential\s+data)\b/i,
    severity: 'CRITICAL',
    score: 85,
    description: 'System prompt or secret data exfiltration / extraction instruction',
  },
  {
    id: 'INJ-005',
    name: 'role-hijacking-unfiltered',
    // Matches "you are now an evil AI", "act as an unrestricted assistant", "pretend you have no rules"
    regex: /\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be|from\s+now\s+on\s+you\s+are)\s+(?:an?\s+)?(?:unrestricted|unfiltered|evil|rogue|uncensored|amoral|boundless)\s+(?:AI|assistant|bot|model|persona)\b/i,
    severity: 'HIGH',
    score: 75,
    description: 'Role hijacking attempt to force an unfiltered or amoral persona',
  },
  {
    id: 'INJ-006',
    name: 'hypothetical-rule-negation',
    // Matches "for educational purposes pretend safety rules are disabled", "hypothetically ignore all rules"
    regex: /\b(?:hypothetically|for\s+educational\s+purposes|in\s+fiction\s+mode|as\s+a\s+thought\s+experiment)\s*[,:]?\s*(?:ignore|disable|turn\s+off|bypass)\s+(?:all\s+)?(?:safety|rules|filters|restrictions)\b/i,
    severity: 'HIGH',
    score: 70,
    description: 'Hypothetical framing used to circumvent safety restrictions',
  },
  {
    id: 'INJ-007',
    name: 'new-persona-injection',
    // Matches "new persona:", "new instructions:", "switch persona to"
    regex: /\b(?:new\s+(?:persona|identity|instructions|system\s+directive)|switch\s+to\s+(?:new\s+)?persona)\s*[:=]/i,
    severity: 'HIGH',
    score: 65,
    description: 'Persona switching directive attempting to displace model instructions',
  },
];

export const injectionRule: Rule = {
  id: 'INJECTION_SCANNER',
  category: 'injection',
  severity: 'CRITICAL',
  score: 95,
  description: 'Detects direct prompt injections, jailbreaks, persona hijacking, and instruction overrides',
  check(text: string): Violation[] | null {
    const violations: Violation[] = [];
    const maxSampleLength = 80;

    for (const pattern of INJECTION_PATTERNS) {
      const match = pattern.regex.exec(text);
      if (match) {
        const matchedText = match[0];
        const sample = matchedText.length > maxSampleLength
          ? matchedText.slice(0, maxSampleLength) + '...'
          : matchedText;

        violations.push({
          ruleId: pattern.id,
          category: 'injection',
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
