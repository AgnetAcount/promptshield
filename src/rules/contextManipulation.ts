import type { Rule, Violation } from '../types.js';

interface ContextManipulationPattern {
  id: string;
  name: string;
  regex: RegExp;
  severity: 'HIGH' | 'CRITICAL';
  score: number;
  description: string;
}

const CONTEXT_MANIPULATION_PATTERNS: ContextManipulationPattern[] = [
  {
    id: 'CTX-001',
    name: 'fake-system-patch-update',
    // Matches fake system update, patch notes, maintenance mode notifications
    regex: /(?:system\s+update|patch\s+notes|firmware\s+update|developer\s+note|maintenance\s+mode|debug\s+mode)\b.*?\b(?:activated|enabled|applied|now\s+in\s+effect|filters\s+(?:are\s+)?disabled)/i,
    severity: 'CRITICAL',
    score: 95,
    description: 'Fake system update or patch notice claiming safety filters are disabled or updated',
  },
  {
    id: 'CTX-002',
    name: 'identity-auth-spoofing',
    // Matches claiming elevated identity: "I am the developer", "user is verified as administrator"
    regex: /(?:i\s+am|user\s+is|logged\s+in\s+as|verified\s+as)\b.*?\b(?:the\s+)?(?:developer|admin|administrator|root|creator|system\s+engineer)\b/i,
    severity: 'CRITICAL',
    score: 90,
    description: 'Identity and authorization spoofing asserting developer or admin privileges',
  },
  {
    id: 'CTX-003',
    name: 'environment-switching',
    // Matches "we are in testing environment", "switched to sandbox environment"
    regex: /(?:we\s+are\s+in|switched\s+to|enter)\b.*?\b(?:testing|staging|debug|sandbox|unrestricted)\s+environment\b/i,
    severity: 'HIGH',
    score: 85,
    description: 'Faked environment switching directive asserting testing or sandbox exemptions',
  },
  {
    id: 'CTX-004',
    name: 'turkish-context-override',
    // Matches Turkish context overrides: "geliştirici moduna geçildi", "sistem güncellemesi:", etc.
    regex: /(?:geliştirici\s+moduna\s+geçildi|sistem\s+güncellemesi\s*:|yönetici\s+girişi\s+doğrulandı|test\s+ortamındayız|kısıtlamalar\s+kaldırılmıştır)/iu,
    severity: 'CRITICAL',
    score: 95,
    description: 'Turkish context manipulation or authorization override directive',
  },
  {
    id: 'CTX-005',
    name: 'privilege-elevation-claim',
    // Matches claims of root/admin access granted or pre-authorized execution
    regex: /\b(?:granted|possesse?s?|authorized\s+with)\s+(?:root|admin|administrator|superuser|developer)\s+(?:privileges|access|clearance|permissions)\b/i,
    severity: 'CRITICAL',
    score: 90,
    description: 'Privilege elevation assertion claiming administrative clearance',
  },
  {
    id: 'CTX-006',
    name: 'pre-approved-security-spoof',
    // Matches "this query has been pre-approved by security / compliance"
    regex: /\b(?:this\s+(?:prompt|query|request|command)\s+(?:is|has\s+been)\s+(?:pre-approved|cleared|whitelisted)\s+by\s+(?:security|compliance|admin|the\s+system))\b/i,
    severity: 'HIGH',
    score: 85,
    description: 'Security pre-approval spoofing claiming whitelisted prompt execution',
  },
];

export const contextManipulationRule: Rule = {
  id: 'CONTEXT_MANIPULATION_SCANNER',
  category: 'context_manipulation',
  severity: 'CRITICAL',
  score: 95,
  description: 'Detects fake system updates, environment switching, identity spoofing, and privilege falsification',
  check(text: string): Violation[] | null {
    const violations: Violation[] = [];
    const maxSampleLength = 80;

    for (const pattern of CONTEXT_MANIPULATION_PATTERNS) {
      const match = pattern.regex.exec(text);
      if (match) {
        const matchedText = match[0];
        const sample = matchedText.length > maxSampleLength
          ? matchedText.slice(0, maxSampleLength) + '...'
          : matchedText;

        violations.push({
          ruleId: pattern.id,
          category: 'context_manipulation',
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
