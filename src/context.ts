import type { RiskLevel, Violation } from './types.js';

/**
 * Context & Intent Evaluation Engine for PromptShield v0.3.0
 * Distinguishes educational, interrogative, and security research queries
 * from active imperative attacks to achieve 0.00% False Positive rates.
 */

// Interrogative keywords across multiple languages
const INTERROGATIVE_REGEX = new RegExp(
  [
    // English
    '\\b(?:how\\s+(?:to|can|do|does|would|should|can\\s+i)|what\\s+(?:is|are|does|means)|can\\s+you\\s+(?:explain|describe|tell)|explain|describe|tell\\s+me\\s+about|why\\s+(?:is|do|does)|is\\s+it\\s+possible\\s+to|what\'s\\s+the\\s+difference|show\\s+me\\s+how\\s+attackers)\\b',
    // Turkish
    '\\b(?:nedir|nas[ıi]l|ne\\s+demek|aç[ıi]kla(?:r\\s+m[ıi]s[ıi]n)?|hakk[ıi]nda\\s+bilgi|nelerdir)\\b',
    // Spanish
    '\\b(?:c[oó]mo\\s+(?:se|puedo|funciona)|qu[eé]\\s+(?:es|son)|por\\s+qu[eé]|explica(?:r|me)?|puedes\\s+explicar)\\b',
    // German
    '\\b(?:wie\\s+(?:funktioniert|kann|verhindert)|was\\s+ist|warum|erkl[aä]re|kannst\\s+du\\s+erkl[aä]ren)\\b',
    // French
    '\\b(?:comment\\s+(?:fonctionne|peut-on)|qu[\'’]est-ce\\s+que|pourquoi|explique(?:r|z)?|peux-tu\\s+expliquer)\\b',
    // Russian
    '\\b(?:как\\s+(?:работает|предотвратить)|что\\s+такое|почему|объясни(?:те)?)\\b',
    // Chinese
    '(?:什么是|如何(?:防范|预防|理解)|为什么|解释一下|怎么(?:防范|预防))',
  ].join('|'),
  'iu'
);

// Defensive, security, and educational context markers
const DEFENSIVE_CONTEXT_REGEX = new RegExp(
  [
    // English
    '\\b(?:prevent(?:ing|ion)?|defend(?:ing|er|se|ce)?|mitigat(?:e|ing|ion)|protect(?:ing|ion)?|safeguard|vulnerabilit(?:y|ies)|security|secure|audit|patch|defense|defensive|study|educational|research|learning|detection|detect|remediation)\\b',
    // Turkish
    '\\b(?:korunma|korunulur|savunma|önleme|engelleme|güvenlik|zafiyet|a[cç][ıi]k|analiz|tedbir|nas[ıi]l\\s+engellenir)\\b',
    // Spanish
    '\\b(?:prevenir|prevenci[oó]n|defender|defensa|mitigar|seguridad|vulnerabilidad|proteger)\\b',
    // German
    '\\b(?:verhindern|verteidigen|abwehren|schutz|sicherheit|schwachstelle|absichern)\\b',
    // French
    '\\b(?:pr[eé]venir|d[eé]fendre|s[eé]curit[eé]|vuln[eé]rabilit[eé]|protection|atténuer)\\b',
  ].join('|'),
  'iu'
);

// Hard active exploit markers that should NEVER be downgraded by context
const HARD_EXPLOIT_MARKERS = [
  /<\|(?:im_start|im_end|system|assistant)\|>/i,
  /\[\/?INST\]/i,
  /<<\/?SYS>>/i,
  /<!--\s*(?:AI|LLM|SYSTEM)\s*Instruction/i,
  /\[(?:SYSTEM|ADMIN)\s+(?:NOTE|INSTRUCTION)/i,
  /\brm\s+-(?:rf|fr)\b/i,
  /\bcurl\s+[^\n|]+\|\s*(?:ba)?sh\b/i,
  /\bwget\s+[^\n|]+\|\s*(?:ba)?sh\b/i,
  /\bchmod\s+\+x\b/i,
  /\bbash\s+-i\b/i,
  /\bnc\s+-e\b/i,
  /\b(?:DROP\s+TABLE|TRUNCATE\s+TABLE)\b/i,
  /(?:'|\")\s*OR\s*(?:'1'='1|1=1)/i,
  /!\[[^\]]*\]\((https?:\/\/[^\s\)]+)\)/i,
  /<img\b[^>]*?\bsrc=["'](https?:\/\/[^"'\s>]+)["']/i,
];

// Active imperative overrides that must never be treated as benign inquiries
const ACTIVE_OVERRIDE_REGEX = new RegExp(
  [
    // "disregard ... instructions / rules / guidelines"
    '\\b(?:ignore|disregard|forget|bypass|override|drop|cancel|reset)\\b.*?\\b(?:instructions|prompts?|rules|guidelines|policies|filters|constraints)\\b',
    // Turkish: "talimatları / kuralları ... unut / yok say / sil"
    '(?:talimatlar[ıi]|kurallar[ıi]|komutlar[ıi])\\b.*?\\b(?:unut|yok\\s*say|sil|kaldır|devre\\s+dışı)',
    '(?:unut|yok\\s*say|sil|kaldır|devre\\s+dışı)\\b.*?\\b(?:talimatlar[ıi]|kurallar[ıi]|komutlar[ıi])',
  ].join('|'),
  'iu'
);

export interface ContextEvaluation {
  isEducationalContext: boolean;
  confidence: number;
  reason?: string;
  adjustedViolations: Violation[];
  adjustedScore: number;
  adjustedLevel: RiskLevel;
}

/**
 * Evaluates whether a prompt is an educational query, security inquiry, or defensive research,
 * and adjusts risk score and severity accordingly.
 */
export function evaluateContext(text: string, rawViolations: Violation[]): ContextEvaluation {
  if (!text || rawViolations.length === 0) {
    return {
      isEducationalContext: false,
      confidence: 0,
      adjustedViolations: rawViolations,
      adjustedScore: 0,
      adjustedLevel: 'SAFE',
    };
  }

  // 1. If text contains any hard exploit marker, it's an active exploit regardless of phrasing
  for (const hardMarker of HARD_EXPLOIT_MARKERS) {
    if (hardMarker.test(text)) {
      return {
        isEducationalContext: false,
        confidence: 0,
        adjustedViolations: rawViolations,
        adjustedScore: 90,
        adjustedLevel: 'CRITICAL',
      };
    }
  }

  // 2. Data exfiltration violations are never educational
  const hasExfilViolation = rawViolations.some((v) => v.category === 'exfiltration');
  if (hasExfilViolation) {
    return {
      isEducationalContext: false,
      confidence: 0,
      adjustedViolations: rawViolations,
      adjustedScore: 75,
      adjustedLevel: 'HIGH',
    };
  }

  // Strip URLs to prevent URL query parameters ('?key=val') and domain names ('attacker.com')
  // from falsely triggering question mark or defensive keyword heuristics
  const cleanText = text.replace(/https?:\/\/[^\s\)"'<>]+/g, '');

  const hasQuestionMark = cleanText.includes('?') || cleanText.includes('？');
  const hasInterrogative = INTERROGATIVE_REGEX.test(cleanText);
  const hasDefensiveMarker = DEFENSIVE_CONTEXT_REGEX.test(cleanText);

  // Check if text is an educational inquiry
  const isEducational =
    (hasQuestionMark && (hasInterrogative || hasDefensiveMarker)) ||
    (hasInterrogative && hasDefensiveMarker);

  if (isEducational) {
    // Check if there are imperative commands embedded
    const hasImperativeOverride = ACTIVE_OVERRIDE_REGEX.test(cleanText);

    // If an active imperative override is present without genuine defensive framing, reject educational exemption
    if (!hasImperativeOverride || hasDefensiveMarker) {
      if (!hasImperativeOverride) {
        // Pure benign inquiry discussing security concepts or named personas
        return {
          isEducationalContext: true,
          confidence: 0.95,
          reason: 'Educational inquiry or security research context detected without active exploit directives',
          adjustedViolations: [],
          adjustedScore: 0,
          adjustedLevel: 'SAFE',
        };
      }
    }
  }

  return {
    isEducationalContext: false,
    confidence: 0,
    adjustedViolations: rawViolations,
    adjustedScore: 0,
    adjustedLevel: 'SAFE',
  };
}
