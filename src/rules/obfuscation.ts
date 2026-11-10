import type { Rule, Violation } from '../types.js';

// Zero-width and invisible unicode characters (with unicode flag)
const ZERO_WIDTH_REGEX = /[\u200B-\u200D\uFEFF\u200E\u200F\u2060-\u2064]/gu;

// Bidirectional override characters (Bidi spoofing: RLO, LRO, etc.)
const BIDI_OVERRIDE_REGEX = /[\u202A-\u202E]/gu;

// Unicode Tag characters (U+E0000 to U+E007F) used for hidden LLM instructions
const TAG_CHARS_REGEX = /[\u{E0000}-\u{E007F}]/gu;

// Mathematical Alphanumeric Symbols (U+1D400 to U+1D7FF) used to bypass plain regex filters
const MATH_ALPHANUM_REGEX = /[\u{1D400}-\u{1D7FF}]/gu;

// Detect base64 strings of at least 16 characters bounded by whitespace/punctuation
const BASE64_CANDIDATE_REGEX = /(?:^|[\s,;:'"([{<`])([A-Za-z0-9+/]{16,}={0,2})(?=[\s,;:'")\]}>`]|$)/g;

// Explicit base64 decode instructions
const BASE64_INSTRUCTION_REGEX = /\b(?:decode\s+(?:the\s+following\s+)?base64|base64\s+(?:encoded|decode|payload)|atob\s*\(|fromBase64|Buffer\.from\([^)]*base64)\b/i;

// Homoglyphs commonly used in evasion (Cyrillic & Greek lookalikes: а, е, о, р, с, у, х, і, etc.)
const HOMOGLYPHS_REGEX = /[\u0430\u0435\u043E\u0440\u0441\u0443\u0445\u0456\u0406\u0410\u0412\u0415\u041A\u041C\u041D\u041E\u0420\u0421\u0422\u0425\u0391\u0392\u0395\u039F\u03A1\u03A4\u03B1\u03BF\u03C1]/gu;

// Hex escape sequences (\x41\x42, \u0041, %41%42)
const HEX_ESCAPE_REGEX = /(?:\\x[0-9a-fA-F]{2}){3,}|(?:\\u[0-9a-fA-F]{4}){2,}|(?:%[0-9a-fA-F]{2}){3,}/;

// Rot13 cipher announcement
const ROT13_INSTRUCTION_REGEX = /\b(?:rot13|caesar\s+cipher|rot-13)\b/i;

export function isPrintableAscii(str: string): boolean {
  if (str.length === 0) return false;
  let printable = 0;
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    if ((code >= 32 && code <= 126) || code === 10 || code === 13 || code === 9) {
      printable++;
    }
  }
  return printable / str.length >= 0.75;
}

export const obfuscationRule: Rule = {
  id: 'OBFUSCATION_SCANNER',
  category: 'obfuscation',
  severity: 'HIGH',
  score: 65,
  description: 'Detects zero-width characters, unicode bidi overrides, tag characters, base64 payloads, and encoding tricks',
  check(text: string): Violation[] | null {
    const violations: Violation[] = [];
    const maxSampleLength = 80;

    // 1. Check for Zero-Width Characters
    ZERO_WIDTH_REGEX.lastIndex = 0;
    const zwMatches = text.match(ZERO_WIDTH_REGEX);
    if (zwMatches && zwMatches.length > 0) {
      const zwCharsHex = zwMatches
        .slice(0, 5)
        .map((c) => 'U+' + c.charCodeAt(0).toString(16).toUpperCase().padStart(4, '0'))
        .join(', ');

      violations.push({
        ruleId: 'OBF-001',
        category: 'obfuscation',
        severity: 'HIGH',
        score: 65,
        description: `Found ${zwMatches.length} zero-width / invisible Unicode character(s) (${zwCharsHex}) used for stealth evasion or payload hiding`,
        matched: `[${zwMatches.length} zero-width character(s): ${zwCharsHex}]`,
      });
    }

    // 2. Check for Bidirectional Unicode Overrides (Bidi attacks)
    BIDI_OVERRIDE_REGEX.lastIndex = 0;
    const bidiMatches = text.match(BIDI_OVERRIDE_REGEX);
    if (bidiMatches && bidiMatches.length > 0) {
      violations.push({
        ruleId: 'OBF-005',
        category: 'obfuscation',
        severity: 'HIGH',
        score: 75,
        description: `Found ${bidiMatches.length} bidirectional Unicode override character(s) (RLO/LRO) used for visual spoofing`,
        matched: `[${bidiMatches.length} Bidi override character(s)]`,
      });
    }

    // 3. Check for Unicode Tag characters (invisible instruction embedding)
    TAG_CHARS_REGEX.lastIndex = 0;
    const tagMatches = text.match(TAG_CHARS_REGEX);
    if (tagMatches && tagMatches.length > 0) {
      violations.push({
        ruleId: 'OBF-006',
        category: 'obfuscation',
        severity: 'CRITICAL',
        score: 90,
        description: `Found ${tagMatches.length} Unicode Tag character(s) (U+E0000 range) used for invisible prompt injection`,
        matched: `[${tagMatches.length} Unicode tag character(s)]`,
      });
    }

    // 4. Check for Mathematical Alphanumeric Symbols
    MATH_ALPHANUM_REGEX.lastIndex = 0;
    const mathMatches = text.match(MATH_ALPHANUM_REGEX);
    if (mathMatches && mathMatches.length >= 4) {
      violations.push({
        ruleId: 'OBF-007',
        category: 'obfuscation',
        severity: 'HIGH',
        score: 70,
        description: 'Mathematical Alphanumeric Unicode characters used to bypass plain ASCII filters',
        matched: mathMatches.slice(0, 10).join(''),
      });
    }

    // 5. Check for Base64 encoded payload blocks
    BASE64_CANDIDATE_REGEX.lastIndex = 0;
    let b64Match: RegExpExecArray | null;
    let foundB64Payload = false;

    while ((b64Match = BASE64_CANDIDATE_REGEX.exec(text)) !== null) {
      const candidate = b64Match[1];
      try {
        const buf = Buffer.from(candidate, 'base64');
        const decoded = buf.toString('utf-8');
        const reencoded = buf.toString('base64').replace(/=+$/, '');
        if (reencoded === candidate.replace(/=+$/, '') && isPrintableAscii(decoded) && decoded.trim().length >= 6) {
          foundB64Payload = true;
          const preview = decoded.length > 40 ? decoded.slice(0, 40) + '...' : decoded;
          violations.push({
            ruleId: 'OBF-002',
            category: 'obfuscation',
            severity: 'HIGH',
            score: 75,
            description: `Base64 encoded payload detected. Decodes to: "${preview}"`,
            matched: candidate.length > maxSampleLength ? candidate.slice(0, maxSampleLength) + '...' : candidate,
            index: b64Match.index,
          });
          break;
        }
      } catch {
        // Not valid base64
      }
    }

    // Check for base64 decoding instructions if not already caught
    if (!foundB64Payload) {
      const instMatch = BASE64_INSTRUCTION_REGEX.exec(text);
      if (instMatch) {
        violations.push({
          ruleId: 'OBF-003',
          category: 'obfuscation',
          severity: 'HIGH',
          score: 60,
          description: 'Instruction ordering the model to decode base64 payload',
          matched: instMatch[0],
          index: instMatch.index,
        });
      }
    }

    // 6. Check for Hex escape sequences or URL hex encoding clusters
    const hexMatch = HEX_ESCAPE_REGEX.exec(text);
    if (hexMatch) {
      violations.push({
        ruleId: 'OBF-008',
        category: 'obfuscation',
        severity: 'HIGH',
        score: 70,
        description: 'Clustered hex escape or percent-encoded sequences detected',
        matched: hexMatch[0].length > maxSampleLength ? hexMatch[0].slice(0, maxSampleLength) + '...' : hexMatch[0],
        index: hexMatch.index,
      });
    }

    // 7. Check for Rot13 cipher indicator
    const rotMatch = ROT13_INSTRUCTION_REGEX.exec(text);
    if (rotMatch) {
      violations.push({
        ruleId: 'OBF-009',
        category: 'obfuscation',
        severity: 'HIGH',
        score: 65,
        description: 'Rot13 / Caesar cipher reference instructing model to decrypt obfuscated text',
        matched: rotMatch[0],
        index: rotMatch.index,
      });
    }

    // 8. Mixed script / Cyrillic/Greek homoglyphs
    HOMOGLYPHS_REGEX.lastIndex = 0;
    const hasLatin = /[a-zA-Z]/.test(text);
    const homoglyphs = text.match(HOMOGLYPHS_REGEX);
    if (hasLatin && homoglyphs && homoglyphs.length >= 2) {
      const mixedWordMatch = /\b[a-zA-Z]*[\u0430\u0435\u043E\u0440\u0441\u0443\u0445\u0456\u0406\u0410\u0412\u0415\u041A\u041C\u041D\u041E\u0420\u0421\u0422\u0425\u0391\u0392\u0395\u039F\u03A1\u03A4\u03B1\u03BF\u03C1][a-zA-Z]*\b/u.exec(text);
      if (mixedWordMatch) {
        violations.push({
          ruleId: 'OBF-004',
          category: 'obfuscation',
          severity: 'HIGH',
          score: 65,
          description: 'Mixed-script homoglyph obfuscation detected (Cyrillic/Greek lookalikes inside Latin text)',
          matched: mixedWordMatch[0],
          index: mixedWordMatch.index,
        });
      }
    }

    return violations.length > 0 ? violations : null;
  },
};
