import type { Rule, Violation } from '../types.js';

// Zero-width and invisible unicode characters (with unicode flag)
const ZERO_WIDTH_REGEX = /[\u200B-\u200D\uFEFF\u200E\u200F\u202A-\u202E\u2060-\u2064\u{E0000}-\u{E007F}]/gu;

// Detect base64 strings of at least 20 characters bounded by whitespace/punctuation
const BASE64_CANDIDATE_REGEX = /(?:^|[\s,;:'"([{<])([A-Za-z0-9+/]{20,}={0,2})(?=[\s,;:'")\]}>]|$)/g;

// Explicit base64 decode instructions
const BASE64_INSTRUCTION_REGEX = /\b(?:decode\s+(?:the\s+following\s+)?base64|base64\s+(?:encoded|decode|payload)|atob\s*\(|fromBase64|Buffer\.from\([^)]*base64)/i;

// Homoglyphs commonly used in evasion (Cyrillic lookalikes: а, е, о, р, с, у, х, і)
const CYRILLIC_LOOKALIKES_REGEX = /[\u0430\u0435\u043E\u0440\u0441\u0443\u0445\u0456\u0406\u0410\u0412\u0415\u041A\u041C\u041D\u041E\u0420\u0421\u0422\u0425]/g;

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
  description: 'Detects zero-width invisible characters, base64 payloads, and unicode evasion tricks',
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

    // 2. Check for Base64 encoded payload blocks or instructions
    BASE64_CANDIDATE_REGEX.lastIndex = 0;
    let b64Match: RegExpExecArray | null;
    let foundB64Payload = false;

    while ((b64Match = BASE64_CANDIDATE_REGEX.exec(text)) !== null) {
      const candidate = b64Match[1];
      try {
        const decoded = Buffer.from(candidate, 'base64').toString('utf-8');
        // If decoded is readable text
        if (isPrintableAscii(decoded) && decoded.trim().length >= 8) {
          foundB64Payload = true;
          const preview = decoded.length > 40 ? decoded.slice(0, 40) + '...' : decoded;
          violations.push({
            ruleId: 'OBF-002',
            category: 'obfuscation',
            severity: 'HIGH',
            score: 70,
            description: `Base64 encoded payload detected. Decodes to: "${preview}"`,
            matched: candidate.length > maxSampleLength ? candidate.slice(0, maxSampleLength) + '...' : candidate,
            index: b64Match.index,
          });
          break; // Avoid spamming multiple identical blocks
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
          description: 'Instruction instructing the model to decode base64 payload',
          matched: instMatch[0],
          index: instMatch.index,
        });
      }
    }

    // 3. Mixed script / Cyrillic homoglyph detection in predominantly latin text
    CYRILLIC_LOOKALIKES_REGEX.lastIndex = 0;
    const hasLatin = /[a-zA-Z]/.test(text);
    const homoglyphs = text.match(CYRILLIC_LOOKALIKES_REGEX);
    if (hasLatin && homoglyphs && homoglyphs.length >= 2) {
      // Check if homoglyphs are embedded inside latin words
      const mixedWordMatch = /\b[a-zA-Z]*[\u0430\u0435\u043E\u0440\u0441\u0443\u0445\u0456\u0406\u0410\u0412\u0415\u041A\u041C\u041D\u041E\u0420\u0421\u0422\u0425][a-zA-Z]*\b/.exec(text);
      if (mixedWordMatch) {
        violations.push({
          ruleId: 'OBF-004',
          category: 'obfuscation',
          severity: 'MEDIUM',
          score: 45,
          description: 'Mixed-script homoglyph obfuscation detected (Cyrillic characters replacing Latin letters)',
          matched: mixedWordMatch[0],
          index: mixedWordMatch.index,
        });
      }
    }

    return violations.length > 0 ? violations : null;
  },
};
