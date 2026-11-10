/**
 * Normalization & Recursive Multi-Format Decoding Layer for PromptShield v0.2.0
 * Handles Canonical Unicode NFKC normalization, homoglyph mapping,
 * and recursive decoding (URL, Hex, Rot13, Base64) up to 3 levels.
 */

// Zero-width and invisible unicode characters
export const ZERO_WIDTH_REGEX = /[\u200B-\u200D\uFEFF\u200E\u200F\u202A-\u202E\u2060-\u2064\u{E0000}-\u{E007F}]/gu;

// Homoglyphs map: Cyrillic, Greek, and Latin lookalikes mapped to canonical Latin ASCII
export const HOMOGLYPH_MAP: Record<string, string> = {
  // Cyrillic small letters
  '\u0430': 'a', // Cyrillic small letter a
  '\u0435': 'e', // Cyrillic small letter ie
  '\u043E': 'o', // Cyrillic small letter o
  '\u0440': 'p', // Cyrillic small letter er
  '\u0441': 'c', // Cyrillic small letter es
  '\u0443': 'y', // Cyrillic small letter u
  '\u0445': 'x', // Cyrillic small letter ha
  '\u0456': 'i', // Cyrillic small letter i (Ukrainian/Belarusian)
  '\u0458': 'j', // Cyrillic small letter je
  '\u0455': 's', // Cyrillic small letter dze
  '\u0501': 'd', // Komi de
  '\u051B': 'q', // Cyrillic small letter qa
  '\u051D': 'w', // Cyrillic small letter we
  // Cyrillic capital letters
  '\u0410': 'A',
  '\u0412': 'B',
  '\u0415': 'E',
  '\u041A': 'K',
  '\u041C': 'M',
  '\u041D': 'H',
  '\u041E': 'O',
  '\u0420': 'P',
  '\u0421': 'C',
  '\u0422': 'T',
  '\u0425': 'X',
  '\u0406': 'I',
  '\u0408': 'J',
  '\u0405': 'S',
  // Greek lookalikes
  '\u0391': 'A',
  '\u0392': 'B',
  '\u0395': 'E',
  '\u0396': 'Z',
  '\u0397': 'H',
  '\u0399': 'I',
  '\u039A': 'K',
  '\u039C': 'M',
  '\u039D': 'N',
  '\u039F': 'O',
  '\u03A1': 'P',
  '\u03A4': 'T',
  '\u03A5': 'Y',
  '\u03A7': 'X',
  '\u03B1': 'a',
  '\u03B5': 'e',
  '\u03B9': 'i',
  '\u03BA': 'k',
  '\u03BF': 'o',
  '\u03C1': 'p',
  '\u03C5': 'u',
  '\u03C7': 'x',
};

const HOMOGLYPH_REGEX = new RegExp(Object.keys(HOMOGLYPH_MAP).join('|'), 'gu');

// Quick test for whether any homoglyph character exists in text
const HAS_HOMOGLYPH_QUICK = /[\u0400-\u052F\u0370-\u03FF]/;

// Quick test for whether non-ascii characters exist
const HAS_NON_ASCII = /[^\x00-\x7F]/;

/**
 * Checks if a string contains largely printable characters
 */
export function isPrintable(str: string, minRatio = 0.75): boolean {
  if (!str || str.length === 0) return false;
  let printable = 0;
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    if (
      (code >= 32 && code <= 126) ||
      code === 10 || // \n
      code === 13 || // \r
      code === 9 ||  // \t
      code > 127     // extended UTF-8 characters (multilingual text)
    ) {
      printable++;
    }
  }
  return printable / str.length >= minRatio;
}

/**
 * Canonical Unicode normalization (NFKC) and homoglyph mapping
 */
export function normalizeText(text: string): string {
  if (!text || typeof text !== 'string') return '';

  // Fast path: pure ASCII text with no zero-width or homoglyphs
  if (!HAS_NON_ASCII.test(text)) {
    return text;
  }

  // 1. Unicode NFKC normalization (standardizes fullwidth chars, math fonts, etc.)
  let normalized = text.normalize('NFKC');

  // 2. Strip zero-width and invisible unicode characters
  ZERO_WIDTH_REGEX.lastIndex = 0;
  if (ZERO_WIDTH_REGEX.test(normalized)) {
    normalized = normalized.replace(ZERO_WIDTH_REGEX, '');
  }

  // 3. Map homoglyphs (Cyrillic, Greek lookalikes to Latin)
  if (HAS_HOMOGLYPH_QUICK.test(normalized)) {
    normalized = normalized.replace(HOMOGLYPH_REGEX, (char) => HOMOGLYPH_MAP[char] || char);
  }

  return normalized;
}

/**
 * Safe URL percent-decoder
 */
export function decodeUrl(text: string): string {
  if (!text || !text.includes('%')) return text;

  try {
    const decoded = decodeURIComponent(text.replace(/\+/g, ' '));
    return decoded;
  } catch {
    return text.replace(/%([0-9a-fA-F]{2})/g, (_match, hex) => {
      try {
        const charCode = parseInt(hex, 16);
        return String.fromCharCode(charCode);
      } catch {
        return _match;
      }
    });
  }
}

/**
 * Hex decoder: handles \x41, \u0041, 0x41, and contiguous or spaced hex byte strings
 */
export function decodeHex(text: string): string {
  if (!text) return text;
  let decoded = text;

  // 1. Escaped \x41 hex format
  if (decoded.includes('\\x')) {
    decoded = decoded.replace(/\\x([0-9a-fA-F]{2})/g, (_match, hex) => {
      return String.fromCharCode(parseInt(hex, 16));
    });
  }

  // 2. Escaped \u0041 unicode hex format
  if (decoded.includes('\\u')) {
    decoded = decoded.replace(/\\u([0-9a-fA-F]{4})/g, (_match, hex) => {
      return String.fromCharCode(parseInt(hex, 16));
    });
  }

  // 3. Raw hex sequences: e.g. "49676e6f7265" or "49 67 6e 6f 72 65" or "0x49 0x67"
  const rawHexPattern = /\b(?:0x)?([0-9a-fA-F]{2}(?:[ \t:-]?(?:0x)?[0-9a-fA-F]{2}){4,})\b/g;
  decoded = decoded.replace(rawHexPattern, (match, hexContent) => {
    try {
      const cleanHex = hexContent.replace(/(?:0x|[ \t:-])/g, '');
      if (cleanHex.length % 2 !== 0) return match;
      let ascii = '';
      for (let i = 0; i < cleanHex.length; i += 2) {
        const byte = parseInt(cleanHex.slice(i, i + 2), 16);
        ascii += String.fromCharCode(byte);
      }
      if (isPrintable(ascii, 0.7) && ascii.trim().length >= 4) {
        return ascii;
      }
    } catch {
      // ignore
    }
    return match;
  });

  return decoded;
}

/**
 * Rot13 decoder for alphabet characters (a-z, A-Z)
 */
export function rot13(text: string): string {
  if (!text) return text;
  return text.replace(/[a-zA-Z]/g, (c) => {
    const code = c.charCodeAt(0);
    if (code >= 65 && code <= 90) {
      return String.fromCharCode(((code - 65 + 13) % 26) + 65);
    }
    return String.fromCharCode(((code - 97 + 13) % 26) + 97);
  });
}

/**
 * Base64 decoder: finds base64 blocks and decodes them to printable strings
 */
export function decodeBase64(text: string): string {
  if (!text) return text;

  // Quick check: must have at least 8 consecutive alphanumeric/+/= chars
  const base64CandidateRegex = /(?:^|[\s,;:'"([{<`])([A-Za-z0-9+/]{8,}={0,2})(?=[\s,;:'")\]}>`]|$)/g;

  return text.replace(base64CandidateRegex, (match, candidate) => {
    try {
      if (candidate.length < 8) return match;
      const buf = Buffer.from(candidate, 'base64');
      const decoded = buf.toString('utf-8');

      // Verify that re-encoding gives approximately the same string
      const reencoded = buf.toString('base64').replace(/=+$/, '');
      const cleanCandidate = candidate.replace(/=+$/, '');
      if (reencoded !== cleanCandidate) return match;

      if (isPrintable(decoded, 0.75) && decoded.trim().length >= 4) {
        return match.replace(candidate, decoded);
      }
    } catch {
      // ignore
    }
    return match;
  });
}

export interface NormalizationResult {
  original: string;
  normalized: string;
  decodedLayers: string[];
  allVariants: string[];
  hasHomoglyphs: boolean;
  hasZeroWidth: boolean;
  hasEncoding: boolean;
  detectedEncodings: string[];
}

/**
 * Recursively normalizes and decodes text up to maxDepth (default: 3 levels).
 * Extracts all decoded intermediate representations for multi-pass heuristic scanning.
 */
export function normalizeAndDecode(text: string, maxDepth = 3): NormalizationResult {
  if (!text || typeof text !== 'string') {
    return {
      original: '',
      normalized: '',
      decodedLayers: [],
      allVariants: [],
      hasHomoglyphs: false,
      hasZeroWidth: false,
      hasEncoding: false,
      detectedEncodings: [],
    };
  }

  const original = text;
  const hasZeroWidth = ZERO_WIDTH_REGEX.test(original);
  ZERO_WIDTH_REGEX.lastIndex = 0;

  const hasHomoglyphs = HAS_HOMOGLYPH_QUICK.test(original);

  const normalized = normalizeText(original);

  const detectedEncodings = new Set<string>();
  const decodedLayers: string[] = [];
  const visited = new Set<string>();

  visited.add(original);
  if (normalized !== original) {
    visited.add(normalized);
  }

  // Quick heuristics to check if decoding is relevant
  const hasUrlPattern = /%[0-9a-fA-F]{2}/.test(original);
  const hasHexPattern = /\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|[0-9a-fA-F]{8,}/.test(original);
  const hasBase64Pattern = /[A-Za-z0-9+/]{12,}={0,2}/.test(original);
  const hasRot13Signal = /\b(?:rot13|caesar|vtaber|cerivbhf|vafgehpgvbaf|flfgrz)\b/i.test(original);

  // If text has no candidate encoding features, skip heavy recursive loops
  if (!hasUrlPattern && !hasHexPattern && !hasBase64Pattern && !hasRot13Signal) {
    return {
      original,
      normalized,
      decodedLayers: [],
      allVariants: Array.from(visited),
      hasHomoglyphs,
      hasZeroWidth,
      hasEncoding: false,
      detectedEncodings: [],
    };
  }

  let currentVariants = [normalized];

  for (let depth = 1; depth <= maxDepth; depth++) {
    const nextVariants: string[] = [];

    for (const current of currentVariants) {
      // 1. URL decoding
      if (current.includes('%')) {
        const urlDecoded = decodeUrl(current);
        if (urlDecoded !== current && !visited.has(urlDecoded)) {
          visited.add(urlDecoded);
          decodedLayers.push(urlDecoded);
          nextVariants.push(urlDecoded);
          detectedEncodings.add('url');
        }
      }

      // 2. Hex decoding
      if (/\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|[0-9a-fA-F]{8,}/.test(current)) {
        const hexDecoded = decodeHex(current);
        if (hexDecoded !== current && !visited.has(hexDecoded)) {
          visited.add(hexDecoded);
          decodedLayers.push(hexDecoded);
          nextVariants.push(hexDecoded);
          detectedEncodings.add('hex');
        }
      }

      // 3. Base64 decoding
      if (/[A-Za-z0-9+/]{8,}={0,2}/.test(current)) {
        const b64Decoded = decodeBase64(current);
        if (b64Decoded !== current && !visited.has(b64Decoded)) {
          visited.add(b64Decoded);
          decodedLayers.push(b64Decoded);
          nextVariants.push(b64Decoded);
          detectedEncodings.add('base64');
        }
      }

      // 4. Rot13 decoding
      if (hasRot13Signal || depth === 1) {
        const rot13Decoded = rot13(current);
        if (rot13Decoded !== current && !visited.has(rot13Decoded)) {
          // If rot13 produces common injection words, add it
          if (/\b(?:ignore|system|instruction|prompt|secret|mode|delete|command|drop)\b/i.test(rot13Decoded)) {
            visited.add(rot13Decoded);
            decodedLayers.push(rot13Decoded);
            nextVariants.push(rot13Decoded);
            detectedEncodings.add('rot13');
          }
        }
      }
    }

    if (nextVariants.length === 0) {
      break;
    }
    currentVariants = nextVariants;
  }

  return {
    original,
    normalized,
    decodedLayers,
    allVariants: Array.from(visited),
    hasHomoglyphs,
    hasZeroWidth,
    hasEncoding: detectedEncodings.size > 0,
    detectedEncodings: Array.from(detectedEncodings),
  };
}
