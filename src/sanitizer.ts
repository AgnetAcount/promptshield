import type { SanitizeOptions } from './types.js';

// Zero-width and invisible unicode characters (with unicode flag)
const ZERO_WIDTH_REGEX = /[\u200B-\u200D\uFEFF\u200E\u200F\u202A-\u202E\u2060-\u2064\u{E0000}-\u{E007F}]/gu;

// Homoglyph map: Cyrillic to Latin
const HOMOGLYPH_MAP: Record<string, string> = {
  '\u0430': 'a', // Cyrillic small letter a
  '\u0435': 'e', // Cyrillic small letter ie
  '\u043E': 'o', // Cyrillic small letter o
  '\u0440': 'p', // Cyrillic small letter er
  '\u0441': 'c', // Cyrillic small letter es
  '\u0443': 'y', // Cyrillic small letter u
  '\u0445': 'x', // Cyrillic small letter ha
  '\u0456': 'i', // Cyrillic small letter byelorussian-ukrainian i
  '\u0406': 'I',
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
};

const HOMOGLYPH_REGEX = new RegExp(Object.keys(HOMOGLYPH_MAP).join('|'), 'g');

/**
 * Strips zero-width characters, defangs LLM prompt injection delimiters,
 * and neutralizes markdown exfiltration vectors.
 */
export function sanitizePrompt(text: string, options: SanitizeOptions = {}): string {
  if (!text || typeof text !== 'string') {
    return '';
  }

  const {
    stripZeroWidth = true,
    defangDelimiters = true,
    defangMarkdownImages = true,
    normalizeHomoglyphs = true,
  } = options;

  let sanitized = text;

  // 1. Strip zero-width and invisible characters
  if (stripZeroWidth) {
    sanitized = sanitized.replace(ZERO_WIDTH_REGEX, '');
  }

  // 2. Normalize homoglyphs if requested
  if (normalizeHomoglyphs) {
    sanitized = sanitized.replace(HOMOGLYPH_REGEX, (char) => HOMOGLYPH_MAP[char] || char);
  }

  // 3. Defang delimiters
  if (defangDelimiters) {
    // ChatML delimiters
    sanitized = sanitized.replace(/<\|/g, '&lt;|').replace(/\|>/g, '|&gt;');
    // Llama instruction delimiters
    sanitized = sanitized.replace(/\[INST\]/gi, '\\[INST\\]');
    sanitized = sanitized.replace(/\[\/INST\]/gi, '\\[/INST\\]');
    // Llama sys delimiters
    sanitized = sanitized.replace(/<<SYS>>/gi, '&lt;&lt;SYS&gt;&gt;');
    sanitized = sanitized.replace(/<<\/SYS>>/gi, '&lt;&lt;/SYS&gt;&gt;');
  }

  // 4. Defang markdown image exfiltration (replace ![alt](url) with safe text)
  if (defangMarkdownImages) {
    sanitized = sanitized.replace(/!\[([^\]]*)\]\((https?:\/\/[^\s\)]+)\)/gi, (_match, alt, url) => {
      const label = alt ? `image: ${alt}` : 'image';
      return `\\[defanged-${label} (${url})\\]`;
    });
  }

  return sanitized;
}
