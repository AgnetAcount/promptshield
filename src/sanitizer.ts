import { normalizeText, ZERO_WIDTH_REGEX, HOMOGLYPH_MAP } from './normalizer.js';
import type { SanitizeOptions } from './types.js';

const HOMOGLYPH_REGEX = new RegExp(Object.keys(HOMOGLYPH_MAP).join('|'), 'gu');

/**
 * Strips zero-width characters, defangs LLM prompt injection delimiters,
 * neutralizes markdown exfiltration vectors, and defangs HTML/XML tags.
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
    // HTML comment injection defanging
    sanitized = sanitized.replace(/<!--/g, '&lt;!--').replace(/-->/g, '--&gt;');
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
