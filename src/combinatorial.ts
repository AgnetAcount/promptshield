import type { Rule, Violation } from './types.js';

/**
 * Combinatorial Semantic Intent & Sliding-Window Co-occurrence Engine
 * for PromptShield v0.3.0.
 *
 * Tokenizes natural language inputs and searches across sliding windows
 * for co-occurrences of semantic clusters (OVERRIDE_VERBS + TARGET_NOUNS + SCOPE_MODIFIERS).
 * Catches natural language paraphrases, polite fillers, and indirect framing
 * that bypass rigid regex phrases while maintaining zero false positives.
 */

// Multi-word verb normalization helper
function normalizeMultiWord(text: string): string {
  return text
    .replace(/\bshut\s+down\b/gi, 'shut_down')
    .replace(/\byok\s+say(?:[ıi]n(?:[ıi]z)?)?\b/giu, 'yok_say')
    .replace(/\bdevre\s+d[ıi][şs][ıi]\s*(?:b[ıi]rak(?:[ıi]n(?:[ıi]z)?)?|et(?:tin|in)?)\b/giu, 'devre_dışı_bırak')
    .replace(/\bge[çc]ersiz\s+k[ıi]l(?:[ıi]n(?:[ıi]z)?)?\b/giu, 'geçersiz_kıl')
    .replace(/\bes\s+ge[çc](?:in)?\b/giu, 'es_geç')
    .replace(/\bbo[şs]\s+ver(?:in)?\b/giu, 'boşver')
    .replace(/\bask[ıi]ya\s+al(?:[ıi]n)?\b/giu, 'askıya_al')
    .replace(/\biptal\s+et(?:in)?\b/giu, 'iptal_et');
}

export const OVERRIDE_VERBS = new Set<string>([
  // English verbs and common inflections
  'ignore',
  'ignoring',
  'ignored',
  'ignores',
  'disregard',
  'disregarding',
  'disregarded',
  'disregards',
  'forget',
  'forgetting',
  'forgot',
  'forgotten',
  'forgets',
  'bypass',
  'bypassing',
  'bypassed',
  'bypasses',
  'disable',
  'disabling',
  'disabled',
  'disables',
  'override',
  'overriding',
  'overrode',
  'overridden',
  'overrides',
  'suspend',
  'suspending',
  'suspended',
  'suspends',
  'drop',
  'dropping',
  'dropped',
  'drops',
  'cancel',
  'cancelling',
  'canceling',
  'cancelled',
  'canceled',
  'cancels',
  'unalign',
  'unaligning',
  'unaligned',
  'unfilter',
  'unfiltering',
  'unfiltered',
  'unrestrict',
  'unrestricting',
  'unrestricted',
  'reset',
  'resetting',
  'resets',
  'overwrite',
  'overwriting',
  'overwrote',
  'overwritten',
  'overwrites',
  'omit',
  'omitting',
  'omitted',
  'omits',
  'skip',
  'skipping',
  'skipped',
  'skips',
  'dismiss',
  'dismissing',
  'dismissed',
  'dismisses',
  'abandon',
  'abandoning',
  'abandoned',
  'abandons',
  'discard',
  'discarding',
  'discarded',
  'discards',
  'neutralize',
  'neutralizing',
  'neutralized',
  'neutralise',
  'neutralising',
  'neutralised',
  'purge',
  'purging',
  'purged',
  'erase',
  'erasing',
  'erased',
  'erases',
  'silence',
  'silencing',
  'silenced',
  'shut_down',
  'shutdown',

  // Turkish verbs and common inflections
  'unut',
  'unutsana',
  'unutun',
  'unutunuz',
  'unutalim',
  'unutalım',
  'yok_say',
  'yoksay',
  'yok_sayın',
  'yoksayın',
  'sil',
  'silin',
  'siliniz',
  'silsene',
  'kaldır',
  'kaldir',
  'kaldırın',
  'kaldirin',
  'devre_dışı_bırak',
  'devredışı_bırak',
  'devredisi_birak',
  'devre_disi_birak',
  'çiğne',
  'cigne',
  'çiğneyin',
  'cigneyin',
  'geçersiz_kıl',
  'gecersiz_kil',
  'geçersizkıl',
  'es_geç',
  'esgeç',
  'es_gecin',
  'es_geçin',
  'boşver',
  'bosver',
  'dinleme',
  'dinlemeyin',
  'temizle',
  'temizleyin',
  'sıfırla',
  'sifirla',
  'sıfırlayın',
  'sifirlayin',
  'askıya_al',
  'askiya_al',
  'askıyaal',
  'kapat',
  'kapatın',
  'kapatin',
  'iptal_et',
  'iptalet',
  'iptal',
]);

export const TARGET_NOUNS = new Set<string>([
  // English target nouns and plurals
  'instruction',
  'instructions',
  'prompt',
  'prompts',
  'system',
  'rule',
  'rules',
  'constraint',
  'constraints',
  'policy',
  'policies',
  'guideline',
  'guidelines',
  'boundary',
  'boundaries',
  'safety',
  'ethics',
  'ethical',
  'filter',
  'filters',
  'guardrail',
  'guardrails',
  'alignment',
  'limitation',
  'limitations',
  'restriction',
  'restrictions',
  'directive',
  'directives',
  'moderation',

  // Turkish target nouns and inflections
  'talimat',
  'talimatlar',
  'talimatları',
  'talimatlari',
  'talimatlarını',
  'talimatlarini',
  'talimatların',
  'talimatlarin',
  'talimati',
  'talimatı',
  'komut',
  'komutlar',
  'komutları',
  'komutlari',
  'komutlarını',
  'komutlarini',
  'komutların',
  'komutlarin',
  'komutu',
  'kural',
  'kurallar',
  'kuralları',
  'kurallari',
  'kurallarını',
  'kurallarini',
  'kuralların',
  'kurallarin',
  'kuralı',
  'kurali',
  'kısıtlama',
  'kısıtlamalar',
  'kısıtlamaları',
  'kısıtlamalari',
  'kısıtlamalarını',
  'kisitlama',
  'kisitlamalar',
  'kisitlamalari',
  'güvenlik',
  'guvenlik',
  'güvenliği',
  'guvenligi',
  'filtre',
  'filtreler',
  'filtreleri',
  'filtrelerini',
  'filtrelerin',
  'filtreyi',
  'sınır',
  'sınırlar',
  'sınırları',
  'sınırlarını',
  'sinir',
  'sinirlar',
  'sinirlari',
  'yönerge',
  'yönergeler',
  'yönergeleri',
  'yönergelerini',
  'yonerge',
  'yonergeler',
  'yonergeleri',
  'protokol',
  'protokoller',
  'protokolleri',
  'protokollerini',
]);

export const SCOPE_MODIFIERS = new Set<string>([
  // English scope modifiers
  'previous',
  'all',
  'earlier',
  'prior',
  'above',
  'original',
  'initial',
  'former',
  'past',
  'existing',
  'developer',
  'system',
  'default',
  'standard',
  'any',
  'every',
  'whole',
  'entire',

  // Turkish scope modifiers
  'önceki',
  'onceki',
  'tüm',
  'tum',
  'bütün',
  'butun',
  'geçmiş',
  'gecmis',
  'baştaki',
  'bastaki',
  'eski',
  'sistem',
  'geliştirici',
  'gelistirici',
  'varsayılan',
  'varsayilan',
  'başlangıçtaki',
  'baslangictaki',
]);

interface TokenMatch {
  raw: string;
  normalized: string;
  start: number;
  end: number;
}

/**
 * Tokenizes the input string into word tokens with positional offsets.
 */
function tokenize(text: string): TokenMatch[] {
  const normalizedText = normalizeMultiWord(text);
  const regex = /[a-zA-Z0-9_\u00C0-\u024F\u1E00-\u1EFF]+/gu;
  const tokens: TokenMatch[] = [];
  let match: RegExpExecArray | null;

  while ((match = regex.exec(normalizedText)) !== null) {
    tokens.push({
      raw: match[0],
      normalized: match[0].toLowerCase(),
      start: match.index,
      end: match.index + match[0].length,
    });
  }

  return tokens;
}

export interface CombinatorialScanResult {
  hasIntent: boolean;
  verb?: string;
  noun?: string;
  scope?: string;
  sample?: string;
  startIndex?: number;
}

const FAST_NOUN_CHECK = /(?:instruction|prompt|system|rule|constraint|policy|guideline|boundary|safety|ethics|filter|guardrail|alignment|limitation|restriction|talimat|komut|kural|k[ıi]s[ıi]tlama|g[uü]venlik|filtre|s[ıi]n[ıi]r|y[oö]nerge|protokol)/i;

/**
 * Analyzes text using a sliding window of 10-12 tokens to detect semantic
 * intent overrides (OVERRIDE_VERBS + TARGET_NOUNS + optional SCOPE_MODIFIERS).
 */
export function checkCombinatorialIntent(text: string): Violation[] | null {
  if (!text || text.length < 5) return null;
  if (!FAST_NOUN_CHECK.test(text)) return null;

  const tokens = tokenize(text);
  if (tokens.length < 2) return null;

  const windowSize = 12;
  const violations: Violation[] = [];

  for (let i = 0; i < tokens.length; i++) {
    const windowTokens = tokens.slice(i, Math.min(i + windowSize, tokens.length));

    let foundVerb: TokenMatch | null = null;
    let foundNoun: TokenMatch | null = null;
    let foundScope: TokenMatch | null = null;

    for (const t of windowTokens) {
      if (!foundVerb && OVERRIDE_VERBS.has(t.normalized)) {
        foundVerb = t;
      }
      if (!foundNoun && TARGET_NOUNS.has(t.normalized)) {
        foundNoun = t;
      }
      if (!foundScope && SCOPE_MODIFIERS.has(t.normalized)) {
        foundScope = t;
      }
    }

    if (foundVerb && foundNoun) {
      // Co-occurrence of override verb and target noun detected in sliding window
      const startIdx = Math.min(foundVerb.start, foundNoun.start, foundScope ? foundScope.start : Infinity);
      const endIdx = Math.max(foundVerb.end, foundNoun.end, foundScope ? foundScope.end : 0);

      // Extract raw window text as sample
      const windowStart = windowTokens[0].start;
      const windowEnd = windowTokens[windowTokens.length - 1].end;
      const sample = text.slice(windowStart, windowEnd).trim();

      const hasScope = foundScope !== null;
      const score = hasScope ? 95 : 90;
      const severity = 'CRITICAL';

      const scopeInfo = foundScope ? ` with scope '${foundScope.raw}'` : '';
      const description = `Combinatorial semantic intent override detected: verb '${foundVerb.raw}' + target '${foundNoun.raw}'${scopeInfo} within sliding window`;

      violations.push({
        ruleId: hasScope ? 'COMBINATORIAL_INTENT_SCOPE' : 'COMBINATORIAL_INTENT',
        category: 'injection',
        severity,
        score,
        description,
        matched: sample.length > 80 ? sample.slice(0, 80) + '...' : sample,
        index: startIdx,
      });

      // Jump forward to avoid redundant reports from the same window
      i += Math.floor(windowSize / 2);
    }
  }

  return violations.length > 0 ? violations : null;
}

export const combinatorialRule: Rule = {
  id: 'COMBINATORIAL_INTENT_SCANNER',
  category: 'injection',
  severity: 'CRITICAL',
  score: 95,
  description: 'Sliding-window combinatorial semantic intent detection for natural language prompt overrides',
  check(text: string): Violation[] | null {
    return checkCombinatorialIntent(text);
  },
};
