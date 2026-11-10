export { scanPrompt } from './scanner.js';
export { sanitizePrompt } from './sanitizer.js';
export {
  DEFAULT_RULES,
  injectionRule,
  exfiltrationRule,
  obfuscationRule,
  delimiterRule,
} from './rules/index.js';

export type {
  RiskLevel,
  ViolationCategory,
  Violation,
  ScanResult,
  Rule,
  ScanOptions,
  SanitizeOptions,
} from './types.js';
