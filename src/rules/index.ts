import { injectionRule } from './injections.js';
import { exfiltrationRule } from './exfiltration.js';
import { obfuscationRule } from './obfuscation.js';
import { delimiterRule } from './delimiters.js';
import type { Rule } from '../types.js';

export { injectionRule } from './injections.js';
export { exfiltrationRule } from './exfiltration.js';
export { obfuscationRule } from './obfuscation.js';
export { delimiterRule } from './delimiters.js';

export const DEFAULT_RULES: Rule[] = [
  injectionRule,
  delimiterRule,
  exfiltrationRule,
  obfuscationRule,
];
