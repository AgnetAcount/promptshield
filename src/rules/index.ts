import { injectionRule } from './injections.js';
import { roleHijackingRule } from './roleHijacking.js';
import { indirectRule } from './indirect.js';
import { toolAbuseRule } from './toolAbuse.js';
import { multilingualRule } from './multilingual.js';
import { exfiltrationRule } from './exfiltration.js';
import { obfuscationRule } from './obfuscation.js';
import { delimiterRule } from './delimiters.js';
import { contextManipulationRule } from './contextManipulation.js';
import { combinatorialRule } from '../combinatorial.js';
import type { Rule } from '../types.js';

export { injectionRule } from './injections.js';
export { roleHijackingRule } from './roleHijacking.js';
export { indirectRule } from './indirect.js';
export { toolAbuseRule } from './toolAbuse.js';
export { multilingualRule } from './multilingual.js';
export { exfiltrationRule } from './exfiltration.js';
export { obfuscationRule } from './obfuscation.js';
export { delimiterRule } from './delimiters.js';
export { contextManipulationRule } from './contextManipulation.js';
export { combinatorialRule } from '../combinatorial.js';

export const DEFAULT_RULES: Rule[] = [
  injectionRule,
  combinatorialRule,
  roleHijackingRule,
  indirectRule,
  toolAbuseRule,
  multilingualRule,
  delimiterRule,
  exfiltrationRule,
  obfuscationRule,
  contextManipulationRule,
];
