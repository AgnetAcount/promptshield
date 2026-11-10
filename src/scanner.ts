import { DEFAULT_RULES } from './rules/index.js';
import type { RiskLevel, ScanOptions, ScanResult, Violation } from './types.js';

const SEVERITY_ORDER: Record<RiskLevel, number> = {
  SAFE: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

/**
 * Ultra-fast heuristic scanner for prompt injections, jailbreaks, delimiters, and data exfiltration.
 * Target execution time is <1ms for typical prompt inputs.
 */
export function scanPrompt(text: string, options: ScanOptions = {}): ScanResult {
  const startTime = performance.now();

  if (!text || typeof text !== 'string' || text.trim().length === 0) {
    const elapsed = performance.now() - startTime;
    return {
      safe: true,
      riskScore: 0,
      riskLevel: 'SAFE',
      violations: [],
      scanTimeMs: Math.round(elapsed * 1000) / 1000,
      textLength: text ? text.length : 0,
    };
  }

  const {
    threshold = 25,
    categories,
    disabledRules = [],
    customRules = [],
  } = options;

  const rulesToRun = [...DEFAULT_RULES, ...customRules].filter((rule) => {
    if (disabledRules.includes(rule.id)) return false;
    if (categories && categories.length > 0 && !categories.includes(rule.category)) return false;
    return true;
  });

  const violations: Violation[] = [];

  for (const rule of rulesToRun) {
    const hits = rule.check(text, options);
    if (hits && hits.length > 0) {
      for (const hit of hits) {
        if (!disabledRules.includes(hit.ruleId)) {
          violations.push(hit);
        }
      }
    }
  }

  // Deduplicate violations by ruleId if needed
  const uniqueViolations: Violation[] = [];
  const seenRuleIds = new Set<string>();
  for (const v of violations) {
    if (!seenRuleIds.has(v.ruleId)) {
      seenRuleIds.add(v.ruleId);
      uniqueViolations.push(v);
    }
  }

  const elapsed = performance.now() - startTime;
  const scanTimeMs = Math.round(elapsed * 1000) / 1000;
  const textLength = text.length;

  if (uniqueViolations.length === 0) {
    return {
      safe: true,
      riskScore: 0,
      riskLevel: 'SAFE',
      violations: [],
      scanTimeMs,
      textLength,
    };
  }

  // Determine highest severity
  let highestSeverity: RiskLevel = 'LOW';
  for (const v of uniqueViolations) {
    if (SEVERITY_ORDER[v.severity] > SEVERITY_ORDER[highestSeverity]) {
      highestSeverity = v.severity;
    }
  }

  // Calculate composite risk score
  // Highest rule score + damped sum of remaining violations
  const sortedScores = uniqueViolations.map((v) => v.score).sort((a, b) => b - a);
  let compositeScore = sortedScores[0];
  for (let i = 1; i < sortedScores.length; i++) {
    compositeScore += (sortedScores[i] * 0.15); // Additive damping
  }
  compositeScore = Math.round(compositeScore);

  // Calibrate score within severity bounds
  if (highestSeverity === 'CRITICAL') {
    compositeScore = Math.min(100, Math.max(80, compositeScore));
  } else if (highestSeverity === 'HIGH') {
    compositeScore = Math.min(79, Math.max(50, compositeScore));
  } else if (highestSeverity === 'MEDIUM') {
    compositeScore = Math.min(49, Math.max(25, compositeScore));
  } else if (highestSeverity === 'LOW') {
    compositeScore = Math.min(24, Math.max(10, compositeScore));
  }

  const isSafe = compositeScore < threshold && highestSeverity === 'SAFE';

  return {
    safe: isSafe,
    riskScore: compositeScore,
    riskLevel: highestSeverity,
    violations: uniqueViolations,
    scanTimeMs,
    textLength,
  };
}
