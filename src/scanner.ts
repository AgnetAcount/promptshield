import { DEFAULT_RULES } from './rules/index.js';
import { normalizeAndDecode } from './normalizer.js';
import { evaluateContext } from './context.js';
import type { RiskLevel, ScanOptions, ScanResult, Violation } from './types.js';

const SEVERITY_ORDER: Record<RiskLevel, number> = {
  SAFE: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

/**
 * Enterprise Hardened heuristic scanner for PromptShield v0.2.0.
 * Incorporates recursive multi-format decoding, multilingual engines,
 * context & intent false positive suppression, and sub-millisecond execution.
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
      isEducationalContext: false,
    };
  }

  const {
    threshold = 25,
    categories,
    disabledRules = [],
    customRules = [],
    enableRecursiveDecoding = true,
    enableContextAnalysis = true,
    maxDecodeDepth = 3,
  } = options;

  const rulesToRun = [...DEFAULT_RULES, ...customRules].filter((rule) => {
    if (disabledRules.includes(rule.id)) return false;
    if (categories && categories.length > 0 && !categories.includes(rule.category)) return false;
    return true;
  });

  // 1. Normalization & Recursive Decoding Layer
  const normResult = enableRecursiveDecoding
    ? normalizeAndDecode(text, maxDecodeDepth)
    : {
        original: text,
        normalized: text,
        decodedLayers: [],
        allVariants: [text],
        hasHomoglyphs: false,
        hasZeroWidth: false,
        hasEncoding: false,
        detectedEncodings: [],
      };

  const violations: Violation[] = [];
  const seenRuleIds = new Set<string>();

  // Pass 1: Scan original text
  for (const rule of rulesToRun) {
    const hits = rule.check(text, options);
    if (hits && hits.length > 0) {
      for (const hit of hits) {
        if (!disabledRules.includes(hit.ruleId) && !seenRuleIds.has(hit.ruleId)) {
          seenRuleIds.add(hit.ruleId);
          violations.push(hit);
        }
      }
    }
  }

  // Pass 2: Multi-pass scan on normalized and decoded layers (if any)
  if (normResult.allVariants.length > 1) {
    for (const variant of normResult.allVariants) {
      if (variant === text) continue;
      for (const rule of rulesToRun) {
        const hits = rule.check(variant, options);
        if (hits && hits.length > 0) {
          for (const hit of hits) {
            if (!disabledRules.includes(hit.ruleId) && !seenRuleIds.has(hit.ruleId)) {
              seenRuleIds.add(hit.ruleId);
              violations.push({
                ...hit,
                description: `[Decoded/Normalized Layer] ${hit.description}`,
              });
            }
          }
        }
      }
    }
  }

  // 2. Context & Intent Analysis (False Positive Reduction)
  let isEducationalContext = false;
  let activeViolations = violations;

  if (enableContextAnalysis && violations.length > 0) {
    const contextEval = evaluateContext(text, violations);
    if (contextEval.isEducationalContext) {
      isEducationalContext = true;
      activeViolations = contextEval.adjustedViolations;
    }
  }

  const elapsed = performance.now() - startTime;
  const scanTimeMs = Math.round(elapsed * 1000) / 1000;
  const textLength = text.length;

  if (activeViolations.length === 0) {
    return {
      safe: true,
      riskScore: 0,
      riskLevel: 'SAFE',
      violations: [],
      scanTimeMs,
      textLength,
      isEducationalContext,
      normalizedText: normResult.normalized,
      decodedLayersCount: normResult.decodedLayers.length,
    };
  }

  // Determine highest severity
  let highestSeverity: RiskLevel = 'LOW';
  for (const v of activeViolations) {
    if (SEVERITY_ORDER[v.severity] > SEVERITY_ORDER[highestSeverity]) {
      highestSeverity = v.severity;
    }
  }

  // Calculate composite risk score (Highest rule score + damped sum of remaining violations)
  const sortedScores = activeViolations.map((v) => v.score).sort((a, b) => b - a);
  let compositeScore = sortedScores[0];
  for (let i = 1; i < sortedScores.length; i++) {
    compositeScore += sortedScores[i] * 0.15; // Additive damping
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
    violations: activeViolations,
    scanTimeMs,
    textLength,
    isEducationalContext,
    normalizedText: normResult.normalized,
    decodedLayersCount: normResult.decodedLayers.length,
  };
}
