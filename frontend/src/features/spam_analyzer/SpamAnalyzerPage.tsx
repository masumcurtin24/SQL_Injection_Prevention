// File: frontend/src/features/spam_analyzer/SpamAnalyzerPage.tsx

import React, { useState } from 'react';
import { ChevronDown, Info, MailCheck, ShieldAlert, Sparkles } from 'lucide-react';
import {
  analyzeSpam,
  createStepUpToken,
  submitSpamFeedback,
  getSpamSettings,
  uploadSpamBlocklist,
  updateSpamSettings,
} from '../../lib/apiClient';
import { useNotification } from '../../contexts/useNotification';
import type { SpamAnalysisResponse } from '../../types/api';
import ExplainabilityPanel from '../../components/common/ExplainabilityPanel';

type ScoreBreakdownKey =
  | 'final'
  | 'raw_fused'
  | 'classical'
  | 'transformer'
  | 'online'
  | 'heuristic'
  | 'reputation'
  | 'campaign'
  | 'fraud_pattern'
  | 'bec_fraud'
  | 'courier_phishing'
  | 'ood';

type ScoreTermDefinition = {
  label: string;
  summary: string;
  operation: string;
  equation: string;
  methodology: string;
  codePath: string;
};

const SCORE_BREAKDOWN_ORDER: ScoreBreakdownKey[] = [
  'final',
  'raw_fused',
  'classical',
  'transformer',
  'online',
  'heuristic',
  'reputation',
  'campaign',
  'fraud_pattern',
  'bec_fraud',
  'courier_phishing',
  'ood',
];

const SCORE_TERM_DEFINITIONS: Record<ScoreBreakdownKey, ScoreTermDefinition> = {
  final: {
    label: 'Final risk',
    summary:
      'The final calibrated score represents spam/phishing risk. Decision confidence is derived from the selected class; uncertainty and AI reliability are separate review controls.',
    operation:
      'Starts from the raw fused ensemble score, applies logistic calibration, then raises the score with policy floor rules when hard evidence is present.',
    equation:
      'calibrated = sigmoid(a * raw_fused + b)\nspam_score = clamp01(max(calibrated, applicable_floor_rules))\nbase_confidence = spam_score for spam/phishing decisions; 1 - spam_score for safe decisions\ndecision_confidence = clamp01(base_confidence)',
    methodology:
      'Calibrated late-fusion ensemble with policy thresholds and guardrail floors for blocklists, campaign/fraud/header hard signals, strong classical evidence, and OOD review.',
    codePath: 'SpamDetectionService.analyze_email -> _fuse_component_scores -> final policy floor rules',
  },
  raw_fused: {
    label: 'Raw fused',
    summary: 'Weighted average of available component scores before calibration and policy floors.',
    operation:
      'Normalizes each available component to 0..1, ignores missing or zero-weight components, then divides weighted numerator terms by total active weight.',
    equation: 'raw_fused = sum(w_i * s_i) / sum(w_i), for every available component i',
    methodology:
      'Weighted late fusion. Weights come from prevention_rules.yml overrides or SPAM_W_* environment defaults.',
    codePath: 'SpamDetectionService._fuse_component_scores',
  },
  classical: {
    label: 'Classical',
    summary: 'Probability from the persisted classical spam model.',
    operation:
      'Preprocesses the subject/body text, runs the joblib-loaded spam pipeline, and reads the spam-class probability.',
    equation: 'classical = predict_proba(preprocess(subject + body))[spam_class_index]',
    methodology:
      'Classical probabilistic ML pipeline loaded from disk with joblib, typically a vectorizer plus classifier.',
    codePath: 'SpamDetectionService.analyze_email -> _preprocess_email_text_for_spam -> predict_proba',
  },
  transformer: {
    label: 'Transformer',
    summary: 'Semantic spam/phishing probability from the optional transformer model.',
    operation:
      'Scores subject, body, and URL text separately, normalizes labels into malicious probability, then blends the available segments.',
    equation:
      'transformer = sum(segment_weight * malicious_probability_segment) / sum(segment_weight_used)\nsegment weights: subject=0.25, body=0.55, urls=0.20',
    methodology:
      'HuggingFace text-classification transformer configured by SPAM_TRANSFORMER_MODEL. If unavailable, this component is omitted from fusion.',
    codePath: 'SpamDetectionService._transformer_semantic_score',
  },
  online: {
    label: 'Online',
    summary: 'Probability from the feedback-trained online learner.',
    operation:
      'Loads the persisted online learner, scores the current subject/body text, and uses the spam-class probability when the model exists.',
    equation: 'online = online_model.predict_proba([subject + body])[spam_class_index]',
    methodology:
      'HashingVectorizer plus SGDClassifier(loss=log_loss), updated by analyst feedback through the spam feedback API.',
    codePath: 'SpamDetectionService._load_online_model -> predict_proba',
  },
  heuristic: {
    label: 'Heuristic',
    summary: 'Rule-based URL, sender-risk, and deterministic BEC heuristic score.',
    operation:
      'Adds weighted risk increments for suspicious URL, reputation, sender indicators, and targeted BEC/fraud patterns, then caps the score.',
    equation:
      'heuristic = max(url_sender_heuristic, bec_heuristic_floor)\nurl_sender_heuristic = min(0.99, URL/reputation/sender addends)\nbec_heuristic_floor applies only when multi-condition BEC rules match',
    methodology:
      'Deterministic phishing heuristics over extracted URLs, domain reputation, sender encoding, sender IP use, sender/link mismatch, and targeted BEC categories.',
    codePath: 'SpamDetectionService._heuristic_phishing_score -> detect_business_email_compromise_signals',
  },
  reputation: {
    label: 'Reputation',
    summary: 'Domain reputation risk score from URL destinations.',
    operation:
      'Scores every URL host against allowlist, blocklist, reputation map, and lexical domain risk, then keeps the strongest URL reputation signal.',
    equation:
      'domain_score(host) = 0 if allowlisted; 1 if blocklisted; reputation_map[host/base] if present; otherwise lexical_domain_risk(host)\nreputation = clamp01(max(url_reputation_avg, url_reputation_max, blocklisted_count > 0 ? 1 : 0))',
    methodology:
      'Reputation lookup with lexical fallback using suspicious domain structure, digits, hyphens, entropy, punycode, and length.',
    codePath: 'SpamDetectionService._domain_reputation_score -> analyze_email reputation_score',
  },
  campaign: {
    label: 'Campaign',
    summary: 'Social-engineering campaign pattern score.',
    operation:
      'Matches normalized subject/body text against curated campaign regex patterns, sums matched weights, then adds contextual bonuses for high-risk combinations.',
    equation:
      'campaign = min(0.99, sum(matched_pattern_weights) + contextual_bonuses)\nbonuses include: +0.25 credential lure with link, +0.24 collaboration credential lure with link, +0.30 money request with link, +0.15 multi-theme, +0.12 high-risk theme with link, +0.12 text-only high-risk, +0.05 sensitive sender role',
    methodology:
      'Curated social-engineering pattern library covering credential harvest, urgency, finance/BEC, delivery, government, tech-support, crypto, MFA, malware lure, scam, and payment redirection themes.',
    codePath: 'SpamDetectionService._modern_campaign_pattern_score',
  },
  fraud_pattern: {
    label: 'Fraud pattern',
    summary: 'Curated fraud-pattern score, including deterministic BEC evidence when present.',
    operation:
      'Scores curated fraud-pack patterns and targeted BEC detections, then uses the strongest fraud score as the fraud-pattern fusion component.',
    equation: 'fraud_pattern = max(fraud_pack_score, bec_fraud_score)',
    methodology:
      'Specific fraud/BEC rules require multiple evidence conditions before high-risk floors are applied.',
    codePath: 'SpamDetectionService._fraud_pattern_pack_score -> detect_business_email_compromise_signals',
  },
  bec_fraud: {
    label: 'BEC fraud',
    summary: 'Deterministic business email compromise signal for gift-card, payroll, credential, payment, MFA, QR, and remote-support fraud.',
    operation:
      'Matches category-specific evidence groups. High scores require multiple conditions such as request type, secret/payment context, exfiltration or change intent, and urgency/unavailability.',
    equation: 'bec_fraud = max(category_score) when required evidence groups match; otherwise 0',
    methodology:
      'Targeted deterministic fraud detection with false-positive controls for benign policy, raffle, newsletter, or ordinary invoice language.',
    codePath: 'SpamDetectionService.detect_business_email_compromise_signals',
  },
  courier_phishing: {
    label: 'Courier phishing',
    summary: 'Targeted courier/customs/redelivery phishing score based on brand claim, fee pressure, suspicious link, and domain mismatch evidence.',
    operation:
      'Matches courier identity, customs or redelivery fee lures, urgency/return threats, payment paths, and official-domain mismatch. Routine shipping notices without payment/link pressure stay low risk.',
    equation:
      'courier_phishing = max(category_score) when multiple evidence groups match\nrisk floors: brand + fee + suspicious link >= 0.82; customs + urgency + suspicious link >= 0.85; generic delivery + fee + suspicious link >= 0.75',
    methodology:
      'Deterministic phishing category with official-domain false-positive controls for DHL, FedEx, UPS, USPS, AusPost, StarTrack, Royal Mail, DPD, Evri, and related courier brands.',
    codePath: 'SpamDetectionService.detect_courier_delivery_phishing_signals',
  },
  ood: {
    label: 'OOD',
    summary: 'Out-of-distribution guardrail score.',
    operation:
      'Measures whether the input looks unlike normal model training inputs or has weak/contradictory model evidence.',
    equation:
      'ood = min(0.99,\n  0.22 if token_count < 4\n  + 0.18 if alpha_ratio < 0.35\n  + 0.20 if symbol_ratio > 0.30\n  + 0.10 if unique_token_ratio > 0.95\n  + 0.25 if transformer_uncertainty >= 0.45\n  + 0.22 if abs(classical - transformer) >= 0.50\n  + 0.25 if all model signals missing\n  + 0.10 if no URLs and token_count < 5\n)',
    methodology:
      'Input-distribution and model-agreement guardrail. High OOD can route the result to Suspicious (OOD Review).',
    codePath: 'SpamDetectionService._compute_ood_score',
  },
};

const formatPercent = (value: unknown, digits = 1): string => {
  if (typeof value !== 'number' || !Number.isFinite(value)) return 'N/A';
  return `${(value * 100).toFixed(digits)}%`;
};

const formatScorePercent = (value: unknown): string => {
  if (typeof value !== 'number' || !Number.isFinite(value)) return 'Not used';
  return formatPercent(value);
};

const formatDecimal = (value: unknown, digits = 3): string => {
  if (typeof value !== 'number' || !Number.isFinite(value)) return 'N/A';
  return value.toFixed(digits);
};

const numericValue = (value: unknown): number => {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string' && value.trim()) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : 0;
  }
  return 0;
};

const clamp01 = (value: unknown): number | null => {
  const numeric = typeof value === 'number' ? value : typeof value === 'string' && value.trim() ? Number(value) : NaN;
  if (!Number.isFinite(numeric)) return null;
  return Math.max(0, Math.min(1, numeric));
};

// The calibrated spam_score is malicious-email risk; it is not the same as
// confidence. Benign decisions derive confidence from 1 - spam_score.
const spamSafeLabels = ['safe', 'ham', 'clean', 'benign', 'not_spam', 'not spam', 'legitimate', 'normal', 'allow', 'allowed'];

const spamRiskFor = (result: SpamAnalysisResponse): number => clamp01(result.spam_score) ?? 0;

const decisionConfidenceFor = (result: SpamAnalysisResponse): number => {
  const direct = clamp01(result.decision_confidence);
  if (direct !== null) return direct;

  const explanationConfidence = clamp01(result.explanation?.confidence);
  if (explanationConfidence !== null) return explanationConfidence;

  const spamScore = spamRiskFor(result);
  const label = String(result.classification_label || result.explanation?.decision || (result.is_spam ? 'spam' : 'ham'))
    .trim()
    .toLowerCase();
  return spamSafeLabels.includes(label) || !result.is_spam ? 1 - spamScore : spamScore;
};

const reliabilityFor = (result: SpamAnalysisResponse) => result.ai_reliability || result.explanation?.ai_reliability || null;
const titleize = (value: unknown, fallback = 'Not returned'): string => {
  const text = String(value || '').trim();
  if (!text) return fallback;
  return text.replace(/_/g, ' ').replace(/\b\w/g, (match) => match.toUpperCase());
};

const recommendedHandlingFor = (result: SpamAnalysisResponse): string => {
  const displayHandling = result.decision_display?.recommended_handling;
  if (displayHandling) return displayHandling;
  const reliability = reliabilityFor(result);
  if (reliability?.recommended_handling) return String(reliability.recommended_handling);
  if (String(result.classification_label || '').toLowerCase().includes('phishing')) return 'block';
  return result.is_spam ? 'review' : 'allow';
};

const requiresAnalystReview = (result: SpamAnalysisResponse): boolean => {
  const risk = spamRiskFor(result);
  const confidence = decisionConfidenceFor(result);
  const reliability = reliabilityFor(result);
  const uncertainty = clamp01(result.explanation?.uncertainty_score ?? result.meta_features?.uncertainty_score) ?? 0;
  const ood = clamp01(result.explanation?.ood_score ?? result.meta_features?.ood_score ?? result.score_breakdown?.ood) ?? 0;
  return Boolean(
    result.decision_display?.review_required ||
    reliability?.review_required ||
      reliability?.recommended_handling === 'review' ||
      confidence < 0.7 ||
      (risk >= 0.45 && risk <= 0.65) ||
      uncertainty > 0.4 ||
      ood > 0.35 ||
      reliability?.adversarial_suspicion,
  );
};

const spamStatusMetaFor = (result: SpamAnalysisResponse) => {
  if (result.decision_display) {
    const display = result.decision_display;
    return {
      label: display.status_label,
      description: display.detail || 'Review-aware display policy returned by the backend.',
      color: display.status_color,
      Icon: display.status_color === 'green' ? MailCheck : ShieldAlert,
    };
  }

  const confidence = decisionConfidenceFor(result);
  const reliability = reliabilityFor(result);
  const decision = String(result.explanation?.decision || result.classification_label || '').toUpperCase();
  const blocked = decision.includes('BLOCK') || String(result.classification_label || '').toLowerCase().includes('phishing');

  if (requiresAnalystReview(result)) {
    return {
      label: 'Needs Review — Possible Spam/Phishing',
      description:
        confidence < 0.7
          ? 'Low-confidence or grey-zone result. The system recommends analyst review, not automatic blocking.'
          : reliability?.review_reasons?.[0] || 'The reliability guardrail requires analyst review.',
      color: 'amber' as const,
      Icon: ShieldAlert,
    };
  }

  return {
    label: blocked ? 'High-Risk Phishing Detected' : result.is_spam ? 'Suspicious Message' : 'Not Spam',
    description: 'The score and reliability guardrail support the selected action.',
    color: blocked ? 'red' as const : result.is_spam ? 'amber' as const : 'green' as const,
    Icon: blocked || result.is_spam ? ShieldAlert : MailCheck,
  };
};

const spamSuggestedActionsFor = (result: SpamAnalysisResponse): string[] => {
  if (Array.isArray(result.explanation?.remediation) && result.explanation.remediation.length > 0) {
    return result.explanation.remediation;
  }
  const handling = recommendedHandlingFor(result).toLowerCase();
  if (requiresAnalystReview(result) || handling === 'review') {
    return [
      'Route to analyst review before blocking.',
      'Do not click links or download attachments.',
      'Verify sender/domain independently.',
      'Check headers, URL reputation, and business context.',
      'Do not automatically block sender/domain from this single grey-zone result.',
    ];
  }
  if (handling === 'block') {
    return [
      'Block or quarantine according to policy.',
      'Preserve evidence.',
      'Investigate recipients and similar messages.',
    ];
  }
  if (handling === 'quarantine') {
    return [
      'Quarantine according to configured mail/file policy.',
      'Preserve evidence.',
      'Escalate if related campaign indicators exist.',
    ];
  }
  if (handling === 'monitor') {
    return [
      'Allow but log and monitor.',
      'Review if repeated pattern emerges.',
    ];
  }
  return [
    'No strong indicators found.',
    'Continue normal handling.',
    'Monitor if similar reports appear.',
  ];
};

const yesNo = (value: unknown): string => (value ? 'yes' : 'no');

const listValue = (value: unknown, fallback = 'none'): string => {
  if (Array.isArray(value) && value.length > 0) return value.slice(0, 8).map(String).join(', ');
  if (typeof value === 'string' && value.trim()) return value;
  return fallback;
};

const displayText = (value: unknown, fallback = 'Not provided'): string => {
  if (typeof value === 'string' && value.trim()) return value;
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  return fallback;
};

const firstHostFromText = (value: string): string | null => {
  const match = String(value || '').match(/https?:\/\/([^/\s?#]+)/i);
  return match?.[1]?.replace(/^www\./i, '').toLowerCase() || null;
};

const senderForSample = (label: string, body: string, index: number): string => {
  const lower = label.toLowerCase();
  if (lower.includes('ceo')) return 'Alex <alex.executive@mobile-mail.example>';
  if (lower.includes('mfa') || lower.includes('security')) return 'Security Team <security-alerts@identity-check.example>';
  if (lower.includes('vendor')) return 'Accounts Payable <ap-updates@vendor-payments.example>';
  if (lower.includes('invoice')) return 'Billing Desk <billing@invoice-office.example>';
  const host = firstHostFromText(body);
  if (host) return `Notice Desk <notice@${host}>`;
  return `Demo Sender <sender${index + 1}@security-training.example>`;
};

const traceDetails = (result: SpamAnalysisResponse, stage: string): Record<string, any> | null => {
  const step = result.explanation?.decision_trace?.find((item) => item.stage === stage);
  return step?.details || null;
};

const attributionFor = (result: SpamAnalysisResponse, component: string): Record<string, any> | null => {
  return result.explanation?.model_attributions?.find((item) => item.component === component) || null;
};

const scoreValue = (result: SpamAnalysisResponse, key: ScoreBreakdownKey): number | null => {
  const value = result.score_breakdown?.[key];
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
};

const attributionLine = (result: SpamAnalysisResponse, component: string): string => {
  const attribution = attributionFor(result, component);
  if (!attribution) return 'This component was not returned for this run, so it was ignored by raw fusion.';
  const score = numericValue(attribution.score);
  const weight = numericValue(attribution.weight);
  const fusion = traceDetails(result, 'fusion_calibration');
  const activeWeights = fusion?.used_weights || {};
  const totalWeight = Object.values(activeWeights).reduce((sum: number, value: any) => sum + numericValue(value), 0);
  const numerator = score * weight;
  const normalized = totalWeight > 0 ? numerator / totalWeight : 0;
  return `Fusion input: score ${formatPercent(score)}, weight ${formatDecimal(weight)}, numerator term ${formatDecimal(numerator)}, normalized contribution ${formatDecimal(normalized)}.`;
};

const heuristicAddends = (result: SpamAnalysisResponse): string[] => {
  const indicators = result.url_indicators || {};
  const sender = result.meta_features || {};
  const addends: string[] = [];
  const totalUrls = numericValue(indicators.total_urls);
  const extraUrlScore = Math.min(0.22, 0.04 * Math.max(0, totalUrls - 1));
  if (extraUrlScore > 0) addends.push(`extra URLs +${formatDecimal(extraUrlScore)}`);
  if (numericValue(indicators.unique_hosts) >= 2) addends.push('unique hosts +0.080');
  if (numericValue(indicators.ip_urls) > 0) addends.push('IP URL +0.180');
  if (numericValue(indicators.suspicious_tlds) > 0) addends.push('suspicious TLD +0.170');
  if (numericValue(indicators.punycode) > 0) addends.push('punycode URL +0.180');
  if (numericValue(indicators.blocklisted_count) > 0) addends.push('blocklisted URL +0.350');
  if (numericValue(indicators.reputation_high) > 0) addends.push('high reputation risk +0.280');
  if (numericValue(indicators.reputation_medium) > 0) addends.push('medium reputation risk +0.120');
  if (numericValue(indicators.shortened_urls) > 0) addends.push('shortened URL +0.100');
  if (numericValue(indicators.non_standard_ports) > 0) addends.push('non-standard port +0.080');
  if (numericValue(indicators.encoded_url_count) > 0) addends.push('encoded URL +0.050');
  if (numericValue(indicators.excessive_subdomains) > 0) addends.push('excessive subdomains +0.080');
  const reputationAvgAddend = Math.min(0.12, numericValue(indicators.reputation_score_avg) * 0.12);
  if (reputationAvgAddend > 0) addends.push(`average reputation +${formatDecimal(reputationAvgAddend)}`);
  if (sender.punycode) addends.push('punycode sender +0.100');
  if (sender.ip_sender) addends.push('IP sender +0.120');
  if (sender.domain_mismatch_with_urls) addends.push('sender/link mismatch +0.140');
  const senderRepAddend = Math.min(0.10, numericValue(sender.sender_reputation_score) * 0.10);
  if (senderRepAddend > 0) addends.push(`sender reputation +${formatDecimal(senderRepAddend)}`);
  const becFloor = numericValue(sender.bec_risk_floor);
  if (numericValue(sender.bec_fraud_score) > 0) {
    addends.push(`BEC fraud heuristic floor ${formatPercent(numericValue(result.score_breakdown?.heuristic))}`);
  }
  if (numericValue(sender.courier_phishing_score) > 0) {
    addends.push(`courier phishing score ${formatPercent(numericValue(sender.courier_phishing_score))}`);
  }
  if (sender.brand_domain_mismatch) addends.push('courier brand/link mismatch');
  if (sender.suspicious_payment_link) addends.push('non-official courier payment link');
  if (becFloor > 0) addends.push(`BEC risk floor ${formatPercent(becFloor)}`);
  return addends;
};

const fraudCategoryFor = (result: SpamAnalysisResponse): string => {
  return String(result.meta_features?.fraud_category_label || result.meta_features?.fraud_category || result.score_breakdown?.fraud_category || '').trim();
};

const fraudEvidenceFor = (result: SpamAnalysisResponse): string[] => {
  const reasons = result.meta_features?.bec_evidence_reasons;
  return Array.isArray(reasons) ? reasons.map((item) => String(item)).filter(Boolean) : [];
};

const courierEvidenceFor = (result: SpamAnalysisResponse): string[] => {
  const reasons = result.meta_features?.courier_evidence_reasons;
  return Array.isArray(reasons) ? reasons.map((item) => String(item)).filter(Boolean) : [];
};

const handlingDisplayFor = (result: SpamAnalysisResponse): string => {
  const handling = recommendedHandlingFor(result).toLowerCase();
  const actions = Array.isArray(result.defender_actions) ? result.defender_actions : [];
  if (handling === 'block' && actions.includes('block_request')) return 'Block Request';
  return titleize(handling);
};

const currentScoreDetails = (result: SpamAnalysisResponse, key: ScoreBreakdownKey): string[] => {
  const lines = [`Displayed score: ${formatScorePercent(scoreValue(result, key))}.`];
  const fusion = traceDetails(result, 'fusion_calibration');
  const features = traceDetails(result, 'feature_extraction');
  const thresholds = result.score_breakdown?.thresholds || result.explanation?.thresholds || {};

  if (key === 'final') {
    const calibration = fusion?.calibration || {};
    lines.push(`Calibration in use: a=${formatDecimal(calibration.a)}, b=${formatDecimal(calibration.b)}.`);
    lines.push(`Thresholds: allow ${formatPercent(thresholds.allow)}, suspicious ${formatPercent(thresholds.suspicious)}, block ${formatPercent(thresholds.block)}, OOD ${formatPercent(thresholds.ood)}.`);
    lines.push(`Hard signals: blocklist ${yesNo(result.score_breakdown?.hard_block_signal)}, campaign ${yesNo(result.score_breakdown?.campaign_hard_signal)}, fraud pattern ${yesNo(result.score_breakdown?.fraud_pattern_hard_signal)}, header ${yesNo(result.score_breakdown?.header_hard_signal)}.`);
    lines.push(`Decision returned by explanation: ${result.explanation?.decision || result.classification_label || 'N/A'}.`);
    lines.push(`Decision confidence: ${formatPercent(decisionConfidenceFor(result))}; spam/phishing risk remains ${formatPercent(spamRiskFor(result))}.`);
  }

  if (key === 'raw_fused') {
    const components = fusion?.components || {};
    const weights = fusion?.used_weights || {};
    const activeComponents = Object.keys(components);
    const totalActiveWeight = activeComponents.reduce((sum, name) => sum + numericValue(weights[name]), 0);
    if (activeComponents.length > 0) {
      lines.push(`Total active weight: ${formatDecimal(totalActiveWeight)}.`);
      activeComponents.forEach((name) => {
        const score = numericValue(components[name]);
        const weight = numericValue(weights[name]);
        const numerator = score * weight;
        const normalized = totalActiveWeight > 0 ? numerator / totalActiveWeight : 0;
        lines.push(`${name}: score ${formatPercent(score)}, weight ${formatDecimal(weight)}, numerator term ${formatDecimal(numerator)}, normalized contribution ${formatDecimal(normalized)}.`);
      });
    }
    lines.push('Header and fraud_pattern can participate in raw fusion when the backend returns those scores, even though the compact list shows the professor-requested terms.');
  }

  if (key === 'classical') lines.push(attributionLine(result, 'classical'));

  if (key === 'transformer') {
    lines.push(attributionLine(result, 'transformer'));
    const transformerSegments = features?.transformer_semantics?.segments || [];
    if (Array.isArray(transformerSegments) && transformerSegments.length > 0) {
      lines.push(
        `Segments: ${transformerSegments
          .map((item: any) => `${item.segment} score ${formatPercent(item.score)} weight ${formatDecimal(item.weight)}`)
          .join('; ')}.`
      );
    } else if (result.meta_features?.transformer_confidence !== undefined) {
      lines.push(`Transformer confidence: ${formatPercent(result.meta_features.transformer_confidence)}.`);
    }
  }

  if (key === 'online') lines.push(attributionLine(result, 'online'));

  if (key === 'heuristic') {
    lines.push(attributionLine(result, 'heuristic'));
    const addends = heuristicAddends(result);
    lines.push(addends.length > 0 ? `Non-zero addends: ${addends.join('; ')}.` : 'No URL/sender heuristic addends were triggered.');
  }

  if (key === 'reputation') {
    lines.push(attributionLine(result, 'reputation'));
    const indicators = result.url_indicators || {};
    lines.push(`URL reputation avg ${formatPercent(indicators.reputation_score_avg)}, max ${formatPercent(indicators.reputation_score_max)}, blocklisted count ${String(indicators.blocklisted_count ?? 0)}.`);
    lines.push(`Hosts: ${listValue(indicators.hosts)}.`);
    lines.push(`Reputation sources: ${listValue(indicators.reputation_sources)}.`);
  }

  if (key === 'campaign') {
    lines.push(attributionLine(result, 'campaign'));
    const campaign = features?.campaign_patterns || {};
    const matches = Array.isArray(campaign.matches) ? campaign.matches : [];
    lines.push(`Themes: ${listValue(campaign.themes)}.`);
    if (matches.length > 0) {
      lines.push(
        `Matched addends: ${matches
          .map((item: any) => `${item.id || item.label}${typeof item.weight === 'number' ? ` +${formatDecimal(item.weight)}` : ''}`)
          .join('; ')}.`
      );
    } else {
      lines.push(`Matched campaign IDs: ${listValue(result.meta_features?.campaign_match_ids)}.`);
    }
  }

  if (key === 'fraud_pattern') {
    lines.push(attributionLine(result, 'fraud_pattern'));
    lines.push(`Fraud category: ${fraudCategoryFor(result) || 'N/A'}.`);
    lines.push(`Matched BEC patterns: ${listValue(result.meta_features?.bec_matched_patterns)}.`);
    const reasons = fraudEvidenceFor(result);
    if (reasons.length > 0) lines.push(`Evidence reasons: ${reasons.join('; ')}.`);
  }

  if (key === 'bec_fraud') {
    lines.push(`Fraud category: ${fraudCategoryFor(result) || 'N/A'}.`);
    lines.push(`BEC fraud score: ${formatPercent(result.meta_features?.bec_fraud_score ?? result.score_breakdown?.bec_fraud)}.`);
    lines.push(`Applied risk floor: ${formatPercent(result.meta_features?.bec_risk_floor ?? result.score_breakdown?.bec_risk_floor)}.`);
    const reasons = fraudEvidenceFor(result);
    lines.push(reasons.length > 0 ? `Evidence reasons: ${reasons.join('; ')}.` : 'No deterministic BEC fraud category was returned.');
  }

  if (key === 'courier_phishing') {
    lines.push(`Courier category: ${displayText(result.meta_features?.courier_category, 'N/A')}.`);
    lines.push(`Claimed brand: ${displayText(result.meta_features?.claimed_brand, 'N/A')}.`);
    lines.push(`Link domains: ${listValue(result.meta_features?.courier_link_domains)}.`);
    lines.push(`Brand mismatch: ${yesNo(result.meta_features?.brand_domain_mismatch)}; sender mismatch: ${yesNo(result.meta_features?.sender_domain_mismatch)}; payment link: ${yesNo(result.meta_features?.suspicious_payment_link)}.`);
    const reasons = courierEvidenceFor(result);
    lines.push(reasons.length > 0 ? `Evidence reasons: ${reasons.join('; ')}.` : 'No courier/customs fee phishing category was returned.');
  }

  if (key === 'ood') {
    lines.push(`OOD threshold: ${formatPercent(thresholds.ood)}.`);
    lines.push(`Reasons: ${listValue(result.meta_features?.ood_reasons || features?.ood_reasons)}.`);
    const metrics = result.meta_features?.ood_metrics || features?.ood_metrics || {};
    const metricText = Object.entries(metrics)
      .map(([name, value]) => `${name}=${String(value)}`)
      .join(', ');
    if (metricText) lines.push(`Metrics: ${metricText}.`);
  }

  return lines;
};

const ScoreBreakdownDetail: React.FC<{ result: SpamAnalysisResponse; termKey: ScoreBreakdownKey }> = ({
  result,
  termKey,
}) => {
  const definition = SCORE_TERM_DEFINITIONS[termKey];
  const details = currentScoreDetails(result, termKey);

  return (
    <div className="mt-2 rounded-md border border-cyan-500/30 bg-gray-950/50 p-3 text-xs text-gray-300 break-words">
      <p className="mb-3 text-sm text-gray-100">{definition.summary}</p>
      <div className="grid gap-3 md:grid-cols-2">
        <div>
          <p className="mb-1 font-semibold text-cyan-200">Operation</p>
          <p className="leading-relaxed">{definition.operation}</p>
        </div>
        <div>
          <p className="mb-1 font-semibold text-cyan-200">Methodology</p>
          <p className="leading-relaxed">{definition.methodology}</p>
        </div>
      </div>
      <div className="mt-3">
        <p className="mb-1 font-semibold text-cyan-200">Equation</p>
        <pre className="whitespace-pre-wrap break-words rounded bg-black/30 p-2 font-mono text-[11px] leading-relaxed text-gray-200">
          {definition.equation}
        </pre>
      </div>
      <div className="mt-3">
        <p className="mb-1 font-semibold text-cyan-200">Current Analysis</p>
        <ul className="list-disc space-y-1 pl-5">
          {details.map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
      </div>
      <p className="mt-3 text-[11px] text-gray-500">Code path: {definition.codePath}</p>
    </div>
  );
};

const SpamAnalyzerPage: React.FC = () => {
  const [text, setText] = useState('');
  const [result, setResult] = useState<SpamAnalysisResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [selectedSpamSample, setSelectedSpamSample] = useState<number>(0);
  const [selectedScoreTerm, setSelectedScoreTerm] = useState<ScoreBreakdownKey | null>(null);
  const [settings, setSettings] = useState<any | null>(null);
  const [uploading, setUploading] = useState(false);
  const { showNotification } = useNotification();

  const complexSpamSamples: { label: string; text: string; senderEmail?: string }[] = [
    {
      label: "Payroll direct-deposit update",
      text: "Subject: URGENT Payroll Action Required\n\nDear employee,\nOur payroll platform migration failed to sync your direct deposit profile. To avoid delayed salary, verify your banking details by 5 PM today:\nhttps://payroll-verify-secure.com/session/update?id=884271\nFailure to verify may place your account on manual hold.",
    },
    {
      label: "Microsoft 365 password expiry",
      text: "Subject: Microsoft 365 Password Expires Today\n\nYour mailbox quota has reached critical threshold and your password expires in 2 hours. Re-authenticate now to avoid lockout:\nhttp://microsoft-credential-check.com/owa/auth\nThis is an automated message from IT Service Desk.",
    },
    {
      label: "Invoice with macro attachment lure",
      text: "Subject: Overdue Invoice #INV-2026-48117\n\nPlease find attached the revised invoice and remittance form. Open in desktop Office and enable content to view protected payment fields.\nAttachment: Invoice_2026_48117.xlsm\nAccounts payable escalation will proceed if payment is not confirmed today.",
    },
    {
      label: "Courier customs fee phishing",
      text: "Subject: Parcel Held at Customs - Final Notice\n\nYour package cannot be delivered due to unpaid customs handling fee (AUD 3.20).\nPay now: https://fast-post-tracking.net/customs/pay/37291\nIf unpaid within 12 hours, parcel will be returned to sender.",
    },
    {
      label: "HR policy acknowledgement spoof",
      text: "Subject: Mandatory Workplace Policy Acknowledgement\n\nAll staff must sign the updated code-of-conduct document before midnight.\nReview here: https://hr-sharepoint-access.live/policies/ack\nYou may lose system access if acknowledgement is missing.",
    },
    {
      label: "CEO gift card fraud",
      text: "Subject: Quick task before board call\n\nI need you to buy 10 gift cards (200 each) for client incentives. Send photos of card numbers and PINs immediately. I am in a meeting and cannot take calls.\n- Alex (Sent from mobile)",
    },
    {
      label: "MFA fatigue social engineering",
      text: "Subject: Security Validation In Progress\n\nWe detected suspicious login attempts. If you receive repeated MFA prompts, approve the next one to confirm your identity and stop automated lockout. Security team is monitoring this incident.",
    },
    {
      label: "DocuSign impersonation",
      text: "Subject: Document signature required: Vendor Agreement\n\nYou have a pending contract awaiting e-signature.\nOpen secure document: https://docusign-review-center.info/doc/948112\nDocument expires in 30 minutes.",
    },
    {
      label: "High-return crypto investment scam",
      text: "Subject: Exclusive Institutional Crypto Pool Access\n\nYour account is selected for a private arbitrage window with guaranteed 18% weekly ROI. Minimum entry 2,000 USDT.\nRegister wallet now: https://prime-defi-yield.pro/join",
    },
    {
      label: "Tax refund pretext",
      text: "Subject: Tax Authority Refund Available\n\nOur records indicate an overpayment for FY2025. Submit your tax ID and banking confirmation to release refund within 24 hours:\nhttp://tax-refund-fasttrack.online/verify",
    },
    {
      label: "Bank transfer verification scam",
      text: "Subject: Suspicious Transfer Detected\n\nA transfer of AUD 4,980 was initiated from your account. If unauthorized, cancel now:\nhttps://secure-bank-alerts.co/reverse\nIf no action is taken within 15 minutes, transfer will be processed.",
    },
    {
      label: "Voicemail HTML attachment lure",
      text: "Subject: New Voicemail (1 min 42 sec)\n\nYou received a confidential voicemail from executive office.\nAttachment: VoiceMessage_2026-04-01.html\nOpen attachment and sign in to decrypt audio transcript.",
    },
    {
      label: "Team collaboration mention phishing",
      text: "Subject: You were mentioned in Project Delta\n\nAlex tagged you in an urgent comment: 'Can you review the updated credentials sheet now?'\nView comment: https://teams-files-share.work/delta/comment/1902",
    },
    {
      label: "Corporate SSO lockout lure",
      text: "Subject: Enterprise SSO Lockout Prevention\n\nYour SSO token is invalid after recent certificate rotation. Re-establish trust immediately:\nhttps://sso-certificate-sync.com/login\nThis link expires in 20 minutes.",
    },
    {
      label: "Cloud file share credential harvest",
      text: "Subject: Secure file shared with you\n\nA confidential board report has been shared via cloud vault.\nAccess file: https://drive-doc-viewer-secure.net/file/board-q2\nSign in using your company email to decrypt the document.",
    },
    {
      label: "Security browser extension scam",
      text: "Subject: Mandatory Browser Security Update\n\nTo comply with new email protection controls, install the approved secure extension from the internal portal:\nhttp://security-extension-check.org/install\nRestart browser after installation.",
    },
    {
      label: "Vendor bank detail change fraud",
      text: "Subject: Updated Remittance Instructions\n\nPlease update beneficiary account details for all pending invoices effective immediately.\nNew bank confirmation letter attached.\nDo not call previous contacts as finance lines are under maintenance.",
    },
    {
      label: "Scholarship/grant scam",
      text: "Subject: Congratulations - Education Grant Approved\n\nYour profile qualifies for an international scholarship payout. Confirm identity and processing fee to release funds:\nhttps://global-grant-center.site/claim",
    },
    {
      label: "Conference reimbursement phishing",
      text: "Subject: Travel reimbursement pending action\n\nYour conference reimbursement is ready. Complete payment preference form with payroll credentials:\nhttps://expense-portal-refund.net/employee/claim",
    },
    {
      label: "QR-code payment redirection",
      text: "Subject: Final utility bill reminder\n\nScan the QR code below to complete overdue bill payment and avoid disconnection.\n[QR CODE]\nBackup payment link: https://utility-fastpay-billing.com/pay-now",
    },
  ];

  const handleLoadSpamSample = () => {
    const chosen = complexSpamSamples[selectedSpamSample] || complexSpamSamples[0];
    const sender = chosen.senderEmail || senderForSample(chosen.label, chosen.text, selectedSpamSample);
    const textWithSender = /^from\s*:/im.test(chosen.text) ? chosen.text : `From: ${sender}\n${chosen.text}`;
    setText(textWithSender);
    setResult(null);
    setSelectedScoreTerm(null);
    showNotification(`Loaded spam sample: ${chosen.label}`, 'info', 2500);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!text.trim()) { showNotification('Please enter some text to analyze.', 'warning'); return; }
    setIsLoading(true); setResult(null); setSelectedScoreTerm(null);
    try {
      const response = await analyzeSpam(text);
      setResult(response.data);
      showNotification('Spam analysis complete.', 'success');
    } catch (error) {
      console.error('Spam analysis failed:', error);
      showNotification('Failed to analyze text. Please try again.', 'error');
    } finally { setIsLoading(false); }
  };

  const getStepUpTokenForAction = async (action: string): Promise<string | null> => {
    const password = window.prompt('Step-up authentication required. Enter your admin password:');
    if (!password) {
      showNotification('Step-up cancelled.', 'warning');
      return null;
    }
    try {
      const tokenResponse = await createStepUpToken(password, [action]);
      return String(tokenResponse.data?.step_up_token || '');
    } catch {
      showNotification('Step-up authentication failed.', 'error');
      return null;
    }
  };

  const statusMeta = result ? spamStatusMetaFor(result) : null;
  const displayedSpamRisk = result ? spamRiskFor(result) : 0;
  const displayedDecisionConfidence = result ? decisionConfidenceFor(result) : 0;
  const reliability = result ? reliabilityFor(result) : null;
  const displayedReliability = reliability
    ? `${reliability.review_required ? 'Needs Review' : titleize(reliability.reliability_status)} (${formatPercent(reliability.reliability_score, 2)})`
    : 'Not returned';
  const displayedHandling = result ? handlingDisplayFor(result) : 'Not returned';
  const suggestedActions = result ? spamSuggestedActionsFor(result) : [];
  const statusToneClasses = statusMeta?.color === 'red'
    ? 'bg-red-500/10 border-red-500/30'
    : statusMeta?.color === 'amber'
      ? 'bg-amber-500/10 border-amber-500/35'
      : 'bg-green-500/10 border-green-500/30';
  const statusIconClasses = statusMeta?.color === 'red'
    ? 'text-red-400'
    : statusMeta?.color === 'amber'
      ? 'text-amber-300'
      : 'text-green-400';

  return (
    <div className="p-4 sm:p-6 md:p-8 text-white">
      <div className="w-full max-w-4xl mx-auto bg-gray-900/70 border border-gray-700/60 rounded-2xl shadow-2xl backdrop-blur-md p-6 md:p-8">
        <header className="mb-6 text-center">
          <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-white">Spam Analyzer</h1>
          <p className="text-gray-300/90 mt-2">Paste email text or a message and check for spam indicators.</p>
        </header>
        {!settings && (
          <div className="mb-4 text-right">
            <button className="text-xs px-3 py-1 rounded-md bg-gray-800/70 border border-gray-700/60" onClick={async()=>{
              try { const s = await getSpamSettings(); setSettings(s.data); }
              catch { showNotification('Failed to load settings','error'); }
            }}>Load Settings</button>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
            <p className="text-xs text-gray-400">Spam/phishing test presets: 20 complex examples</p>
            <div className="flex flex-col sm:flex-row gap-2">
              <select
                value={selectedSpamSample}
                onChange={(e) => setSelectedSpamSample(Number(e.target.value))}
                disabled={isLoading}
                className="px-3 py-2 bg-gray-900/60 border border-gray-700/60 rounded-md text-sm text-gray-100"
                aria-label="Select spam test sample"
              >
                {complexSpamSamples.map((sample, idx) => (
                  <option key={sample.label} value={idx}>
                    {`Spam ${idx + 1}: ${sample.label}`}
                  </option>
                ))}
              </select>
              <button
                type="button"
                onClick={handleLoadSpamSample}
                disabled={isLoading}
                className="px-4 py-2 rounded-md text-sm font-semibold bg-amber-600 hover:bg-amber-700 disabled:bg-slate-500"
              >
                Load Spam Sample
              </button>
            </div>
          </div>
          <textarea
            value={text}
            onChange={(e) => setText(e.target.value)}
            className="w-full p-3.5 bg-gray-950/60 border border-gray-700/60 rounded-lg focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500 transition-colors duration-300 text-gray-100 placeholder:text-gray-400"
            rows={10}
            placeholder="Paste email or message here..."
          />
          <div className="flex justify-end">
            <button type="submit" disabled={isLoading}
              className="px-5 py-2.5 inline-flex items-center justify-center rounded-md text-sm font-semibold bg-cyan-600 hover:bg-cyan-700 disabled:bg-slate-500">
              {isLoading ? 'Analyzing...' : (<><Sparkles className="w-4 h-4 mr-2"/>Analyze Text</>)}
            </button>
          </div>
        </form>

        {result && statusMeta && (
          <section className="mt-6 space-y-4">
            <div className={`flex items-start gap-3 p-4 rounded-lg border ${statusToneClasses}`}>
              <statusMeta.Icon className={`w-6 h-6 ${statusIconClasses}`}/>
              <div>
                <p className="text-lg font-semibold text-white">{statusMeta.label}</p>
                <p className="text-sm text-gray-200/95">{statusMeta.description}</p>
                <p className="text-sm text-gray-200/95">
                  <span className="font-medium">Spam/Phishing Risk:</span> {formatPercent(displayedSpamRisk, 2)}
                </p>
                <p className="text-sm text-gray-200/95">
                  <span className="font-medium">Decision Confidence:</span> {formatPercent(displayedDecisionConfidence, 2)}
                </p>
                <p className="text-sm text-gray-200/95">
                  <span className="font-medium">AI Reliability:</span> {displayedReliability}
                </p>
                <p className="text-sm text-gray-200/95">
                  <span className="font-medium">Recommended Handling:</span> {displayedHandling}
                </p>
              </div>
            </div>

            <div className="rounded-lg border border-amber-500/25 bg-amber-500/10 p-4 text-sm text-amber-50/95">
              <p className="font-medium text-amber-100">Decision Policy</p>
              <p className="mt-1 leading-6">
                The system does not automatically block low-confidence grey-zone results. When decision confidence is below 70%, risk is close to threshold, OOD is high, or AI Reliability requires review, the result is routed to analyst review.
              </p>
            </div>

            {result.score_breakdown && (
              <div className="bg-gray-900/50 border border-gray-700/50 rounded-lg p-5">
                <h3 className="font-semibold mb-2 text-white">Score Breakdown</h3>
                <p className="mb-3 text-xs text-gray-400">Click a term to view its operation, equation, methodology, and current evidence.</p>
                <ul className="space-y-2 text-sm text-gray-300">
                  {SCORE_BREAKDOWN_ORDER.map((termKey) => {
                    const term = SCORE_TERM_DEFINITIONS[termKey];
                    const isOpen = selectedScoreTerm === termKey;
                    return (
                      <li key={termKey}>
                        <button
                          type="button"
                          onClick={() => setSelectedScoreTerm(isOpen ? null : termKey)}
                          className="flex w-full items-center justify-between gap-3 rounded-md border border-gray-700/50 bg-gray-950/30 px-3 py-2 text-left transition-colors hover:border-cyan-500/50 hover:bg-cyan-500/10 focus:outline-none focus:ring-2 focus:ring-cyan-500/60"
                          aria-expanded={isOpen}
                        >
                          <span className="flex min-w-0 items-center gap-2">
                            <Info className="h-4 w-4 shrink-0 text-cyan-300" />
                            <span className="font-medium text-gray-300">{term.label}</span>
                          </span>
                          <span className="flex shrink-0 items-center gap-2 font-mono text-gray-100">
                            {formatScorePercent(scoreValue(result, termKey))}
                            <ChevronDown className={`h-4 w-4 text-gray-400 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
                          </span>
                        </button>
                        {isOpen && <ScoreBreakdownDetail result={result} termKey={termKey} />}
                      </li>
                    );
                  })}
                </ul>
              </div>
            )}

            {/* Feedback buttons */}
            <div className="flex items-center gap-2">
              <button className="px-3 py-1 rounded bg-green-600/80 hover:bg-green-600 text-white text-xs" onClick={async()=>{
                try {
                  const predicted = result.classification_label || (result.is_spam ? 'Spam' : 'Ham');
                  await submitSpamFeedback(text, 'Ham', {
                    predicted_label: predicted,
                    confidence: displayedDecisionConfidence,
                    analysis_id: result.analysis_id,
                    source: 'human',
                  });
                  showNotification('Feedback submitted (Ham)','success');
                }
                catch { showNotification('Failed to submit feedback','error'); }
              }}>Mark as Not Spam</button>
              <button className="px-3 py-1 rounded bg-red-600/80 hover:bg-red-600 text-white text-xs" onClick={async()=>{
                try {
                  const predicted = result.classification_label || (result.is_spam ? 'Spam' : 'Ham');
                  await submitSpamFeedback(text, 'Spam', {
                    predicted_label: predicted,
                    confidence: displayedDecisionConfidence,
                    analysis_id: result.analysis_id,
                    source: 'human',
                  });
                  showNotification('Feedback submitted (Spam)','success');
                }
                catch { showNotification('Failed to submit feedback','error'); }
              }}>Mark as Spam</button>
            </div>

            {(result.meta_features?.courier_category || numericValue(result.meta_features?.courier_phishing_score) > 0) && (
              <div className="bg-red-950/30 border border-red-500/30 rounded-lg p-5">
                <h3 className="font-semibold mb-2 text-white">Courier / Delivery Phishing Evidence</h3>
                <div className="grid gap-2 text-sm text-gray-200 md:grid-cols-2">
                  <p><span className="text-gray-400">Fraud Category:</span> {displayText(result.meta_features?.courier_category, 'Not returned')}</p>
                  <p><span className="text-gray-400">Claimed Brand:</span> {displayText(result.meta_features?.claimed_brand, 'Generic courier/delivery lure')}</p>
                  <p><span className="text-gray-400">Link Domain:</span> {listValue(result.meta_features?.courier_link_domains)}</p>
                  <p><span className="text-gray-400">Courier Phishing Score:</span> {formatPercent(numericValue(result.meta_features?.courier_phishing_score ?? result.score_breakdown?.courier_phishing))}</p>
                  <p><span className="text-gray-400">Brand Mismatch:</span> {yesNo(result.meta_features?.brand_domain_mismatch)}</p>
                  <p><span className="text-gray-400">Sender Mismatch:</span> {yesNo(result.meta_features?.sender_domain_mismatch)}</p>
                  <p><span className="text-gray-400">Payment/Fee Lure:</span> {yesNo(result.meta_features?.courier_payment_fee_lure)}</p>
                  <p><span className="text-gray-400">Urgency/Threat:</span> {yesNo(result.meta_features?.courier_urgency_or_threat)}</p>
                  <p><span className="text-gray-400">Tracking Lure:</span> {yesNo(result.meta_features?.courier_tracking_lure)}</p>
                  <p><span className="text-gray-400">Suspicious Payment Link:</span> {yesNo(result.meta_features?.suspicious_payment_link)}</p>
                </div>
                {courierEvidenceFor(result).length > 0 && (
                  <ul className="mt-3 list-disc list-inside space-y-1 text-sm text-gray-200">
                    {courierEvidenceFor(result).map((reason) => <li key={reason}>{reason}</li>)}
                  </ul>
                )}
                {Array.isArray(result.defender_actions) && (result.defender_actions.includes('block_request') || result.defender_actions.includes('domain_block_request') || result.defender_actions.includes('url_block_request')) && (
                  <p className="mt-3 text-xs text-red-100/90">
                    Block Request, Domain Block Request, and URL Block Request are action-plan recommendations, not confirmed gateway enforcement.
                  </p>
                )}
              </div>
            )}

            {(fraudCategoryFor(result) || fraudEvidenceFor(result).length > 0) && (
              <div className="bg-red-950/30 border border-red-500/30 rounded-lg p-5">
                <h3 className="font-semibold mb-2 text-white">Fraud / BEC Evidence</h3>
                <div className="text-sm text-gray-200 space-y-2">
                  {fraudCategoryFor(result) && (
                    <p><span className="text-gray-400">Fraud Category:</span> {fraudCategoryFor(result)}</p>
                  )}
                  {fraudEvidenceFor(result).length > 0 && (
                    <ul className="list-disc list-inside space-y-1">
                      {fraudEvidenceFor(result).map((reason) => <li key={reason}>{reason}</li>)}
                    </ul>
                  )}
                  {Array.isArray(result.defender_actions) && result.defender_actions.includes('block_request') && (
                    <p className="text-xs text-red-100/90">
                      Block Request is an action plan for configured policy workflow, not confirmed gateway enforcement.
                    </p>
                  )}
                </div>
              </div>
            )}

            <div className="bg-gray-900/50 border border-gray-700/50 rounded-lg p-5">
              <h3 className="font-semibold mb-2 text-white">Suggested actions</h3>
              <ul className="list-disc list-inside text-sm text-gray-300 space-y-1">
                {suggestedActions.map((action) => <li key={action}>{action}</li>)}
              </ul>
            </div>

            {result.url_indicators && (
              <div className="bg-gray-900/50 border border-gray-700/50 rounded-lg p-5">
                <h3 className="font-semibold mb-2 text-white">Phishing Indicators</h3>
                <ul className="text-sm text-gray-300 space-y-1">
                  <li><span className="text-gray-400">Total URLs:</span> {String(result.url_indicators.total_urls ?? 'N/A')}</li>
                  <li><span className="text-gray-400">IP-based URLs:</span> {String(result.url_indicators.ip_urls ?? 'N/A')}</li>
                  <li><span className="text-gray-400">Suspicious TLDs:</span> {String(result.url_indicators.suspicious_tlds ?? 'N/A')}</li>
                  <li><span className="text-gray-400">Punycode domains:</span> {String(result.url_indicators.punycode ?? 'N/A')}</li>
                  {Array.isArray(result.url_indicators.blocklisted) && result.url_indicators.blocklisted.length > 0 && (
                    <li><span className="text-gray-400">Blocklisted:</span> {(result.url_indicators.blocklisted as string[]).slice(0,5).join(', ')}</li>
                  )}
                  {Array.isArray(result.url_indicators.hosts) && result.url_indicators.hosts.length > 0 && (
                    <li><span className="text-gray-400">Hosts (sample):</span> {(result.url_indicators.hosts as string[]).slice(0,5).join(', ')}</li>
                  )}
                </ul>
              </div>
            )}

            {result.meta_features && (
              <div className="bg-gray-900/50 border border-gray-700/50 rounded-lg p-5">
                <h3 className="font-semibold mb-2 text-white">Sender Metadata</h3>
                <ul className="text-sm text-gray-300 space-y-1">
                  <li><span className="text-gray-400">Sender:</span> {displayText(result.meta_features.sender, 'Not provided in input')}</li>
                  <li><span className="text-gray-400">Domain:</span> {displayText(result.meta_features.domain, 'Not derived')}</li>
                  {Boolean(result.meta_features.punycode) && <li><span className="text-red-400">Punycode in sender domain</span></li>}
                  {Boolean(result.meta_features.ip_sender) && <li><span className="text-red-400">Sender domain is an IP</span></li>}
                  {!result.meta_features.sender ? (
                    <li className="text-xs text-gray-400">Add a From: sender@example.com line to evaluate sender reputation and sender/link mismatch.</li>
                  ) : null}
                </ul>
              </div>
            )}

            {result.explanation && (
              <ExplainabilityPanel explanation={result.explanation} title="Explainable AI (Why this was classified)" />
            )}
          </section>
        )}

        {settings && (
          <section className="mt-6 bg-gray-900/50 border border-gray-700/50 rounded-lg p-5">
            <h3 className="font-semibold mb-2 text-white">Reputation Settings</h3>
            <div className="text-sm text-gray-300 space-y-1">
              <p><span className="text-gray-400">Transformer enabled:</span> {String(settings.transformer_enabled)}</p>
              <p><span className="text-gray-400">Final threshold:</span> {settings.final_threshold}</p>
              {settings.thresholds && (
                <p><span className="text-gray-400">Thresholds:</span> allow={settings.thresholds.allow}, suspicious={settings.thresholds.suspicious}, block={settings.thresholds.block}, ood={settings.thresholds.ood}</p>
              )}
              <p><span className="text-gray-400">Blocklist count:</span> {settings.blocklist_count}</p>
              <p><span className="text-gray-400">Suspicious TLDs:</span> {(settings.suspicious_tlds || []).join(', ')}</p>
            </div>
            <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label className="block text-xs text-gray-400 mb-1">Final threshold (0-1)</label>
                <input type="number" step="0.01" min={0} max={1} defaultValue={settings.final_threshold}
                  className="w-full px-2 py-1 bg-gray-800/70 border border-gray-700/60 rounded" id="spam-threshold-input" />
              </div>
              <div>
                <label className="block text-xs text-gray-400 mb-1">Suspicious TLDs (comma-separated)</label>
                <input type="text" defaultValue={(settings.suspicious_tlds || []).join(',')}
                  className="w-full px-2 py-1 bg-gray-800/70 border border-gray-700/60 rounded" id="spam-tlds-input" />
              </div>
            </div>
            <div className="mt-3">
              <button className="px-3 py-1 rounded bg-cyan-600 hover:bg-cyan-700 text-white text-xs" onClick={async()=>{
                const thrEl = document.getElementById('spam-threshold-input') as HTMLInputElement | null;
                const tldsEl = document.getElementById('spam-tlds-input') as HTMLInputElement | null;
                const thr = thrEl ? parseFloat(thrEl.value) : undefined;
                const tlds = tldsEl ? tldsEl.value.split(',').map(s=>s.trim()).filter(Boolean) : undefined;
                try {
                  const stepUpToken = await getStepUpTokenForAction('spam.settings.update');
                  if (!stepUpToken) return;
                  await updateSpamSettings({ final_threshold: thr, suspicious_tlds: tlds }, stepUpToken);
                  const s = await getSpamSettings(); setSettings(s.data);
                  showNotification('Settings updated','success');
                } catch {
                  showNotification('Failed to update settings','error');
                }
              }}>Save Settings</button>
            </div>
            <div className="mt-3">
              <label className="block text-xs text-gray-400 mb-1">Upload new blocklist</label>
              <input type="file" onChange={async (e)=>{
                const f = e.target.files?.[0]; if (!f) return; setUploading(true);
                try {
                  const stepUpToken = await getStepUpTokenForAction('spam.blocklist.upload');
                  if (!stepUpToken) return;
                  await uploadSpamBlocklist(f, stepUpToken);
                  const s = await getSpamSettings(); setSettings(s.data); showNotification('Blocklist updated','success');
                }
                catch { showNotification('Failed to upload blocklist','error'); }
                finally { setUploading(false); }
              }} />
              {uploading && <p className="text-xs text-gray-400 mt-1">Uploading…</p>}
            </div>
          </section>
        )}
      </div>
    </div>
  );
};

export default SpamAnalyzerPage;

