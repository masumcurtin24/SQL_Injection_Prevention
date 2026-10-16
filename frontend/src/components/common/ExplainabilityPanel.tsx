// frontend/src/components/common/ExplainabilityPanel.tsx
import React from 'react';
import type { XAIExplanation } from '../../types/api';

const pill = (sev?: string | null) => {
  const s = String(sev || '').toLowerCase();
  if (s === 'critical' || s === 'high') return 'bg-red-500/10 text-red-300 border-red-500/30';
  if (s === 'medium') return 'bg-yellow-500/10 text-yellow-300 border-yellow-500/30';
  if (s === 'low') return 'bg-blue-500/10 text-blue-300 border-blue-500/30';
  return 'bg-gray-500/10 text-gray-300 border-gray-500/30';
};

const pct = (v?: number | null) => {
  if (typeof v !== 'number' || Number.isNaN(v)) return 'Not returned';
  return `${(v * 100).toFixed(1)}%`;
};

const textOr = (value: unknown, fallback: string): string => {
  if (typeof value === 'string' && value.trim()) return value;
  return fallback;
};

const boolText = (value?: boolean | null): string => (value ? 'Yes' : 'No');

const reliabilityTone = (status?: string | null) => {
  const s = String(status || '').toLowerCase();
  if (s === 'reliable') return 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30';
  if (s === 'needs_review' || s === 'low_confidence' || s === 'out_of_distribution') {
    return 'bg-yellow-500/10 text-yellow-300 border-yellow-500/30';
  }
  return 'bg-red-500/10 text-red-300 border-red-500/30';
};

const labelize = (value?: string | null): string =>
  String(value || 'not_returned').replace(/_/g, ' ').replace(/\b\w/g, (m) => m.toUpperCase());

const valueText = (value: unknown): string => {
  if (typeof value === 'number') return value >= 0 && value <= 1 ? pct(value) : value.toFixed(3);
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  if (typeof value === 'string' && value.trim()) return value;
  return 'Not returned';
};

const renderAttributions = (attrs: Record<string, any>[]) => {
  const filtered = attrs.filter(Boolean).slice(0, 15);
  const shapLike = filtered.some((a) => typeof a?.token === 'string' && typeof a?.value === 'number');
  const compLike = filtered.some((a) => typeof a?.component === 'string' && typeof a?.score === 'number');
  const featLike = filtered.some((a) => typeof a?.feature === 'string' && typeof a?.weight === 'number');

  if (shapLike) {
    return (
      <ul className="text-sm text-gray-200/95 space-y-1">
        {filtered.map((a, idx) => {
          if (a?.algorithm) {
            return <li key={`alg-${idx}`} className="text-xs text-gray-400">Algorithm: {String(a.algorithm)}</li>;
          }
          if (typeof a?.token !== 'string' || typeof a?.value !== 'number') return null;
          const val = Number(a.value);
          const cls = val >= 0 ? 'text-emerald-300' : 'text-rose-300';
          return (
            <li key={idx} className="font-mono">
              {a.token} <span className={cls}>({val >= 0 ? '+' : ''}{val.toFixed(2)})</span>
            </li>
          );
        })}
      </ul>
    );
  }

  if (compLike) {
    return (
      <ul className="text-sm text-gray-200/95 space-y-1">
        {filtered.map((a, idx) => {
          if (typeof a?.component !== 'string') return null;
          const score = typeof a?.score === 'number' ? pct(Number(a.score)) : 'Not used';
          return <li key={idx}><span className="text-gray-400">{a.component}:</span> {score}</li>;
        })}
      </ul>
    );
  }

  if (featLike) {
    return (
      <ul className="text-sm text-gray-200/95 space-y-1">
        {filtered.map((a, idx) => {
          if (typeof a?.feature !== 'string' || typeof a?.weight !== 'number') return null;
          return <li key={idx}><span className="text-gray-400">{a.feature}:</span> {a.weight.toFixed(2)}</li>;
        })}
      </ul>
    );
  }

  return (
    <pre className="text-xs sm:text-sm leading-relaxed max-h-64 overflow-auto bg-black/40 border border-gray-700/50 rounded-md p-3 whitespace-pre-wrap">
      {JSON.stringify(filtered, null, 2)}
    </pre>
  );
};

const ExplainabilityPanel: React.FC<{ explanation: XAIExplanation; title?: string }> = ({ explanation, title = 'Explainable AI' }) => {
  const evidence = explanation.evidence || [];
  const trace = explanation.decision_trace || [];
  const attributions = explanation.model_attributions || [];
  const remediation = explanation.remediation || [];
  const limitations = [
    ...(explanation.limitations || []),
    ...(explanation.decision_rationale?.limitations || []),
    ...(explanation.caveats || []),
  ].filter((item, idx, arr) => item && arr.indexOf(item) === idx);
  const thresholds = explanation.decision_rationale?.thresholds_applied || explanation.thresholds || null;
  const reliability = explanation.ai_reliability || null;
  const scoreSemantics = explanation.score_semantics || null;
  const decisionRationale = explanation.decision_rationale || null;
  const evidenceContributions = explanation.evidence_contributions || [];
  const macroDefense = (explanation.provenance?.macro_defense as Record<string, any> | undefined) || null;
  const courierPhishing = (explanation.provenance?.courier_phishing as Record<string, any> | undefined) || null;
  const categoryText = String(explanation.threat_category || '');
  const isSpamExplanation = /spam|phish/i.test(categoryText);
  const isSqlExplanation = /sql/i.test(categoryText);
  const isFileExplanation = /file|upload/i.test(categoryText);
  const riskValue = typeof scoreSemantics?.risk_score === 'number'
    ? scoreSemantics.risk_score
    : typeof explanation.spam_risk === 'number'
    ? explanation.spam_risk
    : typeof explanation.risk_score === 'number'
      ? explanation.risk_score
      : null;
  const riskLabel = scoreSemantics?.risk_label || (isSpamExplanation
    ? 'Spam/Phishing Risk'
    : isSqlExplanation
      ? 'SQL Risk'
      : isFileExplanation
        ? 'File Risk'
        : 'Risk Score');
  const decisionConfidence = typeof explanation.decision_confidence === 'number'
    ? explanation.decision_confidence
    : explanation.confidence;
  const uncertaintyComponents =
    scoreSemantics?.uncertainty_components ||
    explanation.uncertainty_components ||
    (explanation.provenance?.uncertainty_components as Record<string, number> | undefined) ||
    null;
  const hasProvenance = !!(
    explanation.model_version ||
    explanation.ruleset_version ||
    explanation.policy_version ||
    thresholds ||
    explanation.provenance
  );

  return (
    <section className="bg-gray-900/50 border border-gray-700/50 rounded-lg p-5">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <h3 className="font-semibold text-white">{title}</h3>
        <div className="flex items-center gap-2">
          <span className="text-xs text-gray-300">
            Decision: <span className="font-mono text-gray-100">{explanation.decision}</span>
          </span>
          {explanation.severity ? (
            <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-semibold uppercase tracking-wide border ${pill(explanation.severity)}`}>
              {String(explanation.severity)}
            </span>
          ) : null}
        </div>
      </div>

      <div className="mt-4 rounded-md border border-gray-700/50 bg-gray-950/20 p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <h4 className="text-sm font-semibold text-white">Decision Summary</h4>
            <p className="mt-2 text-sm leading-relaxed text-gray-200/95">
              {textOr(explanation.plain_language_summary, textOr(explanation.impact, 'No plain-language summary returned'))}
            </p>
          </div>
          <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-semibold uppercase tracking-wide border ${decisionRationale?.review_required ? 'bg-yellow-500/10 text-yellow-300 border-yellow-500/30' : decisionRationale?.hard_decision ? 'bg-red-500/10 text-red-300 border-red-500/30' : 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'}`}>
            {decisionRationale?.review_required ? 'Review Required' : decisionRationale?.hard_decision ? 'Hard Decision' : 'No Review Gate'}
          </span>
        </div>
        <div className="mt-3 grid grid-cols-1 gap-3 text-sm text-gray-200/95 sm:grid-cols-2 lg:grid-cols-4">
          <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3">
            <p className="text-xs text-gray-400">Final status</p>
            <p className="font-medium break-words">{textOr(decisionRationale?.final_decision, explanation.decision)}</p>
          </div>
          <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3">
            <p className="text-xs text-gray-400">Recommended Handling</p>
            <p className="font-medium">{labelize(decisionRationale?.recommended_handling || reliability?.recommended_handling)}</p>
          </div>
          <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3">
            <p className="text-xs text-gray-400">Hard Decision</p>
            <p className="font-medium">{boolText(decisionRationale?.hard_decision)}</p>
          </div>
          <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3">
            <p className="text-xs text-gray-400">Review Required</p>
            <p className="font-medium">{boolText(decisionRationale?.review_required || reliability?.review_required)}</p>
          </div>
        </div>
      </div>

      <div className="mt-4">
        <h4 className="text-sm font-semibold text-white mb-2">Score Semantics</h4>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3 text-sm text-gray-200/95">
        <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3">
          <p className="text-xs text-gray-400">Threat category</p>
          <p className="font-medium">{textOr(explanation.threat_category, 'Uncategorized')}</p>
        </div>
        {typeof riskValue === 'number' ? (
          <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3">
            <p className="text-xs text-gray-400">{riskLabel}</p>
            <p className="font-medium">{pct(riskValue)}</p>
          </div>
        ) : null}
        <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3">
          <p className="text-xs text-gray-400">Decision Confidence</p>
          <p className="font-medium">
            {pct(decisionConfidence)}
            {explanation.confidence_label ? (
              <span className="ml-1 text-xs text-gray-400">({String(explanation.confidence_label)})</span>
            ) : null}
          </p>
        </div>
        <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3 md:col-span-2">
          <p className="text-xs text-gray-400">Impact</p>
          <p className="font-medium">{textOr(explanation.impact, 'No impact summary returned')}</p>
        </div>
        <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3">
          <p className="text-xs text-gray-400">Uncertainty</p>
          <p className="font-medium">{pct(scoreSemantics?.uncertainty_score ?? explanation.uncertainty_score)}</p>
        </div>
        <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3">
          <p className="text-xs text-gray-400">Fidelity</p>
          <p className="font-medium">{pct(scoreSemantics?.fidelity_score ?? explanation.fidelity_score)}</p>
        </div>
        <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3">
          <p className="text-xs text-gray-400">OOD Score</p>
          <p className="font-medium">{pct(scoreSemantics?.ood_score ?? explanation.ood_score)}</p>
        </div>
        <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3">
          <p className="text-xs text-gray-400">Abstain reason</p>
          <p className="font-medium break-words">{textOr(explanation.abstain_reason, 'None')}</p>
        </div>
        {typeof scoreSemantics?.reliability_score === 'number' ? (
          <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3">
            <p className="text-xs text-gray-400">AI Reliability</p>
            <p className="font-medium">{pct(scoreSemantics.reliability_score)}</p>
          </div>
        ) : null}
        </div>
        {scoreSemantics?.score_type_notes?.length ? (
          <ul className="mt-3 list-disc list-inside text-xs text-gray-300/95 space-y-1">
            {scoreSemantics.score_type_notes.slice(0, 5).map((note, idx) => <li key={idx}>{note}</li>)}
          </ul>
        ) : null}
      </div>

      {uncertaintyComponents ? (
        <div className="mt-4 rounded-md border border-gray-700/50 bg-gray-950/20 p-4">
          <h4 className="text-sm font-semibold text-white">Uncertainty Components</h4>
          <div className="mt-3 grid grid-cols-1 gap-3 text-sm text-gray-200/95 sm:grid-cols-2 xl:grid-cols-4">
            {Object.entries(uncertaintyComponents).map(([key, value]) => (
              <div key={key} className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3">
                <p className="text-xs text-gray-400">{labelize(key)}</p>
                <p className="font-medium">{pct(typeof value === 'number' ? value : null)}</p>
              </div>
            ))}
          </div>
        </div>
      ) : null}

      {macroDefense ? (
        <div className="mt-4 rounded-md border border-gray-700/50 bg-gray-950/20 p-4">
          <h4 className="text-sm font-semibold text-white">Macro Defence</h4>
          <div className="mt-3 grid grid-cols-1 gap-3 text-sm text-gray-200/95 sm:grid-cols-2 lg:grid-cols-4">
            <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3">
              <p className="text-xs text-gray-400">Macro Present</p>
              <p className="font-medium">{boolText(Boolean(macroDefense.macro_present))}</p>
            </div>
            <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3">
              <p className="text-xs text-gray-400">Macro Risk Level</p>
              <p className="font-medium">{labelize(macroDefense.macro_risk_level)}</p>
            </div>
            <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3">
              <p className="text-xs text-gray-400">Macro Risk Score</p>
              <p className="font-medium">{pct(typeof macroDefense.macro_risk_score === 'number' ? macroDefense.macro_risk_score : null)}</p>
            </div>
            <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3">
              <p className="text-xs text-gray-400">Recommended Handling</p>
              <p className="font-medium">{labelize(macroDefense.recommended_handling)}</p>
            </div>
            <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3 sm:col-span-2">
              <p className="text-xs text-gray-400">Container Type</p>
              <p className="font-medium break-words">{labelize(macroDefense.macro_container_type || 'none')}</p>
            </div>
            <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3 sm:col-span-2">
              <p className="text-xs text-gray-400">Source Trust / MOTW</p>
              <p className="font-medium break-words">{labelize(macroDefense.source_trust || 'unknown')} / {labelize(macroDefense.motw_zone || 'not supplied')}</p>
            </div>
          </div>
          {Array.isArray(macroDefense.evidence_reasons) && macroDefense.evidence_reasons.length ? (
            <ul className="mt-3 list-disc list-inside text-sm text-gray-200/95 space-y-1">
              {macroDefense.evidence_reasons.slice(0, 6).map((reason: string, idx: number) => <li key={idx}>{reason}</li>)}
            </ul>
          ) : null}
        </div>
      ) : null}

      {courierPhishing && typeof courierPhishing.score === 'number' && courierPhishing.score > 0 ? (
        <div className="mt-4 rounded-md border border-red-500/30 bg-red-950/20 p-4">
          <h4 className="text-sm font-semibold text-white">Courier / Delivery Phishing Evidence</h4>
          <div className="mt-3 grid grid-cols-1 gap-3 text-sm text-gray-200/95 sm:grid-cols-2 lg:grid-cols-4">
            <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3">
              <p className="text-xs text-gray-400">Courier Score</p>
              <p className="font-medium">{pct(courierPhishing.score)}</p>
            </div>
            <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3">
              <p className="text-xs text-gray-400">Category</p>
              <p className="font-medium break-words">{labelize(courierPhishing.category)}</p>
            </div>
            <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3">
              <p className="text-xs text-gray-400">Claimed Brand</p>
              <p className="font-medium break-words">{valueText(courierPhishing.claimed_brand)}</p>
            </div>
            <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3">
              <p className="text-xs text-gray-400">Payment Link</p>
              <p className="font-medium">{boolText(Boolean(courierPhishing.suspicious_payment_link))}</p>
            </div>
            <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3">
              <p className="text-xs text-gray-400">Brand Mismatch</p>
              <p className="font-medium">{boolText(Boolean(courierPhishing.brand_domain_mismatch))}</p>
            </div>
            <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3">
              <p className="text-xs text-gray-400">Sender Mismatch</p>
              <p className="font-medium">{boolText(Boolean(courierPhishing.sender_domain_mismatch))}</p>
            </div>
            <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3 sm:col-span-2">
              <p className="text-xs text-gray-400">Link Domains</p>
              <p className="font-medium break-words">{Array.isArray(courierPhishing.link_domains) && courierPhishing.link_domains.length ? courierPhishing.link_domains.join(', ') : 'Not returned'}</p>
            </div>
          </div>
          {Array.isArray(courierPhishing.evidence_reasons) && courierPhishing.evidence_reasons.length ? (
            <ul className="mt-3 list-disc list-inside text-sm text-gray-200/95 space-y-1">
              {courierPhishing.evidence_reasons.slice(0, 6).map((reason: string, idx: number) => <li key={idx}>{reason}</li>)}
            </ul>
          ) : null}
        </div>
      ) : null}

      {reliability ? (
        <div className="mt-4 rounded-md border border-gray-700/50 bg-gray-950/20 p-4">
          <div className="flex items-center justify-between gap-3 flex-wrap">
            <h4 className="text-sm font-semibold text-white">AI Reliability</h4>
            <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-semibold uppercase tracking-wide border ${reliabilityTone(reliability.reliability_status)}`}>
              {labelize(reliability.reliability_status)}
            </span>
          </div>
          <div className="mt-3 grid grid-cols-1 md:grid-cols-4 gap-3 text-sm text-gray-200/95">
            <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3">
              <p className="text-xs text-gray-400">Reliability Score</p>
              <p className="font-medium">{pct(reliability.reliability_score)}</p>
            </div>
            <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3">
              <p className="text-xs text-gray-400">Review Required</p>
              <p className="font-medium">{boolText(reliability.review_required)}</p>
            </div>
            <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3">
              <p className="text-xs text-gray-400">Recommended Handling</p>
              <p className="font-medium">{labelize(reliability.recommended_handling)}</p>
            </div>
            <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3">
              <p className="text-xs text-gray-400">Policy Override</p>
              <p className="font-medium">{boolText(reliability.policy_override)}</p>
            </div>
            <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3">
              <p className="text-xs text-gray-400">Adversarial Suspicion</p>
              <p className="font-medium">{boolText(reliability.adversarial_suspicion)}</p>
            </div>
            <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3 md:col-span-3">
              <p className="text-xs text-gray-400">Signal Conflicts</p>
              <p className="font-medium break-words">
                {reliability.signal_conflicts?.length ? reliability.signal_conflicts.map(labelize).join(', ') : 'None'}
              </p>
            </div>
          </div>
          {reliability.review_reasons?.length ? (
            <div className="mt-3">
              <p className="text-xs text-gray-400">Review Reasons</p>
              <ul className="mt-1 list-disc list-inside text-sm text-amber-100/95 space-y-1">
                {reliability.review_reasons.slice(0, 8).map((reason, idx) => <li key={idx}>{reason}</li>)}
              </ul>
            </div>
          ) : null}
        </div>
      ) : null}

      {evidenceContributions.length > 0 ? (
        <div className="mt-4">
          <h4 className="text-sm font-semibold text-white mb-2">Evidence Contributions</h4>
          <div className="overflow-x-auto rounded-md border border-gray-700/50">
            <table className="min-w-full divide-y divide-gray-700/50 text-left text-sm">
              <thead className="bg-gray-950/40 text-xs uppercase tracking-wide text-gray-400">
                <tr>
                  <th className="px-3 py-2 font-medium">Signal</th>
                  <th className="px-3 py-2 font-medium">Value</th>
                  <th className="px-3 py-2 font-medium">Weight</th>
                  <th className="px-3 py-2 font-medium">Normalized</th>
                  <th className="px-3 py-2 font-medium">Direction</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/70 bg-gray-900/30 text-gray-200/95">
                {evidenceContributions.slice(0, 12).map((item, idx) => (
                  <tr key={`${item.name}-${idx}`}>
                    <td className="px-3 py-2 align-top">
                      <p className="font-medium text-gray-100">{item.name}</p>
                      <p className="text-xs text-gray-400">{item.category} - {item.source}</p>
                      <p className="mt-1 max-w-xl text-xs text-gray-300">{item.explanation}</p>
                    </td>
                    <td className="px-3 py-2 align-top font-mono">{valueText(item.value)}</td>
                    <td className="px-3 py-2 align-top font-mono">{typeof item.weight === 'number' ? item.weight.toFixed(3) : 'N/A'}</td>
                    <td className="px-3 py-2 align-top font-mono">{typeof item.normalized_contribution === 'number' ? item.normalized_contribution.toFixed(4) : 'N/A'}</td>
                    <td className="px-3 py-2 align-top">{labelize(item.direction)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ) : null}

      {hasProvenance ? (
        <div className="mt-4">
          <h4 className="text-sm font-semibold text-white mb-2">Model and policy provenance</h4>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-sm text-gray-200/95">
            <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3">
              <p className="text-xs text-gray-400">Model version</p>
              <p className="font-medium break-words">{textOr(explanation.model_version, 'Not returned')}</p>
            </div>
            <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3">
              <p className="text-xs text-gray-400">Ruleset version</p>
              <p className="font-medium break-words">{textOr(explanation.ruleset_version, 'Not returned')}</p>
            </div>
            <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3">
              <p className="text-xs text-gray-400">Policy version</p>
              <p className="font-medium break-words">{textOr(explanation.policy_version, 'Not returned')}</p>
            </div>
          </div>
          {thresholds ? (
            <details className="mt-3 rounded-md border border-gray-700/50 bg-gray-950/20 p-3">
              <summary className="cursor-pointer select-none text-sm text-gray-100">Decision thresholds</summary>
              <pre className="mt-2 text-xs leading-relaxed overflow-auto bg-black/40 border border-gray-700/50 rounded-md p-3 whitespace-pre-wrap">
                {JSON.stringify(thresholds, null, 2)}
              </pre>
            </details>
          ) : null}
          {explanation.provenance ? (
            <details className="mt-3 rounded-md border border-gray-700/50 bg-gray-950/20 p-3">
              <summary className="cursor-pointer select-none text-sm text-gray-100">Pipeline provenance</summary>
              <pre className="mt-2 text-xs leading-relaxed overflow-auto bg-black/40 border border-gray-700/50 rounded-md p-3 whitespace-pre-wrap">
                {JSON.stringify(explanation.provenance, null, 2)}
              </pre>
            </details>
          ) : null}
        </div>
      ) : null}

      {evidence.length > 0 ? (
        <div className="mt-4">
          <h4 className="text-sm font-semibold text-white mb-2">Evidence</h4>
          <div className="space-y-3">
            {evidence.slice(0, 12).map((ev) => (
              <div key={ev.id} className="rounded-md border border-gray-700/50 bg-gray-950/30 p-3">
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-semibold text-gray-100">{ev.label}</span>
                    {ev.severity ? (
                      <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-semibold uppercase tracking-wide border ${pill(ev.severity)}`}>
                        {String(ev.severity)}
                      </span>
                    ) : null}
                    {ev.source ? <span className="text-[11px] text-gray-400">({ev.source})</span> : null}
                  </div>
                  {typeof ev.score === 'number' ? <span className="text-xs text-gray-300 font-mono">score: {ev.score.toFixed(2)}</span> : null}
                </div>
                {ev.description ? <p className="mt-1 text-sm text-gray-200/90">{ev.description}</p> : null}
                {ev.impact ? <p className="mt-1 text-xs text-gray-300/90"><span className="text-gray-400">Impact:</span> {ev.impact}</p> : null}
                {ev.snippet ? (
                  <pre className="mt-2 text-xs sm:text-sm leading-relaxed overflow-auto bg-black/40 border border-gray-700/50 rounded-md p-3 whitespace-pre-wrap">
                    {ev.snippet}
                  </pre>
                ) : null}
              </div>
            ))}
          </div>
        </div>
      ) : null}

      {attributions.length > 0 ? (
        <div className="mt-4">
          <h4 className="text-sm font-semibold text-white mb-2">Model contributions</h4>
          {renderAttributions(attributions)}
        </div>
      ) : null}

      {trace.length > 0 ? (
        <div className="mt-4">
          <h4 className="text-sm font-semibold text-white mb-2">Decision trace</h4>
          <div className="space-y-2">
            {trace.map((t) => (
              <details key={t.stage} className="rounded-md border border-gray-700/50 bg-gray-950/20 p-3">
                <summary className="cursor-pointer select-none text-sm text-gray-100">
                  <span className="font-mono text-xs text-gray-400 mr-2">{t.stage}</span>
                  {t.summary}
                </summary>
                {t.details ? (
                  <pre className="mt-2 text-xs leading-relaxed overflow-auto bg-black/40 border border-gray-700/50 rounded-md p-3 whitespace-pre-wrap">
                    {JSON.stringify(t.details, null, 2)}
                  </pre>
                ) : null}
              </details>
            ))}
          </div>
        </div>
      ) : null}

      {remediation.length > 0 ? (
        <div className="mt-4">
          <h4 className="text-sm font-semibold text-white mb-2">Recommended actions</h4>
          <ul className="list-disc list-inside text-sm text-gray-200/95 space-y-1">
            {remediation.slice(0, 8).map((r, idx) => <li key={idx}>{r}</li>)}
          </ul>
        </div>
      ) : null}

      {explanation.counterfactual ? (
        <div className="mt-4 text-xs text-gray-300/90">
          <span className="text-gray-400">Counterfactual:</span> {explanation.counterfactual}
        </div>
      ) : null}

      {explanation.technical_summary ? (
        <div className="mt-4 rounded-md border border-gray-700/50 bg-gray-950/20 p-4">
          <h4 className="text-sm font-semibold text-white">Technical Summary</h4>
          <p className="mt-2 text-sm leading-relaxed text-gray-200/95">{explanation.technical_summary}</p>
        </div>
      ) : null}

      {limitations.length > 0 ? (
        <div className="mt-4">
          <h4 className="text-sm font-semibold text-white mb-2">Limitations</h4>
          <ul className="list-disc list-inside text-sm text-amber-200/95 space-y-1">
            {limitations.slice(0, 8).map((c, idx) => <li key={idx}>{c}</li>)}
          </ul>
        </div>
      ) : null}
    </section>
  );
};

export default ExplainabilityPanel;
