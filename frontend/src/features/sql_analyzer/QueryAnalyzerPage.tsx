// frontend/src/features/sql_analyzer/QueryAnalyzerPage.tsx
import { useMemo, useState } from 'react';
import type React from 'react';
import type { FormEvent, ReactElement, ReactNode } from 'react';
import { ChevronDown, Info } from 'lucide-react';
import { analyzeQuery } from '../../lib/apiClient'; 
import type { AnalysisApiResponse, SQLQueryPayload } from '../../types/api';
import { useNotification } from '../../contexts/useNotification';
import ExplainabilityPanel from '../../components/common/ExplainabilityPanel';

// --- Icon Components (All using explicit return) ---
const InputTerminalIcon: React.FC<{ className?: string }> = ({ className = "w-5 h-5" }) => {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className={className}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M6.75 7.5l3 2.25-3 2.25m4.5 0h3m-9 8.25h13.5A2.25 2.25 0 0021 18V6a2.25 2.25 0 00-2.25-2.25H5.25A2.25 2.25 0 003 6v12a2.25 2.25 0 002.25 2.25z" />
    </svg>
  );
};
const ShieldCheckIcon: React.FC<{ className?: string }> = ({ className = "w-6 h-6" }) => {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className={className}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
    </svg>
  );
};
const ShieldExclamationIcon: React.FC<{ className?: string }> = ({ className = "w-6 h-6" }) => {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className={className}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 2.25c-3.75 0-7.03.963-9.75 2.625C2.25 6.375 1.5 8.188 1.5 10.5c0 7.5 6.75 11.25 10.5 11.25S22.5 18 22.5 10.5c0-2.312-.75-4.125-2.25-5.625C17.53.963 14.25 2.25 12 2.25z" />
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m0 .75H12m-.008 3H12m.008 0H12m0 0V15m0-3.75V9" />
    </svg>
  );
};
const DocumentMagnifyingGlassIcon: React.FC<{ className?: string }> = ({ className = "w-5 h-5" }) => {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className={className}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 15.75l-2.489-2.489m0 0a3.375 3.375 0 10-4.773-4.773 3.375 3.375 0 004.774 4.774zM21 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0114.25 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H5.25A2.25 2.25 0 003 6v12a2.25 2.25 0 002.25 2.25h10.5A2.25 2.25 0 0018 18v-2.625" />
    </svg>
  );
};
const ScaleIcon: React.FC<{ className?: string }> = ({ className = "w-5 h-5" }) => {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className={className}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 3v17.25m0 0c-1.472 0-2.882.265-4.185.75M12 20.25c1.472 0 2.882.265 4.185.75M18.75 4.97A48.416 48.416 0 0012 4.5c-2.291 0-4.545.16-6.75.47m13.5 0c1.01.143 2.01.317 3 .52m-3-.52l2.25-1.5m-2.25 1.5l-2.25-1.5m3 1.5l-2.25 1.5m-10.5-1.5L6.75 3.61m0 0A48.416 48.416 0 0112 4.5c2.291 0 4.545.16 6.75.47M3.75 4.97A48.416 48.416 0 0112 4.5c-2.291 0-4.545.16-6.75.47M12 4.5v17.25m0 0c-1.472 0-2.882.265-4.185.75M12 20.25c1.472 0 2.882.265 4.185.75M12 20.25v-2.625m0-10.875L12 4.5m0 12.375L12 10.5m0 0L12 4.5m0 0L12 3" />
    </svg>
  );
};
const LoadingSpinner: React.FC<{ className?: string }> = ({ className = "animate-spin h-5 w-5 text-white" }) => {
  return (
    <svg className={className} xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
    </svg>
  );
};
const TrashIcon: React.FC<{ className?: string }> = ({ className = "w-5 h-5" }) => {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className={className}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M14.74 9l-.346 9m-4.788 0L9.26 9m9.968-3.21c.342.052.682.107 1.022.166m-1.022-.165L18.16 19.673a2.25 2.25 0 01-2.244 2.077H8.084a2.25 2.25 0 01-2.244-2.077L4.772 5.79m14.456 0a48.108 48.108 0 00-3.478-.397m-12.56 0c1.153-.119 2.305-.218 3.478-.397m7.5 0v-.916c0-1.18-.91-2.164-2.09-2.201a51.964 51.964 0 00-3.32 0c-1.18.037-2.09 1.022-2.09 2.201v.916m7.5 0a48.667 48.667 0 00-7.5 0" />
    </svg>
  );
};
const CodeBracketIcon: React.FC<{ className?: string }> = ({ className = "w-5 h-5" }) => {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={1.5} stroke="currentColor" className={className}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M17.25 6.75L22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3l-4.5 16.5" />
    </svg>
  );
};
// --- End Icon Components ---


// Reusable ResultCard component
interface ResultCardProps { // Define props interface for ResultCard
  title: string;
  icon?: ReactElement<{ className?: string }>; // icon is optional
  children: ReactNode;
  cardClasses?: string;
  titleSize?: string;
}
const ResultCard: React.FC<ResultCardProps> = ({
  title, 
  icon, 
  children, 
  cardClasses = "bg-white dark:bg-dark-tertiary", // Default classes for light/dark
  titleSize = "text-base" // Default title size
}) => {
  return (
    <div className={`${cardClasses} p-3 sm:p-4 rounded-lg shadow-md border border-slate-200 dark:border-border-dark`}>
      <h4 className={`${titleSize} font-semibold text-cyan-600 dark:text-accent-cyan mb-2 flex items-center`}>
        {icon && <span className="mr-2 opacity-90">{icon}</span>}
        {title}
      </h4>
      {children}
    </div>
  );
};

type SqlScoreTermKey = 'final' | 'heuristics' | 'nlp' | 'anomaly' | 'ast' | 'ood' | 'fidelity';

type SqlScoreTermDefinition = {
  label: string;
  summary: string;
  operation: string;
  equation: string;
  methodology: string;
  codePath: string;
};

const SQL_SCORE_ORDER: SqlScoreTermKey[] = ['final', 'heuristics', 'nlp', 'anomaly', 'ast', 'ood', 'fidelity'];

const SQL_SCORE_DEFINITIONS: Record<SqlScoreTermKey, SqlScoreTermDefinition> = {
  final: {
    label: 'Final risk',
    summary: 'Calibrated aggregate risk used for the overall risk level and suggested SQL action.',
    operation: 'Combines heuristic, NLP, anomaly, and SQL-structure signals, then applies critical-hit floors and policy thresholds.',
    equation:
      'final = min(1, 0.45*heuristics + 0.25*nlp + 0.20*anomaly + 0.10*ast)\nif any critical heuristic code is present: final = max(final, 0.93)',
    methodology: 'Weighted late-fusion SQL injection detector with deterministic policy escalation for critical signatures.',
    codePath: 'QueryAnalysisService._calibrated_signal_score -> _combine_results -> _build_xai_explanation',
  },
  heuristics: {
    label: 'Heuristics',
    summary: 'Regex/rule score for known SQL injection patterns.',
    operation: 'Matches the SQL text against injection signatures, sums matched rule weights, caps the result, and marks suspected when the score or critical hits cross policy.',
    equation: 'heuristics = min(1.0, sum(matched_rule_weights)); suspected = score >= 0.75 or critical_hit_present',
    methodology: 'Deterministic SQLi rule engine covering tautologies, UNION, stacked statements, timing probes, metadata enumeration, file operations, comments, and dangerous DB procedures.',
    codePath: 'QueryAnalysisService._heuristics_scan',
  },
  nlp: {
    label: 'NLP validation',
    summary: 'Classifier confidence converted into malicious probability.',
    operation: 'Runs the query-validation model and normalizes its label/confidence into a malicious probability for fusion.',
    equation:
      'if label contains malicious: nlp = confidence\nif label contains suspicious: nlp = max(confidence, 0.60)\nif label contains benign/safe: nlp = 1 - confidence\nelse: nlp = confidence',
    methodology: 'Text-classification pipeline over SQL text, used as a semantic corroborating signal.',
    codePath: 'QueryAnalysisService._nlp_malicious_probability',
  },
  anomaly: {
    label: 'Anomaly',
    summary: 'Outlier signal from the SQL anomaly model.',
    operation: 'Runs the anomaly detector. If the detector marks the query anomalous, the fusion layer contributes a fixed anomaly probability.',
    equation: 'anomaly = 0.75 if anomaly_model.is_anomalous else 0.00; weighted contribution = 0.20 * anomaly',
    methodology: 'Anomaly/outlier detection used as a supporting signal when query shape differs from normal traffic.',
    codePath: 'QueryAnalysisService._calibrated_signal_score',
  },
  ast: {
    label: 'AST structure',
    summary: 'Structural SQL feature score.',
    operation: 'Extracts structural features such as stacked statements, UNION, DDL, EXEC, tautologies, timing functions, comments, metadata probes, and file exfiltration operations.',
    equation:
      'ast = min(1,\n  0.35 if stacked statements\n  + 0.30 if UNION\n  + 0.30 if DDL\n  + 0.25 if EXEC/CALL\n  + 0.20 if tautology\n  + 0.25 if timing function\n  + 0.15 if comment\n  + 0.20 if metadata enumeration\n  + 0.20 if file exfil ops\n  + 0.20 if user-management DDL\n  + 0.20 if literal WHERE without placeholder\n)',
    methodology: 'Lightweight SQL structural parsing that corroborates injection behavior independently of text classifier output.',
    codePath: 'QueryAnalysisService._extract_sql_ast_features -> _calibrated_signal_score',
  },
  ood: {
    label: 'OOD',
    summary: 'Out-of-distribution guardrail for unusual SQL payloads.',
    operation: 'Adds risk when the query is extremely long, has high non-ASCII density, or is anomalous without heuristic/NLP agreement.',
    equation:
      'ood = min(1,\n  +0.35 if length > 4000 else +0.20 if length > 2000\n  +0.35 if non_ascii_ratio >= 0.15 else +0.20 if >= 0.05\n  +0.35 if anomalous and no heuristic hits and NLP confidence < 0.55\n)',
    methodology: 'Distribution-shift guardrail that can request manual review when model consensus is weak.',
    codePath: 'QueryAnalysisService._build_xai_explanation',
  },
  fidelity: {
    label: 'Fidelity',
    summary: 'Agreement score between signal families and the final restrictive/allow decision.',
    operation: 'Counts whether anomaly, NLP, and heuristics agree with the final decision direction.',
    equation: 'fidelity = supporting_signal_families / available_signal_families',
    methodology: 'Lightweight explanation-faithfulness proxy; high means the visible signal families align with the final action.',
    codePath: 'QueryAnalysisService._build_xai_explanation',
  },
};

const sqlPct = (value: unknown, digits = 1): string => {
  if (typeof value !== 'number' || !Number.isFinite(value)) return 'N/A';
  return `${(value * 100).toFixed(digits)}%`;
};

const sqlNum = (value: unknown, digits = 3): string => {
  if (typeof value !== 'number' || !Number.isFinite(value)) return 'N/A';
  return value.toFixed(digits);
};

const sqlBool = (value: unknown): string => (value ? 'yes' : 'no');

const sqlList = (value: unknown, fallback = 'none'): string => {
  if (Array.isArray(value) && value.length > 0) return value.slice(0, 10).map(String).join(', ');
  return fallback;
};

const sqlTraceDetails = (result: AnalysisApiResponse, stage: string): Record<string, any> | null => {
  const step = result.explanation?.decision_trace?.find((item) => item.stage === stage);
  return step?.details || null;
};

const sqlNlpMaliciousProbability = (result: AnalysisApiResponse): number | null => {
  const score = result.query_validation?.classification_score;
  if (typeof score !== 'number' || !Number.isFinite(score)) return null;
  const clamped = Math.max(0, Math.min(1, score));
  const label = String(result.query_validation?.classification_label || '').toLowerCase();
  if (label.includes('malicious')) return clamped;
  if (label.includes('suspicious')) return Math.max(clamped, 0.60);
  if (label.includes('benign') || label.includes('safe')) return Math.max(0, 1 - clamped);
  return clamped;
};

const sqlTermValue = (result: AnalysisApiResponse, termKey: SqlScoreTermKey): number | null => {
  if (termKey === 'final') {
    return result.combined_assessment?.calibrated_risk_score ?? result.explanation?.risk_score ?? null;
  }
  if (termKey === 'heuristics') return result.heuristics_detection?.heuristic_score ?? null;
  if (termKey === 'nlp') return sqlNlpMaliciousProbability(result);
  if (termKey === 'anomaly') return result.anomaly_detection?.is_anomalous ? 0.75 : 0.0;
  if (termKey === 'ood') return result.explanation?.ood_score ?? null;
  if (termKey === 'fidelity') return result.explanation?.fidelity_score ?? null;
  if (termKey === 'ast') {
    const contributions = result.combined_assessment?.signal_contributions || sqlTraceDetails(result, 'aggregator')?.signal_contributions || {};
    const weightedAst = typeof contributions.ast === 'number' ? contributions.ast : null;
    return weightedAst === null ? null : Math.min(1, weightedAst / 0.10);
  }
  return null;
};

const clampSql01 = (value: unknown): number | null => {
  if (typeof value !== 'number' || !Number.isFinite(value)) return null;
  return Math.max(0, Math.min(1, value));
};

const sqlRiskFor = (result: AnalysisApiResponse): number | null =>
  clampSql01(result.combined_assessment?.calibrated_risk_score ?? result.explanation?.risk_score);

const sqlDecisionConfidenceFor = (result: AnalysisApiResponse): number | null => {
  const direct = clampSql01(result.explanation?.decision_confidence ?? result.explanation?.confidence);
  if (direct !== null) return direct;
  const risk = sqlRiskFor(result);
  if (risk === null) return null;
  const action = String(result.combined_assessment?.suggested_action || result.explanation?.decision || '').trim().toUpperCase();
  const safeDecision = action.startsWith('ALLOW') || action === 'SAFE' || action === 'MONITOR';
  const baseConfidence = safeDecision ? 1 - risk : risk;
  return Math.max(0, Math.min(1, baseConfidence));
};

const sqlActiveAstFeatures = (result: AnalysisApiResponse): string[] => {
  const astFeatures = result.combined_assessment?.ast_features || sqlTraceDetails(result, 'aggregator')?.ast_features || {};
  return Object.entries(astFeatures)
    .filter(([, value]) => value === true || (typeof value === 'number' && value > 0))
    .map(([key, value]) => (value === true ? key : `${key}=${String(value)}`));
};

const sqlCurrentLines = (result: AnalysisApiResponse, termKey: SqlScoreTermKey): string[] => {
  const lines = [`Displayed score: ${sqlPct(sqlTermValue(result, termKey))}.`];
  const aggregator = sqlTraceDetails(result, 'aggregator') || {};
  const contributions = result.combined_assessment?.signal_contributions || aggregator.signal_contributions || {};
  const thresholds = result.explanation?.thresholds || {};

  if (termKey === 'final') {
    lines.push(`Risk/action: ${result.combined_assessment?.overall_risk_level || 'N/A'} / ${result.combined_assessment?.suggested_action || result.explanation?.decision || 'N/A'}.`);
    lines.push(`Contributions: heuristics ${sqlNum(contributions.heuristics)}, NLP ${sqlNum(contributions.nlp)}, anomaly ${sqlNum(contributions.anomaly)}, AST ${sqlNum(contributions.ast)}, total ${sqlNum(contributions.calibrated_total)}.`);
    lines.push(`Thresholds: medium ${sqlPct(thresholds.risk_medium)}, high ${sqlPct(thresholds.risk_high)}, block ${sqlPct(thresholds.risk_block)}, heuristics high ${sqlPct(thresholds.heuristics_high)}.`);
  }

  if (termKey === 'heuristics') {
    const h = result.heuristics_detection;
    lines.push(`Suspected: ${sqlBool(h?.suspected)}.`);
    lines.push(`Matched hit codes: ${sqlList(h?.hits)}.`);
    lines.push(`Fusion contribution: ${sqlNum(contributions.heuristics)} = 0.45 * ${sqlNum(h?.heuristic_score)}.`);
    const featureWeights = (result.explanation?.model_attributions || [])
      .filter((item) => item.feature && typeof item.weight === 'number')
      .map((item) => `${item.feature} +${sqlNum(item.weight)}`);
    if (featureWeights.length > 0) lines.push(`Matched rule weights: ${featureWeights.slice(0, 12).join('; ')}.`);
  }

  if (termKey === 'nlp') {
    const nlp = result.query_validation;
    lines.push(`Classifier label: ${nlp?.classification_label || 'N/A'}.`);
    lines.push(`Classifier confidence: ${sqlPct(nlp?.classification_score)}.`);
    lines.push(`Normalized malicious probability: ${sqlPct(sqlNlpMaliciousProbability(result))}.`);
    lines.push(`Fusion contribution: ${sqlNum(contributions.nlp)} = 0.25 * normalized NLP malicious probability.`);
  }

  if (termKey === 'anomaly') {
    const anomaly = result.anomaly_detection;
    lines.push(`Anomaly status: ${anomaly?.prediction_label || 'N/A'}; is_anomalous=${sqlBool(anomaly?.is_anomalous)}.`);
    lines.push(`Raw anomaly model score: ${sqlNum(anomaly?.score, 5)}.`);
    lines.push(`Fusion contribution: ${sqlNum(contributions.anomaly)} = 0.20 * ${anomaly?.is_anomalous ? '0.75' : '0.00'}.`);
  }

  if (termKey === 'ast') {
    lines.push(`Active structural features: ${sqlList(sqlActiveAstFeatures(result))}.`);
    lines.push(`Fusion contribution: ${sqlNum(contributions.ast)} = 0.10 * AST structural score.`);
  }

  if (termKey === 'ood') {
    lines.push(`Abstain reason: ${result.explanation?.abstain_reason || 'none'}.`);
    lines.push(`Query length: ${String(result.query_received?.length || 0)} characters.`);
  }

  if (termKey === 'fidelity') {
    const provenance = result.explanation?.provenance || {};
    lines.push(`Signal families: ${String(provenance.signal_families ?? 'N/A')}; supporting signals: ${String(provenance.supporting_signals ?? 'N/A')}.`);
    lines.push(`Final decision is restrictive: ${sqlBool(String(result.explanation?.decision || '').toUpperCase() !== 'ALLOW')}.`);
  }

  return lines;
};

const SqlScoreMethodologyPanel: React.FC<{
  result: AnalysisApiResponse;
  selectedTerm: SqlScoreTermKey | null;
  onSelectTerm: (term: SqlScoreTermKey | null) => void;
}> = ({ result, selectedTerm, onSelectTerm }) => (
  <ResultCard
    title="SQL Score Methodology"
    icon={<Info className="h-5 w-5" />}
    cardClasses="bg-slate-50 dark:bg-dark-tertiary border-slate-200 dark:border-border-light/50 md:col-span-2"
  >
    <p className="mb-3 text-xs text-slate-500 dark:text-text-secondary">
      Click a term to view the exact operation, equation, methodology, and current evidence.
    </p>
    <ul className="space-y-2">
      {SQL_SCORE_ORDER.map((termKey) => {
        const term = SQL_SCORE_DEFINITIONS[termKey];
        const isOpen = selectedTerm === termKey;
        return (
          <li key={termKey}>
            <button
              type="button"
              onClick={() => onSelectTerm(isOpen ? null : termKey)}
              className="flex w-full items-center justify-between gap-3 rounded-md border border-slate-300/70 bg-white px-3 py-2 text-left text-sm transition-colors hover:border-cyan-500/60 hover:bg-cyan-50 focus:outline-none focus:ring-2 focus:ring-cyan-500/50 dark:border-border-light/50 dark:bg-slate-900/40 dark:hover:bg-cyan-500/10"
              aria-expanded={isOpen}
            >
              <span className="flex min-w-0 items-center gap-2">
                <Info className="h-4 w-4 shrink-0 text-cyan-600 dark:text-accent-cyan" />
                <span className="font-medium text-slate-700 dark:text-text-primary">{term.label}</span>
              </span>
              <span className="flex shrink-0 items-center gap-2 font-mono text-slate-800 dark:text-text-primary">
                {sqlPct(sqlTermValue(result, termKey))}
                <ChevronDown className={`h-4 w-4 text-slate-500 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
              </span>
            </button>
            {isOpen && (
              <div className="mt-2 rounded-md border border-cyan-500/30 bg-white p-3 text-xs text-slate-600 shadow-sm dark:bg-slate-950/50 dark:text-text-secondary break-words">
                <p className="mb-3 text-sm text-slate-800 dark:text-text-primary">{term.summary}</p>
                <div className="grid gap-3 md:grid-cols-2">
                  <div>
                    <p className="mb-1 font-semibold text-cyan-700 dark:text-cyan-200">Operation</p>
                    <p className="leading-relaxed">{term.operation}</p>
                  </div>
                  <div>
                    <p className="mb-1 font-semibold text-cyan-700 dark:text-cyan-200">Methodology</p>
                    <p className="leading-relaxed">{term.methodology}</p>
                  </div>
                </div>
                <div className="mt-3">
                  <p className="mb-1 font-semibold text-cyan-700 dark:text-cyan-200">Equation</p>
                  <pre className="whitespace-pre-wrap break-words rounded bg-slate-100 p-2 font-mono text-[11px] leading-relaxed text-slate-800 dark:bg-black/30 dark:text-gray-200">
                    {term.equation}
                  </pre>
                </div>
                <div className="mt-3">
                  <p className="mb-1 font-semibold text-cyan-700 dark:text-cyan-200">Current Analysis</p>
                  <ul className="list-disc space-y-1 pl-5">
                    {sqlCurrentLines(result, termKey).map((line) => (
                      <li key={line}>{line}</li>
                    ))}
                  </ul>
                </div>
                <p className="mt-3 text-[11px] text-slate-400 dark:text-gray-500">Code path: {term.codePath}</p>
              </div>
            )}
          </li>
        );
      })}
    </ul>
  </ResultCard>
);

const QueryAnalyzerPage: React.FC = () => {
  const [query, setQuery] = useState<string>("SELECT * FROM users WHERE id = '1' OR '1'='1';");
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [analysisResult, setAnalysisResult] = useState<AnalysisApiResponse | null>(null);
  const [selectedMaliciousSample, setSelectedMaliciousSample] = useState<number>(0);
  const [selectedScoreTerm, setSelectedScoreTerm] = useState<SqlScoreTermKey | null>(null);
  const { showNotification } = useNotification();

  const sampleNormalQuery = "SELECT id, name, email FROM customers WHERE country = 'USA' AND last_order_date > '2024-01-01' ORDER BY registration_date DESC LIMIT 50;";
  const maliciousSamples: { label: string; query: string }[] = [
    { label: "Auth bypass (OR true)", query: "SELECT * FROM users WHERE username = 'admin' OR '1'='1' --';" },
    { label: "UNION exfiltration", query: "SELECT id, name FROM products WHERE id = 1 UNION SELECT username, password FROM users --;" },
    { label: "Stacked statement drop", query: "SELECT user, password FROM admin_users WHERE id = 1; DROP TABLE users; --" },
    { label: "Time-based delay (PostgreSQL)", query: "SELECT * FROM users WHERE username = 'admin' AND pg_sleep(5) --';" },
    { label: "Time-based delay (MySQL)", query: "SELECT * FROM users WHERE id = 1 AND IF(1=1, SLEEP(5), 0) --;" },
    { label: "Schema enumeration", query: "SELECT * FROM users WHERE id = 1 OR EXISTS(SELECT 1 FROM information_schema.tables) --;" },
    { label: "Boolean blind injection", query: "SELECT * FROM invoices WHERE invoice_id = 10 AND SUBSTRING((SELECT version()),1,1)='1' --;" },
    { label: "Stacked update abuse", query: "SELECT * FROM accounts WHERE id = 5; UPDATE users SET role='admin' WHERE username='attacker'; --" },
    { label: "Comment obfuscation", query: "SELECT * FROM users WHERE username = 'admin'/**/OR/**/'1'='1' --';" },
    { label: "Stored procedure abuse", query: "EXEC('SELECT * FROM users WHERE username = ''admin'' OR ''1''=''1''');" },
  ];

  const handleClearQuery = () => {
    setQuery("");
    setAnalysisResult(null);
    setSelectedScoreTerm(null);
    showNotification("Query input cleared.", "info", 2000);
  };

  const handleLoadSample = (sampleType: 'normal' | 'malicious') => {
    const newQuery = sampleType === 'normal'
      ? sampleNormalQuery
      : (maliciousSamples[selectedMaliciousSample]?.query || maliciousSamples[0].query);
    setQuery(newQuery);
    setAnalysisResult(null);
    setSelectedScoreTerm(null);
    showNotification(`Sample ${sampleType} query loaded.`, "info", 2000);
  };

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!query.trim()) {
      showNotification("Query cannot be empty.", "warning");
      setAnalysisResult(null); 
      setSelectedScoreTerm(null);
      return;
    }
    setIsLoading(true);
    setAnalysisResult(null); 
    setSelectedScoreTerm(null);
    const payload: SQLQueryPayload = { query };
    try {
      const result = await analyzeQuery(payload);
      setAnalysisResult(result);
      showNotification("Query analysis complete!", "success", 3000);
    } catch (err: any)      {
      console.error("Submission error:", err);
      showNotification(err.message || "Failed to analyze query.", "error");
    } finally {
      setIsLoading(false);
    }
  };

  const getRiskLevelClasses = (level?: string): string => {
    if (!level) return "text-slate-500 dark:text-text-secondary";
    switch (level.toLowerCase()) {
      case 'critical': return "text-red-600 dark:text-accent-red font-bold";
      case 'high': return "text-orange-500 dark:text-accent-orange font-bold";
      case 'medium': return "text-yellow-500 dark:text-accent-yellow font-semibold";
      case 'low': return "text-green-600 dark:text-accent-green";
      default: return "text-slate-500 dark:text-text-secondary";
    }
  };
  
  const getClassificationClasses = (label?: string): string => {
    if (!label) return "text-slate-500 dark:text-text-secondary";
    const lowerLabel = label.toLowerCase();
    if (lowerLabel.includes("malicious")) return "text-red-600 dark:text-accent-red font-semibold";
    if (lowerLabel.includes("suspicious")) return "text-orange-500 dark:text-accent-orange font-semibold";
    if (lowerLabel.includes("benign") || lowerLabel.includes("ham")) return "text-green-600 dark:text-accent-green";
    return "text-slate-500 dark:text-text-secondary";
  };

  const highlightedQuery = useMemo(() => {
    if (!analysisResult?.explanation?.highlights || analysisResult.explanation.highlights.length === 0) return null;
    const text = String(analysisResult.query_received || '');
    if (!text) return null;

    const hl = (analysisResult.explanation.highlights || [])
      .filter((h) => typeof h?.start === 'number' && typeof h?.end === 'number' && h.start < text.length && h.end > 0)
      .map((h) => ({ ...h, start: Math.max(0, h.start), end: Math.min(text.length, h.end) }))
      .sort((a, b) => a.start - b.start);
    if (hl.length === 0) return null;

    const parts: ReactNode[] = [];
    let cursor = 0;
    const cls = (sev?: string) => {
      const s = String(sev || '').toLowerCase();
      if (s === 'critical' || s === 'high') return 'bg-red-200/80 dark:bg-red-900/40 text-red-900 dark:text-red-200';
      if (s === 'medium') return 'bg-yellow-200/80 dark:bg-yellow-900/40 text-yellow-900 dark:text-yellow-200';
      if (s === 'low') return 'bg-cyan-200/60 dark:bg-cyan-900/30 text-cyan-900 dark:text-cyan-200';
      return 'bg-slate-200 dark:bg-slate-800/60 text-slate-900 dark:text-slate-200';
    };

    hl.forEach((h, idx) => {
      const start = Math.max(cursor, h.start);
      const end = Math.max(start, h.end);
      if (start > cursor) {
        parts.push(<span key={`q${idx}-n`}>{text.slice(cursor, start)}</span>);
      }
      if (end > start) {
        parts.push(
          <span key={`q${idx}-h`} className={`rounded-sm ${cls(h.severity)} px-0.5`} title={h.label}>
            {text.slice(start, end)}
          </span>
        );
      }
      cursor = end;
    });
    if (cursor < text.length) parts.push(<span key="q-last">{text.slice(cursor)}</span>);
    return parts;
  }, [analysisResult?.query_received, analysisResult?.explanation?.highlights]);

  return (
    <div className="w-full max-w-4xl space-y-8">
      <section className="bg-white dark:bg-dark-secondary shadow-xl rounded-xl p-6 md:p-8 border border-slate-200 dark:border-border-dark">
        <header className="mb-6 text-center">
            <h2 className="text-3xl font-bold text-cyan-600 dark:text-accent-cyan tracking-tight">
              SQL Query Analyzer
            </h2>
            <p className="mt-2 text-md text-slate-600 dark:text-text-secondary">
              Submit SQL queries for AI-powered threat analysis.
            </p>
        </header>
        
        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label htmlFor="sqlQuery" className="block text-sm font-medium text-cyan-700 dark:text-accent-cyan mb-1">
              SQL Query:
            </label>
            <textarea
              id="sqlQuery"
              name="sqlQuery"
              rows={10}
              className="w-full p-3.5 bg-slate-50 dark:bg-dark-tertiary border border-slate-300 dark:border-border-dark rounded-lg shadow-sm focus:ring-2 focus:ring-cyan-500 dark:focus:ring-accent-cyan focus:border-cyan-500 dark:focus:border-accent-cyan text-slate-800 dark:text-text-primary placeholder-slate-400 dark:placeholder-text-secondary/70 text-sm font-mono selection:bg-cyan-500 dark:selection:bg-accent-cyan selection:text-white dark:selection:text-dark-primary custom-scrollbar"
              placeholder="e.g., SELECT * FROM users WHERE username = 'admin';"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              disabled={isLoading}
            />
          </div>

          <div className="flex flex-col items-stretch space-y-3 sm:flex-row sm:space-y-0 sm:space-x-3 sm:justify-end">
              <button
                  type="button" onClick={handleClearQuery} disabled={isLoading || !query}
                  className="px-5 py-2.5 inline-flex items-center justify-center border border-slate-300 dark:border-border-light text-sm font-medium rounded-md shadow-sm text-slate-700 dark:text-text-secondary bg-white dark:bg-dark-tertiary hover:bg-slate-50 dark:hover:bg-slate-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-white dark:focus:ring-offset-dark-secondary focus:ring-cyan-500 dark:focus:ring-accent-cyan disabled:opacity-50 disabled:cursor-not-allowed transition-colors sm:w-auto"
              > <TrashIcon className="mr-2" /> Clear </button>
              <button
                  type="button" onClick={() => handleLoadSample('normal')} disabled={isLoading}
                  className="px-5 py-2.5 inline-flex items-center justify-center border border-transparent text-sm font-medium rounded-md shadow-sm text-sky-700 dark:text-sky-300 bg-sky-100 dark:bg-sky-500/20 hover:bg-sky-200 dark:hover:bg-sky-500/30 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-white dark:focus:ring-offset-dark-secondary focus:ring-sky-500 disabled:opacity-50 transition-colors sm:w-auto"
              > <CodeBracketIcon className="mr-2" /> Sample (Normal) </button>
              <select
                  value={selectedMaliciousSample}
                  onChange={(e) => setSelectedMaliciousSample(Number(e.target.value))}
                  disabled={isLoading}
                  className="px-3 py-2.5 border border-slate-300 dark:border-border-light rounded-md text-sm text-slate-700 dark:text-text-secondary bg-white dark:bg-dark-tertiary focus:outline-none focus:ring-2 focus:ring-amber-500 dark:focus:ring-amber-400 disabled:opacity-50 sm:min-w-[250px]"
                  aria-label="Select malicious sample query"
              >
                {maliciousSamples.map((sample, idx) => (
                  <option key={sample.label} value={idx}>
                    {`Malicious ${idx + 1}: ${sample.label}`}
                  </option>
                ))}
              </select>
              <button
                  type="button" onClick={() => handleLoadSample('malicious')} disabled={isLoading}
                  className="px-5 py-2.5 inline-flex items-center justify-center border border-transparent text-sm font-medium rounded-md shadow-sm text-amber-700 dark:text-amber-300 bg-amber-100 dark:bg-amber-500/20 hover:bg-amber-200 dark:hover:bg-amber-500/30 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-white dark:focus:ring-offset-dark-secondary focus:ring-amber-500 disabled:opacity-50 transition-colors sm:w-auto"
              > <CodeBracketIcon className="mr-2" /> Load Malicious Sample </button>
          </div>

          <div className="pt-4 flex justify-center">
            <button
              type="submit"
              disabled={isLoading}
              className={`inline-flex items-center justify-center px-10 py-3 border border-transparent 
                          rounded-lg shadow-lg text-base font-semibold 
                          text-white dark:text-dark-primary 
                          bg-cyan-600 hover:bg-cyan-700 dark:bg-accent-cyan dark:hover:bg-accent-cyan-light
                          focus:outline-none focus:ring-2 focus:ring-offset-2 
                          focus:ring-offset-white dark:focus:ring-offset-dark-secondary 
                          focus:ring-cyan-500 dark:focus:ring-accent-cyan
                          transition-all duration-150 ease-in-out transform hover:scale-[1.02] active:scale-[0.98]
                          disabled:bg-slate-400 dark:disabled:bg-slate-600 disabled:cursor-not-allowed
                          max-w-xs sm:max-w-sm`}
            >
              {isLoading ? (
                <><LoadingSpinner className="animate-spin mr-2 h-5 w-5" /> Analyzing...</>
              ) : (
                <><InputTerminalIcon className="mr-2 h-5 w-5" /> Analyze Query</>
              )}
            </button>
          </div>
        </form>
      </section>

      {analysisResult && (
        <section className="mt-8 bg-white dark:bg-dark-secondary shadow-xl rounded-xl p-6 md:p-8 border border-slate-200 dark:border-border-dark">
          <header className="mb-4 border-b border-slate-200 dark:border-border-dark pb-3">
            <h3 className="text-xl font-semibold text-cyan-700 dark:text-accent-cyan">Analysis Report</h3>
            {analysisResult.analysis_id && (
              <p className="text-xs text-slate-500 dark:text-text-secondary mt-1">Analysis ID: <span className="font-mono">{analysisResult.analysis_id}</span></p>
            )}
          </header>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs sm:text-sm">
            <ResultCard title="Query Details" icon={<DocumentMagnifyingGlassIcon />} cardClasses="bg-slate-50 dark:bg-dark-tertiary border-slate-200 dark:border-border-light/50">
              <pre className="block bg-slate-100 dark:bg-slate-900 p-3 rounded text-xs text-cyan-700 dark:text-accent-cyan-light font-mono custom-scrollbar overflow-x-auto shadow-inner border border-slate-300 dark:border-slate-700 whitespace-pre-wrap break-words">{highlightedQuery || analysisResult.query_received}</pre>
              <p className="mt-2 text-xs text-slate-500 dark:text-text-secondary"><strong className="text-slate-600 dark:text-slate-400">Timestamp:</strong> {new Date(analysisResult.analysis_timestamp).toLocaleString()}</p>
            </ResultCard>
            
            <ResultCard title="Anomaly Detection" icon={<ShieldCheckIcon />} cardClasses="bg-slate-50 dark:bg-dark-tertiary border-slate-200 dark:border-border-light/50">
              <div className={`flex items-center p-3 rounded-md text-sm ${analysisResult.anomaly_detection.is_anomalous ? 'bg-red-100 dark:bg-accent-red/10' : 'bg-green-100 dark:bg-accent-green/10'}`}>
                {analysisResult.anomaly_detection.is_anomalous ? 
                  <ShieldExclamationIcon className={`h-6 w-6 mr-3 ${getRiskLevelClasses('Critical')} flex-shrink-0`} /> : 
                  <ShieldCheckIcon className={`h-6 w-6 mr-3 ${getRiskLevelClasses('Low')} flex-shrink-0`} />
                }
                <div>
                  <p><strong className="text-slate-700 dark:text-text-primary">Status:</strong> 
                    <span className={`font-semibold ml-1 ${analysisResult.anomaly_detection.is_anomalous ? 'text-red-700 dark:text-accent-red-text' : 'text-green-700 dark:text-accent-green-text'}`}>
                      {analysisResult.anomaly_detection.prediction_label}
                    </span>
                  </p>
                  <p><strong className="text-slate-600 dark:text-text-secondary">Score:</strong> <span className="text-slate-800 dark:text-text-primary font-mono">{analysisResult.anomaly_detection.score.toFixed(5)}</span></p>
                </div>
              </div>
            </ResultCard>

            {analysisResult.query_validation && (
              <ResultCard title="NLP Query Validation" icon={<DocumentMagnifyingGlassIcon />} cardClasses="bg-slate-50 dark:bg-dark-tertiary border-slate-200 dark:border-border-light/50">
                <div className={`p-3 rounded-md text-sm ${getClassificationClasses(analysisResult.query_validation.classification_label).includes('red') || getClassificationClasses(analysisResult.query_validation.classification_label).includes('orange') ? 'bg-orange-100 dark:bg-accent-orange/10' : 'bg-slate-100 dark:bg-slate-700/20'}`}>
                    <p><strong className="text-slate-700 dark:text-text-primary">Classification:</strong>
                        <span className={`font-semibold ml-1 ${getClassificationClasses(analysisResult.query_validation.classification_label)}`}>
                            {analysisResult.query_validation.classification_label}
                        </span>
                    </p>
                    {analysisResult.query_validation.classification_score !== null && analysisResult.query_validation.classification_score !== undefined && (
                        <p><strong className="text-slate-600 dark:text-text-secondary">Model Classification Confidence:</strong> <span className="text-slate-800 dark:text-text-primary font-mono">{(analysisResult.query_validation.classification_score * 100).toFixed(2)}%</span></p>
                    )}
                </div>
              </ResultCard>
            )}

            {analysisResult.combined_assessment && (
              <ResultCard 
                title="Overall Risk Assessment" 
                icon={<ScaleIcon />} 
                cardClasses={`border ${
                    analysisResult.combined_assessment.overall_risk_level.toLowerCase() === 'critical' ? 'bg-red-50 dark:bg-accent-red/20 border-red-300 dark:border-accent-red/50' :
                    analysisResult.combined_assessment.overall_risk_level.toLowerCase() === 'high' ? 'bg-orange-50 dark:bg-accent-orange/20 border-orange-300 dark:border-accent-orange/50' :
                    analysisResult.combined_assessment.overall_risk_level.toLowerCase() === 'medium' ? 'bg-yellow-50 dark:bg-accent-yellow/20 border-yellow-300 dark:border-accent-yellow/50' :
                    'bg-slate-50 dark:bg-dark-tertiary border-slate-200 dark:border-border-light/50'
                }`}
                titleSize="text-base font-semibold"
              >
                <div className="p-2 sm:p-3 rounded-md">
                    <p><strong className="text-slate-700 dark:text-text-primary">Overall Risk Level:</strong>
                        <span className={`font-bold text-lg ml-2 ${getRiskLevelClasses(analysisResult.combined_assessment.overall_risk_level)}`}>
                            {analysisResult.combined_assessment.overall_risk_level}
                        </span>
                    </p>
                    <p className="mt-1"><strong className="text-slate-600 dark:text-text-secondary">Suggested Action:</strong> <span className="text-slate-800 dark:text-text-primary font-semibold bg-slate-200 dark:bg-slate-700 px-2.5 py-1 rounded-full text-xs shadow">{analysisResult.combined_assessment.suggested_action}</span></p>
                    <div className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-2">
                      <p className="rounded-md bg-white/70 p-2 text-sm dark:bg-slate-900/40">
                        <strong className="text-slate-600 dark:text-text-secondary">SQL Risk:</strong>{' '}
                        <span className="font-mono text-slate-800 dark:text-text-primary">{sqlPct(sqlRiskFor(analysisResult), 2)}</span>
                      </p>
                      <p className="rounded-md bg-white/70 p-2 text-sm dark:bg-slate-900/40">
                        <strong className="text-slate-600 dark:text-text-secondary">Decision Confidence:</strong>{' '}
                        <span className="font-mono text-slate-800 dark:text-text-primary">{sqlPct(sqlDecisionConfidenceFor(analysisResult), 2)}</span>
                      </p>
                    </div>
                    {analysisResult.combined_assessment.reasoning && analysisResult.combined_assessment.reasoning.length > 0 && (
                        <div className="mt-2">
                            <strong className="text-slate-600 dark:text-text-secondary text-xs">Reasoning Highlights:</strong>
                            <ul className="list-disc list-inside ml-2 text-xs text-slate-500 dark:text-text-secondary space-y-0.5 mt-1">
                                {analysisResult.combined_assessment.reasoning.map((reason, index) => (
                                    <li key={index}>{reason}</li>
                                ))}
                            </ul>
                        </div>
                    )}
                </div>
              </ResultCard>
            )}

            {analysisResult.heuristics_detection && (
              <ResultCard
                title="Heuristics Detection"
                icon={<DocumentMagnifyingGlassIcon />}
                cardClasses={`border ${analysisResult.heuristics_detection.suspected ? 'bg-amber-50 dark:bg-amber-500/10 border-amber-300 dark:border-amber-400/40' : 'bg-slate-50 dark:bg-dark-tertiary border-slate-200 dark:border-border-light/50'}`}
              >
                <div className="p-2 sm:p-3 rounded-md">
                  <p className="text-sm"><strong className="text-slate-700 dark:text-text-primary">Suspected:</strong>
                    <span className={`ml-2 px-2 py-0.5 rounded-full text-xs font-semibold ${analysisResult.heuristics_detection.suspected ? 'bg-amber-200 dark:bg-amber-400/20 text-amber-900 dark:text-amber-300' : 'bg-green-200/70 dark:bg-green-400/20 text-green-900 dark:text-green-300'}`}>
                      {analysisResult.heuristics_detection.suspected ? 'Yes' : 'No'}
                    </span>
                  </p>
                  {typeof analysisResult.heuristics_detection.heuristic_score === 'number' && (
                    <p className="text-xs text-slate-600 dark:text-text-secondary mt-1"><strong>Score:</strong> <span className="font-mono">{(analysisResult.heuristics_detection.heuristic_score * 100).toFixed(0)}%</span></p>
                  )}
                  {analysisResult.heuristics_detection.hits && analysisResult.heuristics_detection.hits.length > 0 && (
                    <div className="mt-2">
                      <strong className="text-slate-600 dark:text-text-secondary text-xs">Indicators:</strong>
                      <ul className="list-disc list-inside ml-2 text-xs text-slate-600 dark:text-text-secondary space-y-0.5 mt-1">
                        {analysisResult.heuristics_detection.hits.slice(0, 10).map((h, i) => (
                          <li key={`${h}-${i}`}>{h}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              </ResultCard>
            )}

            <SqlScoreMethodologyPanel
              result={analysisResult}
              selectedTerm={selectedScoreTerm}
              onSelectTerm={setSelectedScoreTerm}
            />

            {analysisResult.errors && analysisResult.errors.length > 0 && (
                 <ResultCard title="Analysis Errors" icon={<ShieldExclamationIcon className="text-red-600 dark:text-accent-red"/>} cardClasses="bg-red-50 dark:bg-accent-red/20 border-red-300 dark:border-accent-red/50 md:col-span-2">
                    <ul className="list-disc list-inside ml-1 text-sm text-red-700 dark:text-accent-red-text space-y-0.5 p-2">
                        {analysisResult.errors.map((err, index) => (
                            <li key={index}>{err}</li>
                        ))}
                    </ul>
                 </ResultCard>
            )}
          </div>
          
          {analysisResult.explanation && (
            <div className="mt-6">
              <ExplainabilityPanel explanation={analysisResult.explanation} title="Explainable AI (Why this query was flagged)" />
            </div>
          )}

          <details className="mt-8 group">
            <summary className="text-xs text-slate-500 dark:text-text-secondary hover:text-slate-700 dark:hover:text-text-primary cursor-pointer focus:outline-none list-none">
                <span className="group-open:hidden">Show Raw JSON Response ▼</span>
                <span className="hidden group-open:inline">Hide Raw JSON Response ▲</span>
            </summary>
            <pre className="mt-2 p-3 bg-slate-100 dark:bg-slate-900 text-xs text-cyan-700 dark:text-accent-cyan-light rounded-md overflow-x-auto custom-scrollbar shadow-inner border border-slate-300 dark:border-slate-700">
              {JSON.stringify(analysisResult, null, 2)}
            </pre>
          </details>
        </section>
      )}
    </div>
  );
};

export default QueryAnalyzerPage;
