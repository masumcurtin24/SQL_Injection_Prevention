// File: frontend/src/features/file_scanner/FileScannerPage.tsx

import React, { useState, useCallback, useMemo, useEffect, useRef } from 'react';
import { useDropzone } from 'react-dropzone';
import { UploadCloud, FileCheck2, ShieldX, ShieldAlert, Info, ChevronDown } from 'lucide-react';
import { analyzeFile } from '../../lib/apiClient';
import { useNotification } from '../../contexts/useNotification';
import type { FileAnalysisResponse } from '../../types/api';
import ExplainabilityPanel from '../../components/common/ExplainabilityPanel';

const Badge: React.FC<{ label: string; color: 'green' | 'yellow' | 'red' | 'gray' }> = ({ label, color }) => (
  <span
    className={
      `inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ` +
      (color === 'green'
        ? 'bg-green-500/10 text-green-300 border-green-500/30'
        : color === 'yellow'
        ? 'bg-yellow-500/10 text-yellow-300 border-yellow-500/30'
        : color === 'red'
        ? 'bg-red-500/10 text-red-300 border-red-500/30'
        : 'bg-gray-500/10 text-gray-300 border-gray-500/30')
    }
  >
    {label}
  </span>
);

type FileScoreTermKey = 'risk' | 'type_validation' | 'signature' | 'archive' | 'macro_defense' | 'heuristics' | 'ml' | 'ood' | 'fidelity';

type FileScoreTermDefinition = {
  label: string;
  summary: string;
  operation: string;
  equation: string;
  methodology: string;
  codePath: string;
};

const FILE_SCORE_ORDER: FileScoreTermKey[] = [
  'risk',
  'type_validation',
  'signature',
  'archive',
  'macro_defense',
  'heuristics',
  'ml',
  'ood',
  'fidelity',
];

const FILE_SCORE_DEFINITIONS: Record<FileScoreTermKey, FileScoreTermDefinition> = {
  risk: {
    label: 'Final risk',
    summary: 'Overall file risk score used for the status and recommended action.',
    operation: 'Evaluates size/type policy, YARA/signature results, archive/macro/PDF indicators, ML results, and heuristic policy floors.',
    equation:
      'base risk = 0.90 too large; 0.80 disallowed type; 0.95 YARA malicious; 0.90 inner archive YARA; 0.75 suspicious ML/macro/PDF; 0.10 safe\nfinal risk = max(base risk, applicable policy floors)',
    methodology: 'Rule-priority risk assessment with conservative floors for high-confidence malware, exploit, script execution, mismatch, and skimmer/credential-stealer evidence.',
    codePath: 'FileAnalysisService._assess_risk plus post-assessment policy floor adjustments',
  },
  type_validation: {
    label: 'Type validation',
    summary: 'Declared/observed file type policy check.',
    operation: 'Detects MIME/content type, compares it against allowed upload types, and records extension/content mismatch evidence.',
    equation: 'type risk floor = 0.80 when type is not allowed; extension/content mismatch floor = max(current risk, 0.70)',
    methodology: 'Static file-type validation using detected MIME/content type plus extension consistency checks.',
    codePath: 'FileAnalysisService type validation stage -> _assess_risk',
  },
  signature: {
    label: 'Signature scan',
    summary: 'YARA/signature detection result.',
    operation: 'Scans outer file content and nested archive/document content for known malicious or suspicious YARA rules.',
    equation: 'outer YARA malicious risk = 0.95; inner archive YARA risk = 0.90; medium-confidence YARA floor = max(current risk, 0.72)',
    methodology: 'Signature-based malware and exploit detection using YARA rule matches and scan details.',
    codePath: 'FileAnalysisService malware/signature scan -> _assess_risk',
  },
  archive: {
    label: 'Archive scan',
    summary: 'Nested archive/document analysis for hidden payloads and macros.',
    operation: 'Inspects ZIP/OOXML structures, nested paths, macro indicators, and inner YARA matches with safety limits.',
    equation: 'inner YARA risk = 0.90; macro/pdf/ML suspicious base risk = 0.75 when no higher-priority rule already applies',
    methodology: 'Recursive archive inspection with depth/file limits plus macro and embedded-content heuristics.',
    codePath: 'FileAnalysisService._safe_zip_scan -> _build_structured_verdict',
  },
  macro_defense: {
    label: 'Macro defence',
    summary: 'Static Office macro-container and risky macro-behaviour analysis.',
    operation: 'Inspects OOXML vbaProject.bin containers, non-macro extension mismatches, legacy OLE macro evidence when supported, VBA auto-exec/execution/network/obfuscation indicators, remote relationships, and embedded OLE/ActiveX indicators.',
    equation:
      'macro risk = max(container baseline, risky VBA indicators, external relationship floor, extension mismatch floor)\nhigh-risk macro floor >= 0.80\ncritical macro chain floor >= 0.92\nfinal file risk = max(file risk, macro policy floor)',
    methodology: 'Static macro defence only: it does not execute macros or claim sandbox detonation. Source trust/MOTW and signature metadata are used only when supplied.',
    codePath: 'FileAnalysisService._build_macro_defense_result -> _apply_macro_defense_to_assessment',
  },
  heuristics: {
    label: 'Heuristics',
    summary: 'Execution, active-content, and content-mismatch heuristic score drivers.',
    operation: 'Looks for execution chains, reverse shells, PDF active actions, web skimmers, credential-stealer indicators, and extension/content mismatch.',
    equation:
      'remote shell floor = max(current risk, 0.90)\nhard execution floor = max(current risk, 0.80)\nscript execution floor = max(current risk, 0.72)\nweb skimmer floor = max(current risk, 0.80)\ncredential stealer floor = max(current risk, 0.75)\nextension mismatch floor = max(current risk, 0.70)',
    methodology: 'Deterministic behavioral heuristics over extracted text, PDF metadata, script markers, and file metadata.',
    codePath: 'FileAnalysisService heuristic marker extraction and post-assessment policy floors',
  },
  ml: {
    label: 'ML scan',
    summary: 'Content-based ML model result for suspicious file text/features.',
    operation: 'Runs the ML content model when the file type is text-extractable or otherwise supported, then records label, score, evidence terms, and optional feature attributions.',
    equation: 'if ML is suspicious and no higher-priority hit exists: risk = max(current risk, 0.75)',
    methodology: 'Machine-learning content classifier with optional evidence terms, top tokens, and SHAP-style feature attributions.',
    codePath: 'FileAnalysisService ML scan stage -> _assess_risk',
  },
  ood: {
    label: 'OOD',
    summary: 'Out-of-distribution guardrail for ambiguous or low-confidence file content.',
    operation: 'Adds OOD risk for generic binary MIME types, disallowed file types, uncertain ML scores, or missing ML on text-like content.',
    equation:
      'ood = min(1,\n  +0.45 if MIME is application/octet-stream or binary/octet-stream\n  +0.30 if type is disallowed\n  +0.20 if ML score is between 0.40 and 0.60\n  +0.20 if ML is missing for text-like MIME\n)',
    methodology: 'File-distribution guardrail that can route ambiguous samples to manual review.',
    codePath: 'FileAnalysisService XAI OOD calculation',
  },
  fidelity: {
    label: 'Fidelity',
    summary: 'Agreement score between file signal families and final allow/block decision.',
    operation: 'Counts whether type validation, signature scanning, and ML scanning agree with the final restrictive/allow decision.',
    equation: 'fidelity = supporting_signal_families / available_signal_families',
    methodology: 'Lightweight explanation-faithfulness proxy for the file verdict.',
    codePath: 'FileAnalysisService XAI fidelity calculation',
  },
};

const filePct = (value: unknown, digits = 1): string => {
  if (typeof value !== 'number' || !Number.isFinite(value)) return 'N/A';
  return `${(value * 100).toFixed(digits)}%`;
};

const fileNum = (value: unknown, digits = 3): string => {
  if (typeof value !== 'number' || !Number.isFinite(value)) return 'N/A';
  return value.toFixed(digits);
};

const fileBool = (value: unknown): string => (value ? 'yes' : 'no');

const fileList = (value: unknown, fallback = 'none'): string => {
  if (Array.isArray(value) && value.length > 0) return value.slice(0, 10).map(String).join(', ');
  return fallback;
};

const fileLabelize = (value: unknown): string =>
  String(value || 'not_returned').replace(/_/g, ' ').replace(/\b\w/g, (m) => m.toUpperCase());

const macroDefenseFor = (result: FileAnalysisResponse): Record<string, any> =>
  (result.macro_defense || result.file_details?.macro_defense || result.structured_verdict?.macro_defense || {}) as Record<string, any>;

const macroDisplayStatus = (macro: Record<string, any>): { label: string; color: 'green' | 'yellow' | 'red' | 'gray' } => {
  const level = String(macro?.macro_risk_level || 'none').toLowerCase();
  const present = Boolean(macro?.macro_present);
  const container = String(macro?.macro_container_type || '').toLowerCase();
  if (level === 'critical') return { label: 'Critical Macro Behaviour Detected', color: 'red' };
  if (level === 'high') return { label: container.includes('without') ? 'Macro Extension Mismatch' : 'Risky Macro Detected', color: 'red' };
  if (level === 'medium') return { label: 'Macro Present - Review Required', color: 'yellow' };
  if (level === 'low' || present) return { label: 'Macro Present - Low Risk', color: 'yellow' };
  return { label: 'No Macro Detected', color: 'green' };
};

const fileExplanationStage = (result: FileAnalysisResponse, stage: string): Record<string, any> | null => {
  const step = result.explanation?.decision_trace?.find((item) => item.stage === stage);
  return step?.details || null;
};

const fileStructuredStage = (result: FileAnalysisResponse, stage: string): Record<string, any> | null => {
  const stages = result.structured_verdict?.analysis_stages;
  if (!Array.isArray(stages)) return null;
  return stages.find((item: any) => item?.stage === stage) || null;
};

const fileTermValue = (result: FileAnalysisResponse, termKey: FileScoreTermKey): number | null => {
  if (termKey === 'risk') return result.risk_score ?? result.explanation?.risk_score ?? null;
  if (termKey === 'type_validation') {
    const typeDetails = fileExplanationStage(result, 'type_validation') || result.file_details?.type_validation || {};
    return typeDetails.is_allowed_type === false ? 0.80 : 0.0;
  }
  if (termKey === 'signature') {
    const signatureDetails = fileExplanationStage(result, 'signature_scan') || result.file_details?.malware_scan || {};
    if (signatureDetails.is_malicious) return 0.95;
    return result.matched_rules.length > 0 ? 0.72 : 0.0;
  }
  if (termKey === 'archive') {
    const archiveStage = fileStructuredStage(result, 'archive_scan');
    const details = archiveStage?.details || {};
    const lineageCount = Array.isArray(details.archive_lineage) ? details.archive_lineage.length : 0;
    return details.macro_present || lineageCount > 0 ? 0.75 : 0.0;
  }
  if (termKey === 'macro_defense') {
    const macro = result.macro_defense || result.file_details?.macro_defense || result.structured_verdict?.macro_defense || {};
    return typeof macro.macro_risk_score === 'number' ? macro.macro_risk_score : null;
  }
  if (termKey === 'heuristics') {
    const heurStage = fileStructuredStage(result, 'heuristics');
    return heurStage?.status === 'hit' ? 0.72 : 0.0;
  }
  if (termKey === 'ml') {
    const ml = fileExplanationStage(result, 'ml_scan') || result.file_details?.ml_scan || {};
    if (typeof ml.prediction_score_ml === 'number') return ml.prediction_score_ml;
    return null;
  }
  if (termKey === 'ood') return result.explanation?.ood_score ?? null;
  if (termKey === 'fidelity') return result.explanation?.fidelity_score ?? null;
  return null;
};

const clampFile01 = (value: unknown): number | null => {
  if (typeof value !== 'number' || !Number.isFinite(value)) return null;
  return Math.max(0, Math.min(1, value));
};

const fileRiskFor = (result: FileAnalysisResponse): number | null =>
  clampFile01(result.risk_score ?? result.explanation?.risk_score);

const fileDecisionConfidenceFor = (result: FileAnalysisResponse): number | null => {
  const direct = clampFile01(result.decision_confidence ?? result.explanation?.decision_confidence ?? result.explanation?.confidence);
  if (direct !== null) return direct;
  const risk = fileRiskFor(result);
  if (risk === null) return null;
  const action = String(result.recommended_action || result.explanation?.decision || '').trim().toUpperCase();
  const status = String(result.overall_status || '').trim().toLowerCase();
  const safeDecision = action.startsWith('ALLOW') || action === 'SAFE' || action === 'CLEAN' || (status.includes('safe') && !/(block|flag|review|quarantine)/i.test(action));
  const baseConfidence = safeDecision ? 1 - risk : risk;
  return Math.max(0, Math.min(1, baseConfidence));
};

const fileCurrentLines = (result: FileAnalysisResponse, termKey: FileScoreTermKey): string[] => {
  const lines = [`Displayed score: ${filePct(fileTermValue(result, termKey))}.`];

  if (termKey === 'risk') {
    lines.push(`Status/action: ${result.overall_status || 'N/A'} / ${result.recommended_action || result.explanation?.decision || 'N/A'}.`);
    lines.push(`Risk score: ${filePct(result.risk_score)} (${fileNum(result.risk_score)}).`);
    lines.push(`Reasoning: ${fileList(result.reasoning)}.`);
  }

  if (termKey === 'type_validation') {
    const typeDetails = fileExplanationStage(result, 'type_validation') || result.file_details?.type_validation || {};
    lines.push(`Detected MIME: ${String(typeDetails.detected_mime_type || result.mime_type || 'N/A')}.`);
    lines.push(`Allowed type: ${fileBool(typeDetails.is_allowed_type !== false)}.`);
    lines.push(`Declared/observed: ${String(result.structured_verdict?.declared_type || 'N/A')} / ${String(result.structured_verdict?.detected_type || result.mime_type || 'N/A')}.`);
  }

  if (termKey === 'signature') {
    const signatureDetails = fileExplanationStage(result, 'signature_scan') || result.file_details?.malware_scan || {};
    const scanDetails = signatureDetails.scan_details || {};
    lines.push(`YARA malicious: ${fileBool(signatureDetails.is_malicious)}.`);
    lines.push(`Threat name: ${String(signatureDetails.threat_name || 'none')}.`);
    lines.push(`Matched rules: ${fileList(result.matched_rules)}.`);
    lines.push(`Outer YARA matches: ${fileList(scanDetails.outer_yara_matches)}.`);
  }

  if (termKey === 'archive') {
    const archiveStage = fileStructuredStage(result, 'archive_scan');
    const details = archiveStage?.details || {};
    lines.push(`Stage status: ${String(archiveStage?.status || 'N/A')}.`);
    lines.push(`Macro present: ${fileBool(details.macro_present)}.`);
    lines.push(`Archive lineage: ${fileList(details.archive_lineage)}.`);
  }

  if (termKey === 'macro_defense') {
    const macro = macroDefenseFor(result);
    lines.push(`Macro present: ${fileBool(macro.macro_present)}.`);
    lines.push(`Risk level: ${fileLabelize(macro.macro_risk_level)}.`);
    lines.push(`Container: ${String(macro.macro_container_type || 'none')}.`);
    lines.push(`Recommended handling: ${fileLabelize(macro.recommended_handling)}.`);
    lines.push(`Auto-exec indicators: ${fileList(macro.auto_exec_indicators)}.`);
    lines.push(`Execution indicators: ${fileList(macro.execution_indicators)}.`);
    lines.push(`External references: ${fileList(macro.external_reference_indicators)}.`);
  }

  if (termKey === 'heuristics') {
    const heurStage = fileStructuredStage(result, 'heuristics');
    const details = heurStage?.details || {};
    lines.push(`Stage status: ${String(heurStage?.status || 'N/A')}.`);
    lines.push(`Execution markers: ${fileList(details.exec_markers)}.`);
    lines.push(`Extension/content mismatch: ${fileBool(details.ext_mismatch)}.`);
    lines.push(`PDF active-content hits: ${fileList(details.pdf_hits)}.`);
  }

  if (termKey === 'ml') {
    const ml = fileExplanationStage(result, 'ml_scan') || result.file_details?.ml_scan || {};
    lines.push(`ML label: ${String(ml.prediction_label_ml || 'N/A')}.`);
    lines.push(`ML suspicious: ${fileBool(ml.is_suspicious_ml)}.`);
    lines.push(`ML score: ${filePct(ml.prediction_score_ml)}.`);
    lines.push(`Evidence terms: ${fileList(ml.evidence_terms)}.`);
  }

  if (termKey === 'ood') {
    const typeDetails = fileExplanationStage(result, 'type_validation') || result.file_details?.type_validation || {};
    const ml = fileExplanationStage(result, 'ml_scan') || result.file_details?.ml_scan || {};
    lines.push(`Detected MIME: ${String(typeDetails.detected_mime_type || result.mime_type || 'N/A')}.`);
    lines.push(`Type disallowed: ${fileBool(typeDetails.is_allowed_type === false)}.`);
    lines.push(`ML score: ${filePct(ml.prediction_score_ml)}.`);
    lines.push(`Abstain reason: ${result.explanation?.abstain_reason || 'none'}.`);
  }

  if (termKey === 'fidelity') {
    const provenance = result.explanation?.provenance || {};
    lines.push(`Signal families: ${String(provenance.signal_families ?? 'N/A')}; supporting signals: ${String(provenance.supporting_signals ?? 'N/A')}.`);
    lines.push(`Final decision is restrictive: ${fileBool(!String(result.explanation?.decision || result.recommended_action || '').toUpperCase().startsWith('ALLOW'))}.`);
  }

  return lines;
};

const FileScoreMethodologyPanel: React.FC<{
  result: FileAnalysisResponse;
  selectedTerm: FileScoreTermKey | null;
  onSelectTerm: (term: FileScoreTermKey | null) => void;
}> = ({ result, selectedTerm, onSelectTerm }) => (
  <div className="bg-gray-900/50 border border-gray-700/50 rounded-lg p-5">
    <h3 className="font-semibold mb-2 flex items-center gap-2 text-white">
      <Info className="w-4 h-4 text-cyan-300" /> File Score Methodology
    </h3>
    <p className="mb-3 text-xs text-gray-400">Click a term to view its operation, equation, methodology, and current evidence.</p>
    <ul className="space-y-2 text-sm text-gray-300">
      {FILE_SCORE_ORDER.map((termKey) => {
        const term = FILE_SCORE_DEFINITIONS[termKey];
        const isOpen = selectedTerm === termKey;
        return (
          <li key={termKey}>
            <button
              type="button"
              onClick={() => onSelectTerm(isOpen ? null : termKey)}
              className="flex w-full items-center justify-between gap-3 rounded-md border border-gray-700/50 bg-gray-950/30 px-3 py-2 text-left transition-colors hover:border-cyan-500/50 hover:bg-cyan-500/10 focus:outline-none focus:ring-2 focus:ring-cyan-500/60"
              aria-expanded={isOpen}
            >
              <span className="flex min-w-0 items-center gap-2">
                <Info className="h-4 w-4 shrink-0 text-cyan-300" />
                <span className="font-medium text-gray-300">{term.label}</span>
              </span>
              <span className="flex shrink-0 items-center gap-2 font-mono text-gray-100">
                {filePct(fileTermValue(result, termKey))}
                <ChevronDown className={`h-4 w-4 text-gray-400 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
              </span>
            </button>
            {isOpen && (
              <div className="mt-2 rounded-md border border-cyan-500/30 bg-gray-950/50 p-3 text-xs text-gray-300 break-words">
                <p className="mb-3 text-sm text-gray-100">{term.summary}</p>
                <div className="grid gap-3 md:grid-cols-2">
                  <div>
                    <p className="mb-1 font-semibold text-cyan-200">Operation</p>
                    <p className="leading-relaxed">{term.operation}</p>
                  </div>
                  <div>
                    <p className="mb-1 font-semibold text-cyan-200">Methodology</p>
                    <p className="leading-relaxed">{term.methodology}</p>
                  </div>
                </div>
                <div className="mt-3">
                  <p className="mb-1 font-semibold text-cyan-200">Equation</p>
                  <pre className="whitespace-pre-wrap break-words rounded bg-black/30 p-2 font-mono text-[11px] leading-relaxed text-gray-200">
                    {term.equation}
                  </pre>
                </div>
                <div className="mt-3">
                  <p className="mb-1 font-semibold text-cyan-200">Current Analysis</p>
                  <ul className="list-disc space-y-1 pl-5">
                    {fileCurrentLines(result, termKey).map((line) => (
                      <li key={line}>{line}</li>
                    ))}
                  </ul>
                </div>
                <p className="mt-3 text-[11px] text-gray-500">Code path: {term.codePath}</p>
              </div>
            )}
          </li>
        );
      })}
    </ul>
  </div>
);

const FileScannerPage: React.FC = () => {
  const [result, setResult] = useState<FileAnalysisResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [lastFileName, setLastFileName] = useState<string | null>(null);
  const [preview, setPreview] = useState<
    | { kind: 'text'; content: string; truncated?: boolean }
    | { kind: 'image'; url: string }
    | { kind: 'none'; reason?: string }
    | null
  >(null);
  const objectUrlRef = useRef<string | null>(null);
  const { showNotification } = useNotification();
  const [showHighlights, setShowHighlights] = useState(true);
  const [selectedScoreTerm, setSelectedScoreTerm] = useState<FileScoreTermKey | null>(null);

  const ruleDescriptions: Record<string, string> = {
    webshell_indicators_php: 'PHP webshell indicators (exec + eval/file write)',
    potential_obfuscation: 'Obfuscation patterns (base64/eval/packers)',
    command_injection_and_reverse_shell_indicators: 'Command injection / reverse shell markers',
    office_macro_suspicious: 'Office macro auto-exec/shell indicators',
    pdf_suspicious_actions: 'PDF JS/OpenAction/Launch/EmbeddedFile',
    exploit_poc_generic_edb_cve: 'Exploit-DB/CVE write-up markers',
    exploit_poc_phpmyadmin_bruteforce: 'phpMyAdmin brute-force PoC markers',
    exploit_poc_generic_tools: 'GHDB/SearchSploit/OffSec banners + CVE',
    exploit_poc_python_generic: 'Python PoC scaffold (requests/urllib + argv + CVE)',
    exploit_poc_bruteforce_generic: 'Brute-force PoC markers (threading/cookiejar + login)',
    exploit_poc_powershell_downloader: 'PowerShell download/exec (IEX/WebClient/-enc)',
    exploit_poc_metasploit_module: 'Metasploit module scaffolding',
    exploit_poc_python_pwntools: 'pwntools/ROP/ELF patterns',
    exploit_poc_js_fetch_xhr: 'JS HTTP primitives + CVE/Exploit context',
    exploit_poc_generic_poc_terms: 'Generic PoC terms with code presence',
    obfuscation_base64_large_generic: 'Large base64 blobs + eval/exec',
    exploit_poc_writeup_generic: 'Exploit write-up (CVE + Exploit Title/PoC)',
    exploit_advisory_asan_generic: 'Exploit advisory (ASAN evidence + structured sections)',
    edb_header_block: 'Exploit-DB header (Exploit Database + EDB-ID/Author)',
    edb_metadata_with_cve: 'Exploit write-up with CVE + Exploit Title/PoC',
    edb_python_exploit_generic: 'Python PoC skeleton (requests/urllib/socket + argv)',
    edb_c_exploit_generic: 'C/C++ PoC skeleton (socket/connect + main)',
    edb_bash_exploit_generic: 'Bash PoC skeleton (nc/curl/wget)',
    edb_php_exploit_generic: 'PHP PoC skeleton (argv + http/file access)',
    edb_js_exfil_generic: 'JS PoC (XHR/fetch + cookie/localStorage)'
  };

  const statusMeta = useMemo(() => {
    if (!result) return null;
    const macro = macroDefenseFor(result);
    const macroStatus = macroDisplayStatus(macro);
    const status = String(result.overall_status || '').toLowerCase();
    const action = String(result.recommended_action || '').toUpperCase();
    if (macroStatus.color === 'red') {
      return { label: macroStatus.label, color: 'red' as const, Icon: ShieldX };
    }
    if (status.includes('review') || status.includes('suspicious') || action.includes('FLAG')) {
      return { label: macroStatus.color === 'yellow' ? macroStatus.label : 'File Requires Review', color: 'yellow' as const, Icon: ShieldAlert };
    }
    return result.is_malicious
      ? { label: 'Malicious file detected', color: 'red' as const, Icon: ShieldX }
      : { label: 'No threats detected', color: 'green' as const, Icon: FileCheck2 };
  }, [result]);

  const onDrop = useCallback(async (acceptedFiles: File[]) => {
    const file = acceptedFiles[0];
    if (!file) return;

    setIsLoading(true);
    setResult(null);
    setPreview(null);
    setSelectedScoreTerm(null);
    setLastFileName(file.name);

    try {
      // Build a quick local preview before uploading
      const isImage = file.type.startsWith('image/');
      const textLikeExt = (name: string) => /\.(txt|md|csv|json|js|ts|py|html|css|xml|log|sh|yml|yaml)$/i.test(name);
      const isTextLike = file.type.startsWith('text/') || textLikeExt(file.name);

      if (isImage) {
        if (objectUrlRef.current) URL.revokeObjectURL(objectUrlRef.current);
        const url = URL.createObjectURL(file);
        objectUrlRef.current = url;
        setPreview({ kind: 'image', url });
      } else if (isTextLike) {
        const MAX_BYTES = 100 * 1024; // 100KB preview
        const firstChunk = file.slice(0, MAX_BYTES);
        const text = await firstChunk.text();
        setPreview({ kind: 'text', content: text, truncated: file.size > MAX_BYTES });
      } else {
        setPreview({ kind: 'none', reason: 'Preview unavailable for this file type.' });
      }

      const response = await analyzeFile(file);
      setResult(response.data);
      showNotification(
        `File scan complete: ${response.data.filename}`,
        response.data.is_malicious ? 'warning' : 'success'
      );
    } catch (error) {
      console.error('File analysis failed:', error);
      showNotification('Failed to analyze file. Please try again.', 'error');
    } finally {
      setIsLoading(false);
    }
  }, [showNotification]);

  // Cleanup created object URL on unmount
  useEffect(() => {
    return () => {
      if (objectUrlRef.current) URL.revokeObjectURL(objectUrlRef.current);
      objectUrlRef.current = null;
    };
  }, []);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    multiple: false, // accept all types; omitting `accept` prevents browser MIME warnings
  });

  const highlightedPreview = useMemo(() => {
    if (!(preview && preview.kind === 'text' && showHighlights)) return null;
    const text = preview.content;
    const hl = (result?.highlights || [])
      .filter(h => typeof h.start === 'number' && typeof h.end === 'number' && h.start < text.length && h.end > 0)
      .map(h => ({ ...h, start: Math.max(0, h.start), end: Math.min(text.length, h.end) }))
      .sort((a, b) => a.start - b.start);
    if (hl.length === 0) return null;
    const parts: React.ReactNode[] = [];
    let cursor = 0;
    const cls = (sev?: string) => sev === 'high' ? 'bg-red-900/40 text-red-200' : sev === 'medium' ? 'bg-yellow-900/40 text-yellow-200' : 'bg-cyan-900/30 text-cyan-200';
    hl.forEach((h, idx) => {
      if (h.start > cursor) {
        parts.push(<span key={`p${idx}-n`}>{text.slice(cursor, h.start)}</span>);
      }
      parts.push(
        <span key={`p${idx}-h`} className={`rounded-sm ${cls(h.severity)} px-0.5`} title={h.label}>
          {text.slice(h.start, h.end)}
        </span>
      );
      cursor = h.end;
    });
    if (cursor < text.length) parts.push(<span key={`p-last`}>{text.slice(cursor)}</span>);
    return parts;
  }, [preview, result?.highlights, showHighlights]);

  return (
    <div className="p-4 sm:p-6 md:p-8 text-white">
      <div className="w-full max-w-4xl mx-auto bg-gray-900/70 border border-gray-700/60 rounded-2xl shadow-2xl backdrop-blur-md p-6 md:p-8">
      <header className="mb-6 text-center">
        <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-white">
          Scan Files for Threats
        </h1>
        <p className="text-gray-300/90 mt-2 leading-relaxed">
          Upload a file for a comprehensive security check. We run signature-based and ML analysis locally and never store your file.
        </p>
      </header>

      <section
        {...getRootProps()}
        className={`relative flex flex-col items-center justify-center p-10 rounded-xl border-2 border-dashed transition-colors duration-300
          ${isDragActive ? 'border-cyan-400 bg-cyan-950/40' : 'border-gray-600 hover:border-gray-500 hover:bg-gray-800/40'}`}
      >
        <input {...getInputProps()} />
        <UploadCloud className="w-12 h-12 text-gray-200 mb-4" />
        <p className="text-lg font-semibold text-white drop-shadow">
          {isDragActive ? 'Drop the file here' : 'Drag a file here, or click to browse'}
        </p>
        <p className="text-sm text-gray-300/90 mt-1">Max 10 MB. Supported: jpg, png, txt, pdf, doc/docx/docm, xls/xlsx/xlsm, ppt/pptx/pptm, zip.</p>
        {isLoading && (
          <div className="absolute inset-0 backdrop-blur-sm bg-black/20 rounded-xl grid place-items-center">
            <div className="flex items-center gap-3 text-sm">
              <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white" />
              <span className="text-white/95">Scanning{lastFileName ? `: ${lastFileName}` : ' file'}...</span>
            </div>
          </div>
        )}
      </section>

      {result && statusMeta && (
        <section className="mt-6 space-y-6">
          {/* Status banner */}
          <div
            className={`flex items-start gap-3 p-4 rounded-lg border ${
              statusMeta.color === 'red'
                ? 'bg-red-500/10 border-red-500/30'
                : statusMeta.color === 'yellow'
                ? 'bg-yellow-500/10 border-yellow-500/30'
                : 'bg-green-500/10 border-green-500/30'
            }`}
          >
            <statusMeta.Icon className={`w-6 h-6 ${statusMeta.color === 'red' ? 'text-red-400' : statusMeta.color === 'yellow' ? 'text-yellow-300' : 'text-green-400'}`} />
            <div>
              <p className="text-lg font-semibold text-white">
                {statusMeta.label}
              </p>
              <p className="text-gray-200/95 text-sm"><span className="font-medium">Filename:</span> <span className="font-mono break-all">{result.filename}</span></p>
            </div>
            <div className="ml-auto">
              <Badge label={statusMeta.label.toUpperCase()} color={statusMeta.color} />
            </div>
          </div>

          {/* Details grid */}
          <div className="grid grid-cols-1 2xl:grid-cols-2 gap-6">
            <div className="min-w-0 bg-gray-900/50 border border-gray-700/50 rounded-lg p-5">
              <h3 className="font-semibold mb-3 flex items-center gap-2 text-white">
                <ShieldAlert className="w-4 h-4 text-cyan-300" /> Scan summary
              </h3>
              <ul className="text-sm text-gray-300 space-y-2">
                <li className="grid grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)] gap-x-3">
                  <span className="text-gray-400">File name</span>
                  <span className="min-w-0 break-all text-right font-mono">{result.filename}</span>
                </li>
                <li className="grid grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)] gap-x-3">
                  <span className="text-gray-400">Matched rules</span>
                  <span className="text-right">{result.matched_rules.length}</span>
                </li>
                <li className="grid grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)] gap-x-3">
                  <span className="text-gray-400">Recommendation</span>
                  <span className="min-w-0 break-words text-right font-medium">
                    {fileLabelize(result.recommended_action || macroDefenseFor(result).recommended_handling || (result.is_malicious ? 'review' : 'allow'))}
                  </span>
                </li>
                <li className="grid grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)] gap-x-3">
                  <span className="text-gray-400">File Risk</span>
                  <span className="text-right font-mono">{filePct(fileRiskFor(result), 2)}</span>
                </li>
                <li className="grid grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)] gap-x-3">
                  <span className="text-gray-400">Decision Confidence</span>
                  <span className="text-right font-mono">{filePct(fileDecisionConfidenceFor(result), 2)}</span>
                </li>
                {result.mime_type && (
                  <li className="grid grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)] gap-x-3">
                    <span className="text-gray-400">MIME type</span>
                    <span className="min-w-0 break-words text-right">{result.mime_type}</span>
                  </li>
                )}
                {typeof result.file_size_kb === 'number' && (
                  <li className="grid grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)] gap-x-3">
                    <span className="text-gray-400">Size</span>
                    <span className="text-right">{result.file_size_kb?.toFixed(1)} KB</span>
                  </li>
                )}
              </ul>
              {result.short_summary && (
                <div className="mt-3 text-sm text-gray-200/95">
                  <span className="text-gray-400">Short analysis:</span> {result.short_summary}
                </div>
              )}
            </div>

            <div className="min-w-0 bg-gray-900/50 border border-gray-700/50 rounded-lg p-5">
              <h3 className="font-semibold mb-3 flex items-center gap-2 text-white">
                <Info className="w-4 h-4 text-cyan-300" /> Matched signatures
              </h3>
              {result.matched_rules.length > 0 ? (
                <ul className="space-y-2 text-sm text-yellow-300/90">
                  {result.matched_rules.map(rule => (
                    <li key={rule} className="min-w-0 pl-4">
                      <span className="block max-w-full break-all font-mono leading-relaxed">{rule}</span>
                      {ruleDescriptions[rule] && (
                        <span className="block max-w-full break-words text-gray-300/90 leading-relaxed">- {ruleDescriptions[rule]}</span>
                      )}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-sm text-gray-300/95">No known signatures matched.</p>
              )}
            </div>
          </div>

          {(() => {
            const macro = macroDefenseFor(result);
            const macroStatus = macroDisplayStatus(macro);
            const reasons = Array.isArray(macro.evidence_reasons) ? macro.evidence_reasons : [];
            const limitations = Array.isArray(macro.limitations) ? macro.limitations : [];
            const riskyIndicators = [
              ...(Array.isArray(macro.auto_exec_indicators) ? macro.auto_exec_indicators.map((x: string) => `Auto-exec: ${x}`) : []),
              ...(Array.isArray(macro.execution_indicators) ? macro.execution_indicators.map((x: string) => `Execution: ${x}`) : []),
              ...(Array.isArray(macro.network_indicators) ? macro.network_indicators.map((x: string) => `Network: ${x}`) : []),
              ...(Array.isArray(macro.obfuscation_indicators) ? macro.obfuscation_indicators.map((x: string) => `Obfuscation: ${x}`) : []),
              ...(Array.isArray(macro.external_reference_indicators) ? macro.external_reference_indicators.map((x: string) => `External: ${x}`) : []),
              ...(Array.isArray(macro.embedded_object_indicators) ? macro.embedded_object_indicators.map((x: string) => `Embedded: ${x}`) : []),
            ];
            return (
              <div className="bg-gray-900/50 border border-gray-700/50 rounded-lg p-5">
                <div className="flex items-center justify-between gap-3 flex-wrap">
                  <h3 className="font-semibold flex items-center gap-2 text-white">
                    <ShieldAlert className="w-4 h-4 text-cyan-300" /> Macro Defence
                  </h3>
                  <Badge label={macroStatus.label} color={macroStatus.color} />
                </div>
                <div className="mt-3 grid grid-cols-1 gap-3 text-sm text-gray-200/95 sm:grid-cols-2 lg:grid-cols-4">
                  <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3">
                    <p className="text-xs text-gray-400">Macro Present</p>
                    <p className="font-medium">{fileBool(macro.macro_present)}</p>
                  </div>
                  <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3">
                    <p className="text-xs text-gray-400">Macro Risk Level</p>
                    <p className="font-medium">{fileLabelize(macro.macro_risk_level)}</p>
                  </div>
                  <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3">
                    <p className="text-xs text-gray-400">Macro Risk Score</p>
                    <p className="font-medium font-mono">{filePct(macro.macro_risk_score, 2)}</p>
                  </div>
                  <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3">
                    <p className="text-xs text-gray-400">Recommended Handling</p>
                    <p className="font-medium">{fileLabelize(macro.recommended_handling)}</p>
                  </div>
                  <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3">
                    <p className="text-xs text-gray-400">Container Type</p>
                    <p className="font-medium break-words">{fileLabelize(macro.macro_container_type || 'none')}</p>
                  </div>
                  <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3">
                    <p className="text-xs text-gray-400">Source Trust / MOTW</p>
                    <p className="font-medium break-words">{fileLabelize(macro.source_trust || 'unknown')} / {fileLabelize(macro.motw_zone || 'not supplied')}</p>
                  </div>
                  <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3">
                    <p className="text-xs text-gray-400">Signed Macro</p>
                    <p className="font-medium">{macro.signed_macro === true ? 'Yes' : macro.signed_macro === false ? 'No' : 'Not supplied'}</p>
                  </div>
                  <div className="rounded-md border border-gray-700/50 bg-gray-800/40 p-3">
                    <p className="text-xs text-gray-400">Trusted Publisher</p>
                    <p className="font-medium">{macro.trusted_publisher === true ? 'Yes' : macro.trusted_publisher === false ? 'No' : 'Not supplied'}</p>
                  </div>
                </div>
                {riskyIndicators.length > 0 ? (
                  <div className="mt-4">
                    <p className="text-xs font-semibold uppercase tracking-wide text-gray-400">Risky Indicators</p>
                    <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-gray-200/95">
                      {riskyIndicators.slice(0, 12).map((item) => <li key={item} className="break-words">{item}</li>)}
                    </ul>
                  </div>
                ) : (
                  <p className="mt-4 text-sm text-gray-300/95">No risky macro behaviour indicators were returned.</p>
                )}
                {reasons.length > 0 ? (
                  <div className="mt-4">
                    <p className="text-xs font-semibold uppercase tracking-wide text-gray-400">Evidence Reasons</p>
                    <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-gray-200/95">
                      {reasons.slice(0, 8).map((item: string) => <li key={item} className="break-words">{item}</li>)}
                    </ul>
                  </div>
                ) : null}
                {limitations.length > 0 ? (
                  <div className="mt-4">
                    <p className="text-xs font-semibold uppercase tracking-wide text-gray-400">Limitations</p>
                    <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-amber-200/95">
                      {limitations.slice(0, 6).map((item: string) => <li key={item} className="break-words">{item}</li>)}
                    </ul>
                  </div>
                ) : null}
              </div>
            );
          })()}

          <FileScoreMethodologyPanel
            result={result}
            selectedTerm={selectedScoreTerm}
            onSelectTerm={setSelectedScoreTerm}
          />

          {result.explanation && (
            <ExplainabilityPanel explanation={result.explanation} title="Explainable AI (Why this file was flagged)" />
          )}

          {/* Highlights controls & legend */}
          {preview?.kind === 'text' && (
            <div className="bg-gray-900/50 border border-gray-700/50 rounded-lg p-4 flex items-start justify-between gap-4">
              <div className="flex items-center gap-2">
                <input id="toggle-hl" type="checkbox" checked={showHighlights} onChange={(e)=> setShowHighlights(e.target.checked)} />
                <label htmlFor="toggle-hl" className="text-sm text-gray-200">Show highlights</label>
              </div>
              <div className="text-xs text-gray-300 flex flex-wrap gap-2">
                <span className="inline-flex items-center gap-1"><span className="px-1 rounded-sm bg-yellow-900/40 text-yellow-200">&nbsp;&nbsp;</span> Evidence terms</span>
                <span className="inline-flex items-center gap-1"><span className="px-1 rounded-sm bg-cyan-900/30 text-cyan-200">&nbsp;&nbsp;</span> Top tokens</span>
              </div>
            </div>
          )}

          {/* Why flagged? (collapsible) */}
          {Array.isArray(result.reasoning) && result.reasoning.length > 0 && (
            <div className="bg-gray-900/50 border border-gray-700/50 rounded-lg p-5">
              <details>
                <summary className="cursor-pointer select-none text-white font-semibold">Why flagged?</summary>
                <ul className="mt-3 list-disc list-inside text-sm text-gray-200/95 space-y-1">
                  {result.reasoning.map((r, idx) => (
                    <li key={idx} className="whitespace-pre-wrap break-words">{r}</li>
                  ))}
                </ul>
              </details>
            </div>
          )}
          {/* File preview */}
          <div className="bg-gray-900/50 border border-gray-700/50 rounded-lg p-5">
            <h3 className="font-semibold mb-3 flex items-center gap-2 text-white">
              <Info className="w-4 h-4 text-cyan-300" /> File preview
            </h3>
            {!preview && (
              <p className="text-sm text-gray-300/95">No preview available. Upload a file to see its contents here.</p>
            )}
            {preview?.kind === 'image' && (
              <div className="rounded-md overflow-hidden border border-gray-700/50 bg-black/40">
                <img src={preview.url} alt="Uploaded preview" className="max-h-96 w-auto mx-auto object-contain" />
              </div>
            )}
            {preview?.kind === 'text' && (
              <pre className="text-xs sm:text-sm leading-relaxed max-h-80 overflow-auto bg-black/40 border border-gray-700/50 rounded-md p-3 whitespace-pre-wrap">
                {highlightedPreview || preview.content}
              </pre>
            )}
            {preview?.kind === 'text' && preview.truncated && (
              <p className="mt-2 text-xs text-gray-400">Preview truncated to 100KB.</p>
            )}
            {preview?.kind === 'none' && (
              <p className="text-sm text-gray-300/95">{preview.reason || 'Preview unavailable for this file type.'}</p>
            )}
          </div>
        </section>
      )}
      </div>
    </div>
  );
};

export default FileScannerPage;


