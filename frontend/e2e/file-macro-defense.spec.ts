import { expect, test, type Page } from '@playwright/test';

const authUser = { id: 'u-admin', email: 'admin@example.com', tenant_id: 'tenant-demo', role: 'admin' };

async function mockFileApis(page: Page): Promise<void> {
  await page.route('**/api/v1/**', async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    const json = (payload: unknown) =>
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(payload),
      });

    if (path.endsWith('/auth/me')) return json(authUser);
    if (path.endsWith('/auth/login')) {
      return json({ access_token: 'test-token', token_type: 'bearer', expires_in: 3600, user: authUser });
    }
    if (path.endsWith('/dashboard/stats')) {
      return json({ total_queries: 0, malicious_queries: 0, files_scanned: 0, spam_detected: 0 });
    }
    if (path.endsWith('/dashboard/spam-detections')) {
      return json({ day: '2026-05-13', count: 0, detected_only: false, detections: [] });
    }
    if (path.endsWith('/analyze-file/file')) {
      return json({
        analysis_id: 'file-macro-1',
        analysis_timestamp: '2026-05-13T04:20:00Z',
        file_details: {
          filename: 'invoice.docm',
          filesize_kb: 2.1,
          type_validation: {
            detected_mime_type: 'application/vnd.ms-word.document.macroEnabled.12',
            is_allowed_type: true,
            extension_provided: '.docm',
          },
          malware_scan: {
            scan_engine_version: 'YARA + optional ClamAV',
            is_malicious: false,
            threat_name: null,
            scan_details: {
              macro: {
                present: true,
                risky: true,
                indicators: ['AutoOpen', 'WScript.Shell', 'powershell'],
              },
            },
          },
          ml_scan: null,
          macro_defense: {
            macro_present: true,
            macro_container_type: 'ooxml_vba_project',
            macro_risk_score: 0.92,
            macro_risk_level: 'critical',
            macro_indicators: ['AutoOpen', 'WScript.Shell', 'powershell'],
            auto_exec_indicators: ['AutoOpen'],
            execution_indicators: ['WScript.Shell', 'powershell'],
            network_indicators: [],
            obfuscation_indicators: [],
            external_reference_indicators: [],
            embedded_object_indicators: [],
            motw_zone: null,
            source_trust: 'unknown',
            signed_macro: null,
            trusted_publisher: null,
            recommended_handling: 'block_request',
            evidence_reasons: [
              'OOXML package contains vbaProject.bin macro container.',
              'Auto-execution macro indicators: AutoOpen.',
              'Macro execution indicators: WScript.Shell, powershell.',
              'Auto-execution combined with command interpreter or LOLBin execution is critical macro behaviour.',
            ],
            limitations: [
              'Source-zone / Mark-of-the-Web metadata was not supplied by the upload context.',
              'Static macro defence does not execute macros and does not claim sandbox detonation.',
              'Block/quarantine labels are requests or recommendations unless an enforcement integration performs durable action.',
            ],
          },
        },
        macro_defense: {
          macro_present: true,
          macro_container_type: 'ooxml_vba_project',
          macro_risk_score: 0.92,
          macro_risk_level: 'critical',
          macro_indicators: ['AutoOpen', 'WScript.Shell', 'powershell'],
          auto_exec_indicators: ['AutoOpen'],
          execution_indicators: ['WScript.Shell', 'powershell'],
          network_indicators: [],
          obfuscation_indicators: [],
          external_reference_indicators: [],
          embedded_object_indicators: [],
          motw_zone: null,
          source_trust: 'unknown',
          signed_macro: null,
          trusted_publisher: null,
          recommended_handling: 'block_request',
          evidence_reasons: [
            'OOXML package contains vbaProject.bin macro container.',
            'Auto-execution macro indicators: AutoOpen.',
            'Macro execution indicators: WScript.Shell, powershell.',
            'Auto-execution combined with command interpreter or LOLBin execution is critical macro behaviour.',
          ],
          limitations: [
            'Source-zone / Mark-of-the-Web metadata was not supplied by the upload context.',
            'Static macro defence does not execute macros and does not claim sandbox detonation.',
            'Block/quarantine labels are requests or recommendations unless an enforcement integration performs durable action.',
          ],
        },
        overall_assessment: {
          overall_status: 'Critical Macro Behaviour Detected',
          risk_score: 0.92,
          recommended_action: 'BLOCK_REQUEST',
          reasoning: ['Auto-execution combined with command interpreter or LOLBin execution is critical macro behaviour.'],
        },
        structured_verdict: {
          analysis_id: 'file-macro-1',
          classification: 'blocked',
          severity: 'high',
          score: 0.92,
          confidence: 0.92,
          declared_type: '.docm',
          detected_type: 'application/vnd.ms-word.document.macroEnabled.12',
          matched_rules: [],
          matched_signatures: [],
          iocs: [],
          evidence_items: [],
          archive_lineage: [],
          macro_defense: null,
          analysis_stages: [],
          analyst_summary: 'Critical Macro Behaviour Detected',
        },
        explanation: {
          decision: 'BLOCK_REQUEST',
          severity: 'High',
          threat_category: 'File upload scanning',
          risk_score: 0.92,
          decision_confidence: 0.92,
          confidence: 0.92,
          provenance: {
            macro_defense: {
              macro_present: true,
              macro_container_type: 'ooxml_vba_project',
              macro_risk_score: 0.92,
              macro_risk_level: 'critical',
              recommended_handling: 'block_request',
              evidence_reasons: ['Auto-execution combined with command interpreter or LOLBin execution is critical macro behaviour.'],
            },
          },
          remediation: ['Block Request or Quarantine Request according to configured policy; do not claim completed durable quarantine unless enforcement is connected.'],
        },
      });
    }
    return json({});
  });
}

test('risky macro result shows Macro Defence evidence and request wording', async ({ page }) => {
  await mockFileApis(page);

  await page.goto('/');
  await page.locator('input[type="password"]').fill('admin-password-123');
  await page.getByRole('button', { name: /^Sign in$/i }).click();
  await page.getByRole('button', { name: /File Security/i }).click();

  await page.locator('input[type="file"]').setInputFiles({
    name: 'invoice.docm',
    mimeType: 'application/vnd.ms-word.document.macroEnabled.12',
    buffer: Buffer.from('macro test file'),
  });

  await expect(page.getByText('Critical Macro Behaviour Detected').first()).toBeVisible();
  await expect(page.getByText('Macro Defence').first()).toBeVisible();
  await expect(page.getByText('Auto-exec: AutoOpen')).toBeVisible();
  await expect(page.getByText('Execution: WScript.Shell')).toBeVisible();
  await expect(page.getByText('Execution: powershell')).toBeVisible();
  await expect(page.getByText('Block Request').first()).toBeVisible();
  await expect(page.getByText('Static macro defence does not execute macros and does not claim sandbox detonation.').first()).toBeVisible();
  await expect(page.getByText(/^Blocked$/i)).toHaveCount(0);
  await expect(page.getByText(/^Quarantined$/i)).toHaveCount(0);
});
