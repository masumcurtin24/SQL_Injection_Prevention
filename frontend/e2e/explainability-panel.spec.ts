import { expect, test, type Page } from '@playwright/test';

const authUser = { id: 'u-admin', email: 'admin@example.com', tenant_id: 'tenant-demo', role: 'admin' };

async function mockApis(page: Page): Promise<void> {
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
    if (path.endsWith('/analyze-spam/email')) {
      return json({
        analysis_id: 'spam-xai-1',
        analysis_timestamp: '2026-05-13T03:30:00Z',
        received_subject: 'Password notice',
        spam_classification: {
          is_spam: true,
          spam_score: 0.5062,
          decision_confidence: 0.5062,
          classification_label: 'Suspicious (Review)',
        },
        explanation: {
          decision: 'FLAG_FOR_REVIEW',
          severity: 'Medium',
          threat_category: 'Spam/Phishing',
          risk_score: 0.5062,
          spam_risk: 0.5062,
          decision_confidence: 0.5062,
          confidence: 0.5062,
          uncertainty_score: 0.969,
          uncertainty_components: {
            threshold_margin_uncertainty: 0.969,
            component_disagreement_uncertainty: 0.08,
            missing_component_uncertainty: 0.1,
            ood_score: 0.1,
            low_fidelity_uncertainty: 0.375,
          },
          fidelity_score: 0.625,
          ood_score: 0.1,
          score_semantics: {
            risk_score: 0.5062,
            risk_label: 'Spam/Phishing Risk',
            decision_confidence: 0.5062,
            uncertainty_score: 0.969,
            uncertainty_components: {
              threshold_margin_uncertainty: 0.969,
              component_disagreement_uncertainty: 0.08,
              missing_component_uncertainty: 0.1,
              ood_score: 0.1,
            },
            ood_score: 0.1,
            fidelity_score: 0.625,
            reliability_score: 0.033,
            score_type_notes: [
              'Threat risk estimates how dangerous the input appears; it is not the same as decision confidence.',
              'AI Reliability is deterministic decision-governance logic, not a learned calibration model.',
            ],
          },
          evidence_contributions: [
            {
              name: 'classical',
              category: 'model_component',
              value: 0.48,
              weight: 0.4,
              normalized_contribution: 0.192,
              direction: 'mixed',
              explanation: 'Weighted fusion component; normalized contribution is score x weight divided by total active weight.',
              source: 'model_attributions',
            },
            {
              name: 'Near spam threshold',
              category: 'policy',
              value: 0.5062,
              weight: null,
              normalized_contribution: null,
              direction: 'raises_risk',
              explanation: 'Risk is close to the review threshold.',
              source: 'threshold_review',
            },
          ],
          decision_rationale: {
            final_decision: 'FLAG_FOR_REVIEW',
            decision_type: 'review_required',
            recommended_handling: 'review',
            hard_decision: false,
            review_required: true,
            review_reasons: ['Decision confidence is below the operational threshold.'],
            thresholds_applied: { suspicious: 0.5, block: 0.8 },
            policy_overrides: [],
            limitations: ['This score is a calibrated project risk score, not a guaranteed probability.'],
          },
          plain_language_summary:
            'Spam/Phishing Risk is 50.62%; decision confidence is 50.62%. Recommended handling is review. Review is required because Decision confidence is below the operational threshold.',
          technical_summary:
            'Spam/Phishing Risk comes from the analyzer calibrated fusion/rule pipeline. Decision confidence is not rewritten by uncertainty.',
          limitations: ['AI Reliability is deterministic decision-governance logic, not a learned calibration model.'],
          remediation: ['Route to analyst review before blocking.'],
          ai_reliability: {
            reliability_score: 0.033,
            reliability_status: 'low_confidence',
            review_required: true,
            review_reasons: ['Decision confidence is below the operational threshold.'],
            signal_conflicts: [],
            policy_override: false,
            adversarial_suspicion: false,
            recommended_handling: 'review',
            reliability_factors: {},
          },
        },
        ai_reliability: {
          reliability_score: 0.033,
          reliability_status: 'low_confidence',
          review_required: true,
          review_reasons: ['Decision confidence is below the operational threshold.'],
          signal_conflicts: [],
          policy_override: false,
          adversarial_suspicion: false,
          recommended_handling: 'review',
          reliability_factors: {},
        },
        decision_display: {
          status_label: 'Needs Review — Possible Spam/Phishing',
          status_color: 'amber',
          hard_detection: false,
          review_required: true,
          recommended_handling: 'review',
          reliability_status: 'low_confidence',
          detail: 'Grey-zone or reliability guardrail conditions require analyst review before treating the result as final.',
        },
      });
    }
    return json({});
  });
}

test('explainability panel separates scores, evidence, governance, and limitations', async ({ page }) => {
  await mockApis(page);

  await page.goto('/');
  await page.locator('input[type="password"]').fill('admin-password-123');
  await page.getByRole('button', { name: /^Sign in$/i }).click();
  await page.getByRole('button', { name: /Email Security/i }).click();

  await page.getByPlaceholder('Paste email or message here...').fill('Please review this password notice.');
  await page.getByRole('button', { name: /Analyze Text/i }).click();

  await expect(page.getByText('Decision Summary')).toBeVisible();
  await expect(page.getByText('Score Semantics')).toBeVisible();
  await expect(page.getByText('Evidence Contributions')).toBeVisible();
  await expect(page.getByText('Review Reasons')).toBeVisible();
  await expect(page.getByText('Technical Summary')).toBeVisible();
  await expect(page.getByText('Limitations')).toBeVisible();
  await expect(page.getByText('Spam/Phishing Risk').first()).toBeVisible();
  await expect(page.getByText('Decision Confidence').first()).toBeVisible();
  await expect(page.getByText('Review Required').first()).toBeVisible();
  await expect(page.getByText('Weighted fusion component', { exact: false }).first()).toBeVisible();
});
