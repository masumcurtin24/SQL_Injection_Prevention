import { expect, test, type Page } from '@playwright/test';

const authUser = { id: 'u-admin', email: 'admin@example.com', tenant_id: 'tenant-demo', role: 'admin' };

async function mockSpamApis(page: Page): Promise<void> {
  await page.route('**/api/v1/**', async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    const json = (payload: unknown) =>
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(payload),
      });

    if (path.endsWith('/auth/me')) {
      return json(authUser);
    }
    if (path.endsWith('/auth/login')) {
      return json({
        access_token: 'test-token',
        token_type: 'bearer',
        expires_in: 3600,
        user: authUser,
      });
    }
    if (path.endsWith('/dashboard/stats')) {
      return json({
        total_queries: 0,
        malicious_queries: 0,
        files_scanned: 0,
        spam_detected: 0,
      });
    }
    if (path.endsWith('/dashboard/spam-detections')) {
      return json({ day: '2026-05-13', count: 0, detected_only: false, detections: [] });
    }
    if (path.endsWith('/analyze-spam/email')) {
      const requestBody = request.postDataJSON?.() as { body_text?: string } | undefined;
      const submittedText = String(requestBody?.body_text || '').toLowerCase();
      if (submittedText.includes('dhl.com/en/express/tracking')) {
        return json({
          analysis_id: 'spam-official-dhl-1',
          analysis_timestamp: '2026-05-13T04:10:00Z',
          received_subject: 'DHL shipment update',
          spam_classification: {
            is_spam: false,
            spam_score: 0.12,
            decision_confidence: 0.88,
            classification_label: 'Ham',
          },
          score_breakdown: {
            final: 0.12,
            decision_confidence: 0.88,
            raw_fused: 0.10,
            courier_phishing: 0.0,
            ood: 0.0,
          },
          meta_features: {
            courier_phishing_score: 0.0,
            claimed_brand: 'DHL',
            courier_official_domain_context: true,
          },
          explanation: {
            decision: 'ALLOW',
            severity: 'Low',
            threat_category: 'Spam/Phishing',
            risk_score: 0.12,
            spam_risk: 0.12,
            decision_confidence: 0.88,
            confidence: 0.88,
            remediation: ['No strong indicators found.', 'Continue normal handling.', 'Monitor if similar reports appear.'],
          },
          ai_reliability: {
            reliability_score: 0.82,
            reliability_status: 'reliable',
            review_required: false,
            review_reasons: [],
            signal_conflicts: [],
            policy_override: false,
            adversarial_suspicion: false,
            recommended_handling: 'allow',
            reliability_factors: {},
          },
          decision_display: {
            status_label: 'Not Spam',
            status_color: 'green',
            hard_detection: false,
            review_required: false,
            recommended_handling: 'allow',
            reliability_status: 'reliable',
            detail: 'No review gate or high-risk handling path was triggered.',
          },
          defender_actions: ['log_only'],
        });
      }
      if (submittedText.includes('customs') && submittedText.includes('fast-post-tracking')) {
        return json({
          analysis_id: 'spam-courier-customs-1',
          analysis_timestamp: '2026-05-13T04:05:00Z',
          received_subject: 'DHL parcel hold - Customs',
          spam_classification: {
            is_spam: true,
            spam_score: 0.85,
            decision_confidence: 0.85,
            classification_label: 'Phishing',
          },
          score_breakdown: {
            final: 0.85,
            decision_confidence: 0.85,
            raw_fused: 0.56,
            heuristic: 0.90,
            reputation: 0.15,
            campaign: 0.54,
            fraud_pattern: 0.94,
            bec_fraud: 0.94,
            courier_phishing: 0.94,
            brand_impersonation: 0.72,
            payment_link_impersonation: 0.78,
            fraud_category: 'courier_customs_fee_phishing',
            bec_risk_floor: 0.85,
            ood: 0.05,
          },
          url_indicators: {
            total_urls: 1,
            hosts: ['fast-post-tracking.net'],
            reputation_score_avg: 0.15,
            reputation_score_max: 0.15,
          },
          meta_features: {
            sender: 'Notice Desk <notice@fast-post-tracking.net>',
            domain: 'fast-post-tracking.net',
            bec_fraud_score: 0.94,
            courier_phishing_score: 0.94,
            fraud_category: 'courier_customs_fee_phishing',
            fraud_category_label: 'Courier/customs fee phishing',
            courier_category: 'courier_customs_fee_phishing',
            claimed_brand: 'DHL',
            brand_domain_mismatch: true,
            sender_domain_mismatch: true,
            suspicious_payment_link: true,
            courier_link_domains: ['fast-post-tracking.net'],
            courier_payment_fee_lure: true,
            courier_urgency_or_threat: true,
            courier_tracking_lure: true,
            bec_matched_patterns: ['claimed_courier_brand', 'payment_or_fee_lure', 'suspicious_payment_link', 'brand_domain_mismatch'],
            bec_evidence_reasons: [
              'Courier delivery/customs fee payment lure detected.',
              'Claimed DHL identity but link domain is not an official DHL domain.',
              'Urgency/return-to-sender threat increases phishing risk.',
            ],
            courier_evidence_reasons: [
              'Courier delivery/customs fee payment lure detected.',
              'Claimed DHL identity but link domain is not an official DHL domain.',
              'Urgency/return-to-sender threat increases phishing risk.',
              'Tracking-number or tracking-domain language is used to increase legitimacy.',
            ],
            bec_risk_floor: 0.85,
          },
          explanation: {
            decision: 'BLOCK_EMAIL',
            severity: 'High',
            threat_category: 'Spam/Phishing',
            risk_score: 0.85,
            spam_risk: 0.85,
            decision_confidence: 0.85,
            confidence: 0.85,
            remediation: [
              'Do not click the payment or tracking link.',
              'Do not enter card, banking, or personal details.',
              'Verify delivery status through the official courier website or app.',
              'Check sender and link domains independently.',
              'Report the message to SOC/security team.',
              'Use block-request or quarantine-request wording only as an action plan.',
            ],
          },
          ai_reliability: {
            reliability_score: 0.70,
            reliability_status: 'reliable',
            review_required: false,
            review_reasons: [],
            signal_conflicts: [],
            policy_override: false,
            adversarial_suspicion: false,
            recommended_handling: 'block',
            reliability_factors: {},
          },
          decision_display: {
            status_label: 'High-Risk Courier/Customs Fee Phishing Detected',
            status_color: 'red',
            hard_detection: true,
            review_required: false,
            recommended_handling: 'block',
            reliability_status: 'reliable',
            detail: 'High-risk BEC/phishing evidence supports a block-request action plan; this is not a claim of completed gateway enforcement.',
          },
          defender_actions: ['block_request', 'notify_soc', 'preserve_evidence', 'domain_block_request', 'url_block_request'],
        });
      }
      if (submittedText.includes('gift cards')) {
        return json({
          analysis_id: 'spam-bec-gift-card-1',
          analysis_timestamp: '2026-05-13T03:35:00Z',
          received_subject: 'Quick task before board call',
          spam_classification: {
            is_spam: true,
            spam_score: 0.82,
            decision_confidence: 0.82,
            classification_label: 'Phishing',
          },
          score_breakdown: {
            final: 0.82,
            decision_confidence: 0.82,
            raw_fused: 0.50,
            heuristic: 0.86,
            fraud_pattern: 0.98,
            bec_fraud: 0.98,
            fraud_category: 'gift_card_fraud',
            bec_risk_floor: 0.82,
            ood: 0.05,
          },
          meta_features: {
            bec_fraud_score: 0.98,
            fraud_category: 'gift_card_fraud',
            fraud_category_label: 'Gift-card fraud',
            bec_matched_patterns: ['gift_card_purchase', 'pin_or_card_number_exfiltration', 'send_photo_or_code', 'urgency_unavailability'],
            bec_evidence_reasons: [
              'Gift-card purchase request with PIN/card-number exfiltration',
              'Request to send photos/codes rather than normal procurement records',
              'Urgency or unavailability pattern common in BEC fraud',
            ],
            bec_risk_floor: 0.82,
          },
          explanation: {
            decision: 'BLOCK_EMAIL',
            severity: 'High',
            threat_category: 'Spam/Phishing',
            risk_score: 0.82,
            spam_risk: 0.82,
            decision_confidence: 0.82,
            confidence: 0.82,
            remediation: [
              'Do not purchase gift cards.',
              'Do not send card numbers, PINs, codes, or photos.',
              'Verify the request through a trusted channel.',
              'Report to SOC or a manager.',
              'Create a block request or quarantine according to configured policy after review or policy approval.',
            ],
          },
          ai_reliability: {
            reliability_score: 0.60,
            reliability_status: 'reliable',
            review_required: false,
            review_reasons: [],
            signal_conflicts: [],
            policy_override: false,
            adversarial_suspicion: false,
            recommended_handling: 'block',
            reliability_factors: {},
          },
          decision_display: {
            status_label: 'High-Risk BEC / Gift-Card Fraud Detected',
            status_color: 'red',
            hard_detection: true,
            review_required: false,
            recommended_handling: 'block',
            reliability_status: 'reliable',
            detail: 'High-risk BEC/phishing evidence supports a block-request action plan; this is not a claim of completed gateway enforcement.',
          },
          defender_actions: ['block_request', 'notify_soc', 'preserve_evidence'],
        });
      }
      return json({
        analysis_id: 'spam-grey-zone-1',
        analysis_timestamp: '2026-05-13T03:30:00Z',
        received_subject: 'Password notice',
        spam_classification: {
          is_spam: true,
          spam_score: 0.5062,
          decision_confidence: 0.5062,
          classification_label: 'Suspicious (Review)',
        },
        score_breakdown: {
          final: 0.5062,
          decision_confidence: 0.5062,
          raw_fused: 0.501,
          ood: 0.1,
          uncertainty_components: {
            threshold_margin_uncertainty: 0.969,
            component_disagreement_uncertainty: 0.08,
            missing_component_uncertainty: 0.1,
            ood_score: 0.1,
          },
        },
        meta_features: {
          ood_score: 0.1,
          uncertainty_score: 0.969,
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
          },
          fidelity_score: 0.625,
          ood_score: 0.1,
          remediation: [
            'Route to analyst review before blocking.',
            'Do not click links or download attachments.',
            'Verify sender/domain independently.',
            'Check headers, URL reputation, and business context.',
            'Do not automatically block sender/domain from this single grey-zone result.',
          ],
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

test('grey-zone spam analysis renders review-first policy and handling', async ({ page }) => {
  await mockSpamApis(page);

  await page.goto('/');
  await page.locator('input[type="password"]').fill('admin-password-123');
  await page.getByRole('button', { name: /^Sign in$/i }).click();
  await page.getByRole('button', { name: /Email Security/i }).click();
  await expect(page.getByText('Spam Analyzer')).toBeVisible();

  await page.getByPlaceholder('Paste email or message here...').fill('Please review this password notice.');
  await page.getByRole('button', { name: /Analyze Text/i }).click();

  await expect(page.getByText('Needs Review — Possible Spam/Phishing')).toBeVisible();
  await expect(page.getByText(/Spam\/Phishing Risk:/i)).toBeVisible();
  await expect(page.getByText(/Decision Confidence:/i)).toBeVisible();
  await expect(page.getByText(/AI Reliability:/i)).toBeVisible();
  await expect(page.getByText(/Recommended Handling:/i)).toBeVisible();
  await expect(page.getByText('Route to analyst review before blocking.').first()).toBeVisible();
  await expect(page.getByText(/Do not automatically block sender\/domain/i).first()).toBeVisible();
  await expect(page.getByText(/^Spam detected$/i)).toHaveCount(0);
});

test('gift-card BEC sample renders high-risk fraud category and block-request wording', async ({ page }) => {
  await mockSpamApis(page);

  await page.goto('/');
  await page.locator('input[type="password"]').fill('admin-password-123');
  await page.getByRole('button', { name: /^Sign in$/i }).click();
  await page.getByRole('button', { name: /Email Security/i }).click();
  await expect(page.getByText('Spam Analyzer')).toBeVisible();

  await page.getByPlaceholder('Paste email or message here...').fill(
    'Subject: Quick task before board call\n\nI need you to buy 10 gift cards. Send photos of card numbers and PINs immediately. I am in a meeting and cannot take calls.'
  );
  await page.getByRole('button', { name: /Analyze Text/i }).click();

  await expect(page.getByText('High-Risk BEC / Gift-Card Fraud Detected')).toBeVisible();
  await expect(page.getByText(/Fraud Category:/i)).toBeVisible();
  await expect(page.getByText(/Fraud Category:\s*Gift-card fraud/i)).toBeVisible();
  await expect(page.getByText(/Gift-card purchase request with PIN\/card-number exfiltration/i)).toBeVisible();
  await expect(page.getByText(/Recommended Handling:/i)).toBeVisible();
  await expect(page.locator('p').filter({ hasText: /Recommended Handling:\s*Block Request/i })).toBeVisible();
  await expect(page.getByText(/not confirmed gateway enforcement/i)).toBeVisible();
});

test('courier customs fee phishing renders specific evidence and block-request wording', async ({ page }) => {
  await mockSpamApis(page);

  await page.goto('/');
  await page.locator('input[type="password"]').fill('admin-password-123');
  await page.getByRole('button', { name: /^Sign in$/i }).click();
  await page.getByRole('button', { name: /Email Security/i }).click();
  await expect(page.getByText('Spam Analyzer')).toBeVisible();

  await page.getByPlaceholder('Paste email or message here...').fill(
    'From: Notice Desk <notice@fast-post-tracking.net>\nSubject: DHL parcel hold - Customs\n\nYour package cannot be delivered due to unpaid customs handling fee (AUD $2.80).\nPay now: https://fast-post-tracking.net/customer/pay/37291\nIf unpaid within 12 hours, parcel will be returned to sender.'
  );
  await page.getByRole('button', { name: /Analyze Text/i }).click();

  await expect(page.getByText('High-Risk Courier/Customs Fee Phishing Detected')).toBeVisible();
  await expect(page.getByText('Courier / Delivery Phishing Evidence')).toBeVisible();
  await expect(page.getByText(/Fraud Category:\s*courier_customs_fee_phishing/i)).toBeVisible();
  await expect(page.getByText(/Claimed Brand:\s*DHL/i)).toBeVisible();
  await expect(page.getByText(/Brand Mismatch:\s*yes/i)).toBeVisible();
  await expect(page.getByText(/Claimed DHL identity but link domain is not an official DHL domain/i).first()).toBeVisible();
  await expect(page.locator('p').filter({ hasText: /Recommended Handling:\s*Block Request/i })).toBeVisible();
  await expect(page.getByText(/action-plan recommendations, not confirmed gateway enforcement/i)).toBeVisible();
});

test('official DHL shipping notification does not render courier phishing status', async ({ page }) => {
  await mockSpamApis(page);

  await page.goto('/');
  await page.locator('input[type="password"]').fill('admin-password-123');
  await page.getByRole('button', { name: /^Sign in$/i }).click();
  await page.getByRole('button', { name: /Email Security/i }).click();
  await expect(page.getByText('Spam Analyzer')).toBeVisible();

  await page.getByPlaceholder('Paste email or message here...').fill(
    'From: DHL <tracking@dhl.com>\nSubject: DHL shipment update\n\nYour package is scheduled for delivery tomorrow. Track it at https://www.dhl.com/en/express/tracking.html'
  );
  await page.getByRole('button', { name: /Analyze Text/i }).click();

  await expect(page.locator('p').filter({ hasText: /^Not Spam$/ })).toBeVisible();
  await expect(page.getByText(/High-Risk Courier\/Customs Fee Phishing/i)).toHaveCount(0);
  await expect(page.getByText(/Courier \/ Delivery Phishing Evidence/i)).toHaveCount(0);
});
