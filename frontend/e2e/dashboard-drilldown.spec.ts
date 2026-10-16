import { expect, test, type Locator, type Page } from '@playwright/test';

const authUser = { id: 'u-admin', email: 'admin@example.com', role: 'admin' };

async function mockDashboardApis(page: Page): Promise<void> {
  await page.route('**/api/v1/**', async (route) => {
    const reqUrl = new URL(route.request().url());
    const path = reqUrl.pathname;
    const q = reqUrl.searchParams;

    const json = (payload: unknown) =>
      route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(payload),
      });

    if (path.endsWith('/auth/me')) {
      return json(authUser);
    }
    if (path.endsWith('/dashboard/stats')) {
      return json({
        total_queries: 8,
        malicious_queries: 2,
        files_scanned: 6,
        spam_detected: 3,
      });
    }
    if (path.endsWith('/dashboard/stats-history')) {
      return json({
        time_period: 'last_14_days',
        data: [
          { date: '2026-03-24', total_queries: 5, malicious_queries: 1, files_scanned: 3, spam_detected: 1 },
          { date: '2026-03-25', total_queries: 8, malicious_queries: 2, files_scanned: 6, spam_detected: 3 },
        ],
      });
    }
    if (path.endsWith('/dashboard/threat-trends')) {
      return json({
        time_period: 'last_7_days',
        trend_data: [
          { name: '2026-03-19', SQL_Injection: 1, Files: 1, Spam: 1, Other: 0 },
          { name: '2026-03-20', SQL_Injection: 2, Files: 0, Spam: 1, Other: 0 },
          { name: '2026-03-21', SQL_Injection: 1, Files: 1, Spam: 0, Other: 0 },
          { name: '2026-03-22', SQL_Injection: 0, Files: 1, Spam: 1, Other: 0 },
          { name: '2026-03-23', SQL_Injection: 1, Files: 1, Spam: 0, Other: 0 },
          { name: '2026-03-24', SQL_Injection: 2, Files: 1, Spam: 1, Other: 0 },
          { name: '2026-03-25', SQL_Injection: 1, Files: 1, Spam: 2, Other: 0 },
        ],
      });
    }
    if (path.endsWith('/dashboard/live-events')) {
      return json({
        events: [
          { id: 'sql-1', type: 'query', message: 'SQL query analyzed', timestamp: '2026-03-25T09:00:00Z', isMalicious: false },
        ],
      });
    }
    if (path.endsWith('/dashboard/files-scanned')) {
      return json({
        day: '2026-03-25',
        count: 3,
        files: [
          {
            analysis_id: 'file-blocked-1',
            timestamp: '2026-03-25T10:00:00Z',
            filename: 'blocked-report.pdf',
            overall_status: 'Malicious',
            risk_score: 0.95,
            recommended_action: 'BLOCK_UPLOAD_QUARANTINE',
            reasoning: ['YARA signature matched'],
            detected_mime_type: 'application/pdf',
            yara_malicious: true,
            ml_suspicious: true,
            category: 'blocked',
          },
          {
            analysis_id: 'file-suspicious-1',
            timestamp: '2026-03-25T10:05:00Z',
            filename: 'suspicious-note.html',
            overall_status: 'Suspicious',
            risk_score: 0.66,
            recommended_action: 'FLAG_REVIEW',
            reasoning: ['Script indicators found'],
            detected_mime_type: 'text/html',
            ml_suspicious: true,
            category: 'suspicious',
          },
          {
            analysis_id: 'file-safe-1',
            timestamp: '2026-03-25T10:08:00Z',
            filename: 'safe.txt',
            overall_status: 'Safe',
            risk_score: 0.12,
            recommended_action: 'ALLOW_UPLOAD',
            reasoning: ['No malicious indicators'],
            detected_mime_type: 'text/plain',
            category: 'safe',
          },
        ],
      });
    }
    if (path.endsWith('/dashboard/sql-queries')) {
      const maliciousOnly = q.get('malicious_only') === 'true';
      const allRows = [
        {
          analysis_id: 'sql-blocked-1',
          timestamp: '2026-03-25T11:00:00Z',
          query_received: 'SELECT * FROM users; DROP TABLE users; --',
          risk_level: 'High',
          suggested_action: 'BLOCK_IMMEDIATE',
          is_anomalous: true,
          classification_label: 'Malicious',
          classification_score: 0.99,
          category: 'blocked',
        },
        {
          analysis_id: 'sql-suspicious-1',
          timestamp: '2026-03-25T11:05:00Z',
          query_received: 'SELECT * FROM products WHERE id=1 OR 1=1',
          risk_level: 'Medium',
          suggested_action: 'FLAG_REVIEW',
          is_anomalous: true,
          classification_label: 'Suspicious',
          classification_score: 0.72,
          category: 'suspicious',
        },
        {
          analysis_id: 'sql-safe-1',
          timestamp: '2026-03-25T11:09:00Z',
          query_received: 'SELECT 1',
          risk_level: 'Low',
          suggested_action: 'ALLOW',
          is_anomalous: false,
          classification_label: 'Benign',
          classification_score: 0.11,
          category: 'safe',
        },
      ];
      const rows = maliciousOnly ? [allRows[0]] : allRows;
      return json({
        day: '2026-03-25',
        count: rows.length,
        malicious_only: maliciousOnly,
        queries: rows,
      });
    }
    if (path.endsWith('/dashboard/spam-detections')) {
      return json({
        day: '2026-03-25',
        count: 3,
        detected_only: false,
        detections: [
          {
            analysis_id: 'spam-blocked-1',
            timestamp: '2026-03-25T12:00:00Z',
            received_subject: 'Urgent account verification',
            is_spam: true,
            spam_score: 0.96,
            classification_label: 'Phishing',
            category: 'blocked',
          },
          {
            analysis_id: 'spam-suspicious-1',
            timestamp: '2026-03-25T12:03:00Z',
            received_subject: 'Invoice pending',
            is_spam: true,
            spam_score: 0.72,
            classification_label: 'Spam',
            category: 'suspicious',
          },
          {
            analysis_id: 'spam-safe-1',
            timestamp: '2026-03-25T12:07:00Z',
            received_subject: 'Weekly sync notes',
            is_spam: false,
            spam_score: 0.12,
            classification_label: 'Ham',
            category: 'safe',
          },
        ],
      });
    }
    if (path.endsWith('/alerts')) {
      return json({ alerts: [], total_alerts: 0, page: 1, page_size: 10, total_pages: 1 });
    }
    return json({});
  });
}

test.beforeEach(async ({ page }) => {
  await mockDashboardApis(page);
  await page.addInitScript((user) => {
    localStorage.setItem('auth_access_token', 'test-token');
    localStorage.setItem('auth_user', JSON.stringify(user));
  }, authUser);
  await page.goto('/');
  await expect(page.getByText('Admin Security Dashboard')).toBeVisible();
});

async function expectCategoryHeaders(drawer: Locator): Promise<void> {
  await expect(drawer.locator('span').filter({ hasText: /^Blocked$/ }).first()).toBeVisible();
  await expect(drawer.locator('span').filter({ hasText: /^Suspicious$/ }).first()).toBeVisible();
  await expect(drawer.locator('span').filter({ hasText: /^Safe$/ }).first()).toBeVisible();
}

test('file drill-down: card click -> grouped list -> item detail', async ({ page }) => {
  await page.getByRole('button', { name: /^Files Scanned \(Today\)/i }).click();
  const drawer = page.locator('div.fixed.inset-0.z-50').last();
  await expect(drawer.getByRole('heading', { name: 'Files Scanned Today' })).toBeVisible();
  await expectCategoryHeaders(drawer);

  await drawer.getByRole('button', { name: /blocked-report\.pdf/i }).click();
  await expect(drawer.getByText('BLOCK_UPLOAD_QUARANTINE')).toBeVisible();
  await expect(drawer.getByText('YARA signature matched')).toBeVisible();
});

test('sql drill-down: card click -> grouped list -> item detail', async ({ page }) => {
  await page.getByRole('button', { name: /^Queries \(Today\)/i }).click();
  const drawer = page.locator('div.fixed.inset-0.z-50').last();
  await expect(drawer.getByRole('heading', { name: 'SQL Queries Today' })).toBeVisible();
  await expectCategoryHeaders(drawer);

  await drawer.getByRole('button', { name: /DROP TABLE users/i }).click();
  await expect(drawer.getByText('BLOCK_IMMEDIATE')).toBeVisible();
  await expect(drawer.getByText(/Malicious \(/)).toBeVisible();
});

test('spam drill-down: card click -> grouped list -> item detail', async ({ page }) => {
  await page.getByRole('button', { name: /^Spam Detected \(Today\)/i }).click();
  const drawer = page.locator('div.fixed.inset-0.z-50').last();
  await expect(drawer.getByRole('heading', { name: 'Spam Checks Today' })).toBeVisible();
  await expectCategoryHeaders(drawer);

  await drawer.getByRole('button', { name: /Urgent account verification/i }).click();
  await expect(drawer.getByText('Phishing')).toBeVisible();
  await expect(drawer.getByText('0.960')).toBeVisible();
});
