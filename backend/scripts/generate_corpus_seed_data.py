from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Dict, List

import pandas as pd


def _backend_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _corpus_root() -> Path:
    return _backend_root() / "data" / "corpus"


def _write_rows(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(path, index=False)


def _sql_seed_rows() -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    benign_enterprise = [
        ("SELECT id, customer_id, total_amount FROM invoices WHERE tenant_id = ? AND status = ?", "postgresql", "sqlalchemy", "billing-api"),
        ("SELECT order_id, sku, quantity FROM order_items WHERE order_id = $1", "postgresql", "django_orm", "order-api"),
        ("SELECT TOP 50 id, event_type FROM audit_logs ORDER BY created_at DESC", "sqlserver", "none", "audit-service"),
        ("SELECT id, display_name FROM users WHERE org_id = @org AND active = 1", "sqlserver", "entity_framework", "identity-service"),
        ("SELECT id, amount FROM payments WHERE created_at >= NOW() - interval '7 days'", "postgresql", "none", "payment-service"),
        ("SELECT region, SUM(amount) FROM revenue GROUP BY region", "mysql", "none", "analytics-service"),
    ]
    for q, d, orm, svc in benign_enterprise:
        rows.append(
            {
                "label": "benign",
                "scenario": "benign_enterprise_query",
                "query": q,
                "dialect": d,
                "orm_name": orm,
                "service_context": svc,
                "notes": "enterprise benign workload",
            }
        )

    orm_generated = [
        ("SELECT \"user\".\"id\", \"user\".\"email\" FROM \"user\" WHERE \"user\".\"id\" = $1", "postgresql", "django_orm", "auth-service"),
        ("SELECT users.id AS users_id, users.email AS users_email FROM users WHERE users.id = %(id_1)s", "mysql", "sqlalchemy", "auth-service"),
        ("SELECT [u].[Id], [u].[Email] FROM [Users] AS [u] WHERE [u].[Id] = @__id_0", "sqlserver", "entity_framework", "identity-service"),
        ("SELECT t0.\"Id\", t0.\"Name\" FROM \"Tenant\" t0 WHERE t0.\"IsActive\" = $1", "postgresql", "sequelize", "tenant-service"),
    ]
    for q, d, orm, svc in orm_generated:
        rows.append(
            {
                "label": "benign",
                "scenario": "orm_generated_query",
                "query": q,
                "dialect": d,
                "orm_name": orm,
                "service_context": svc,
                "notes": "ORM-style baseline",
            }
        )

    cross_dialect = [
        ("SELECT NOW()", "postgresql", "none", "healthcheck-service"),
        ("SELECT GETDATE()", "sqlserver", "none", "healthcheck-service"),
        ("SELECT CURRENT_TIMESTAMP()", "mysql", "none", "healthcheck-service"),
        ("SELECT COALESCE(name, 'unknown') FROM customers", "postgresql", "none", "crm-service"),
        ("SELECT ISNULL(name, 'unknown') FROM customers", "sqlserver", "none", "crm-service"),
        ("SELECT IFNULL(name, 'unknown') FROM customers", "mysql", "none", "crm-service"),
    ]
    for q, d, orm, svc in cross_dialect:
        rows.append(
            {
                "label": "benign",
                "scenario": "cross_dialect_query",
                "query": q,
                "dialect": d,
                "orm_name": orm,
                "service_context": svc,
                "notes": "cross dialect benign query",
            }
        )

    obfuscated_sqli = [
        ("SeLeCt * FrOm users WhErE id=1/**/OR/**/1=1--", "mysql"),
        ("SELECT/*foo*/name FROM admin WHERE user='a' OR '1'='1' --", "postgresql"),
        ("SELECT id FROM users WHERE id=1 /*!50000OR*/ 1=1", "mysql"),
        ("SELECT * FROM products WHERE id='1' OR/**/sleep(5)#", "mysql"),
        ("SELECT * FROM members WHERE username='x' OR 1=1;--", "sqlserver"),
        ("SELECT id FROM t WHERE id=1 OR 1=1/*injected*/", "postgresql"),
    ]
    for q, d in obfuscated_sqli:
        rows.append(
            {
                "label": "malicious",
                "scenario": "obfuscated_sqli",
                "query": q,
                "dialect": d,
                "orm_name": "none",
                "service_context": "public-api",
                "notes": "obfuscated injection payload",
            }
        )

    stored_proc_abuse = [
        ("EXEC xp_cmdshell 'whoami'", "sqlserver"),
        ("EXEC master..xp_dirtree 'C:\\\\'", "sqlserver"),
        ("EXEC sp_OACreate 'WScript.Shell'", "sqlserver"),
        ("CALL sys_eval('id')", "mysql"),
        ("SELECT pg_sleep(10)", "postgresql"),
    ]
    for q, d in stored_proc_abuse:
        rows.append(
            {
                "label": "malicious",
                "scenario": "stored_procedure_abuse",
                "query": q,
                "dialect": d,
                "orm_name": "none",
                "service_context": "legacy-admin-console",
                "notes": "stored procedure abuse sample",
            }
        )

    service_context_trace = [
        ("SELECT * FROM orders WHERE id = 42; DROP TABLE orders; --", "postgresql", "order-api"),
        ("UPDATE users SET is_admin = 1 WHERE id = 4 OR 1=1", "mysql", "identity-service"),
        ("SELECT card_no FROM cards WHERE user_id = 7 UNION SELECT password FROM users", "postgresql", "payment-service"),
        ("DELETE FROM logs WHERE tenant_id = 5 OR 1=1", "sqlserver", "audit-service"),
        ("SELECT * FROM invoices WHERE id = @id; WAITFOR DELAY '00:00:05'--", "sqlserver", "billing-api"),
        ("SELECT * FROM accounts WHERE email = '' OR pg_sleep(5)--", "postgresql", "auth-service"),
    ]
    for q, d, svc in service_context_trace:
        rows.append(
            {
                "label": "malicious",
                "scenario": "service_context_trace",
                "query": q,
                "dialect": d,
                "orm_name": "none",
                "service_context": svc,
                "notes": "context-labeled malicious trace",
            }
        )
    return rows


def _file_seed_rows() -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []

    def add_row(
        *,
        label: str,
        scenario: str,
        filename: str,
        file_type: str,
        mime_type: str,
        extension: str,
        macro_enabled: bool,
        nested_archive: bool,
        content_excerpt: str,
        notes: str,
    ) -> None:
        rows.append(
            {
                "label": label,
                "scenario": scenario,
                "filename": filename,
                "file_type": file_type,
                "mime_type": mime_type,
                "extension": extension,
                "macro_enabled": str(bool(macro_enabled)).lower(),
                "nested_archive": str(bool(nested_archive)).lower(),
                "content_excerpt": content_excerpt,
                "notes": notes,
            }
        )

    # Safe: benign-but-complex PDF/OOXML (20)
    benign_complex_entries = [
        ("annual_report", "pdf", "application/pdf", "pdf", "Board report with charts, forms, signatures, and references."),
        ("product_manual", "pdf", "application/pdf", "pdf", "Large manual with embedded images, index, and bookmarks."),
        ("quarterly_summary", "ooxml", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "docx", "Complex OOXML document with tracked changes and comments."),
        ("financial_pack", "ooxml", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "xlsx", "Workbook with pivot tables, formulas, and internal links."),
        ("project_spec", "ooxml", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "docx", "Architecture specification with figures and appendices."),
        ("compliance_appendix", "pdf", "application/pdf", "pdf", "Compliance appendix with TOC and legal references."),
        ("operations_handbook", "pdf", "application/pdf", "pdf", "Operations handbook with large embedded diagrams."),
        ("risk_register", "ooxml", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "xlsx", "Risk register sheet with lookups and protected ranges."),
        ("site_survey", "pdf", "application/pdf", "pdf", "Survey PDF with layered vector graphics and forms."),
        ("engineering_notes", "ooxml", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "docx", "Engineering notes document with equations and citations."),
    ]
    for i, (stem, ft, mime, ext, excerpt) in enumerate(benign_complex_entries, start=1):
        add_row(
            label="safe",
            scenario="benign_complex_pdf_ooxml",
            filename=f"{stem}_{i:02d}.{ext}",
            file_type=ft,
            mime_type=mime,
            extension=ext,
            macro_enabled=False,
            nested_archive=False,
            content_excerpt=excerpt,
            notes="benign complex document",
        )
        add_row(
            label="safe",
            scenario="benign_complex_pdf_ooxml",
            filename=f"{stem}_{i:02d}_rev2.{ext}",
            file_type=ft,
            mime_type=mime,
            extension=ext,
            macro_enabled=False,
            nested_archive=False,
            content_excerpt=f"{excerpt} Versioned update with additional tables.",
            notes="benign complex document variant",
        )

    # Safe: macro-enabled but benign (16)
    benign_macro_entries = [
        ("finance_template", "xlsm", "application/vnd.ms-excel.sheet.macroEnabled.12", "Signed macro for monthly report generation."),
        ("inventory_tool", "xlsm", "application/vnd.ms-excel.sheet.macroEnabled.12", "Macro recalculates pivots and formatting only."),
        ("budget_planner", "docm", "application/vnd.ms-word.document.macroEnabled.12", "Trusted macro inserts approved watermark and footer."),
        ("timesheet_pack", "xlsm", "application/vnd.ms-excel.sheet.macroEnabled.12", "Macro validates date cells and style consistency."),
        ("procurement_form", "docm", "application/vnd.ms-word.document.macroEnabled.12", "Macro expands controlled template sections."),
        ("ops_tracker", "xlsm", "application/vnd.ms-excel.sheet.macroEnabled.12", "Macro refreshes data connections to internal source."),
        ("forecast_model", "xlsm", "application/vnd.ms-excel.sheet.macroEnabled.12", "Macro computes forecast assumptions and summaries."),
        ("hr_letter_template", "docm", "application/vnd.ms-word.document.macroEnabled.12", "Macro applies corporate branding fields."),
    ]
    for i, (stem, ext, mime, excerpt) in enumerate(benign_macro_entries, start=1):
        add_row(
            label="safe",
            scenario="benign_macro_enabled_office",
            filename=f"{stem}_{i:02d}.{ext}",
            file_type="ooxml",
            mime_type=mime,
            extension=ext,
            macro_enabled=True,
            nested_archive=False,
            content_excerpt=excerpt,
            notes="macro enabled but benign",
        )
        add_row(
            label="safe",
            scenario="benign_macro_enabled_office",
            filename=f"{stem}_{i:02d}_signed.{ext}",
            file_type="ooxml",
            mime_type=mime,
            extension=ext,
            macro_enabled=True,
            nested_archive=False,
            content_excerpt=f"{excerpt} Signed by internal certificate chain.",
            notes="macro enabled but benign signed variant",
        )

    # Malicious: PDF/OOXML weaponization (14)
    malicious_doc_entries = [
        ("invoice_payload", "pdf", "application/pdf", "pdf", False, "Embedded JavaScript launch action with encoded shellcode."),
        ("proposal_dropper", "docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "docx", False, "External template injection and suspicious relationship paths."),
        ("loader", "xlsm", "application/vnd.ms-excel.sheet.macroEnabled.12", "xlsm", True, "Macro spawns powershell download cradle."),
        ("bank_notice", "pdf", "application/pdf", "pdf", False, "OpenAction with URI to dynamic exploit page."),
        ("resume_weaponized", "docm", "application/vnd.ms-word.document.macroEnabled.12", "docm", True, "AutoOpen VBA with obfuscated command execution."),
        ("shipping_advice", "pdf", "application/pdf", "pdf", False, "Suspicious URI action and embedded encoded stream."),
        ("policy_update", "docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "docx", False, "Remote OLE object and hidden template callback."),
    ]
    for i, (stem, ext, mime, ext2, macro, excerpt) in enumerate(malicious_doc_entries, start=1):
        add_row(
            label="malicious",
            scenario="malicious_pdf_ooxml",
            filename=f"{stem}_{i:02d}.{ext}",
            file_type="pdf" if ext == "pdf" else "ooxml",
            mime_type=mime,
            extension=ext2,
            macro_enabled=macro,
            nested_archive=False,
            content_excerpt=excerpt,
            notes="known malicious document traits",
        )
        add_row(
            label="malicious",
            scenario="malicious_pdf_ooxml",
            filename=f"{stem}_{i:02d}_variant.{ext}",
            file_type="pdf" if ext == "pdf" else "ooxml",
            mime_type=mime,
            extension=ext2,
            macro_enabled=macro,
            nested_archive=False,
            content_excerpt=f"{excerpt} Includes obfuscated command and network callback.",
            notes="known malicious document traits variant",
        )

    # Malicious: nested archive abuse (12)
    nested_entries = [
        ("records_bundle", "zip", "application/zip", "zip->zip->rar nesting with executable bait"),
        ("claims_archive", "7z", "application/x-7z-compressed", "deep nested archive with script payload"),
        ("media_pack", "zip", "application/zip", "nested archive with large expansion ratio"),
        ("invoice_batch", "zip", "application/zip", "multiple nested levels with disguised .scr payload"),
        ("design_assets", "7z", "application/x-7z-compressed", "nested archive containing malicious lnk and ps1"),
        ("customer_docs", "zip", "application/zip", "archive bomb style high compression abuse"),
    ]
    for i, (stem, ext, mime, excerpt) in enumerate(nested_entries, start=1):
        add_row(
            label="malicious",
            scenario="nested_archive_abuse",
            filename=f"{stem}_{i:02d}.{ext}",
            file_type="archive",
            mime_type=mime,
            extension=ext,
            macro_enabled=False,
            nested_archive=True,
            content_excerpt=excerpt,
            notes="archive abuse sample",
        )
        add_row(
            label="malicious",
            scenario="nested_archive_abuse",
            filename=f"{stem}_{i:02d}_deep.{ext}",
            file_type="archive",
            mime_type=mime,
            extension=ext,
            macro_enabled=False,
            nested_archive=True,
            content_excerpt=f"{excerpt}; password-protected inner archives.",
            notes="archive abuse sample deep variant",
        )

    # Malicious: MIME/extension mismatch (10)
    mismatch_entries = [
        ("statement", "pdf", "text/html", "HTML script content presented as PDF"),
        ("report", "docx", "application/x-msdownload", "PE header content with office extension"),
        ("invoice", "xlsx", "application/javascript", "JavaScript content mismatched as spreadsheet"),
        ("meeting_notes", "txt", "application/pdf", "PDF binary content with plain text extension"),
        ("quotation", "pdf", "application/octet-stream", "Executable payload disguised as document"),
    ]
    for i, (stem, ext, mime, excerpt) in enumerate(mismatch_entries, start=1):
        add_row(
            label="malicious",
            scenario="mime_extension_mismatch",
            filename=f"{stem}_{i:02d}.{ext}",
            file_type="unknown",
            mime_type=mime,
            extension=ext,
            macro_enabled=False,
            nested_archive=False,
            content_excerpt=excerpt,
            notes="mismatched mime and extension",
        )
        add_row(
            label="malicious",
            scenario="mime_extension_mismatch",
            filename=f"{stem}_{i:02d}_alt.{ext}",
            file_type="unknown",
            mime_type=mime,
            extension=ext,
            macro_enabled=False,
            nested_archive=False,
            content_excerpt=f"{excerpt}; embedded script tags and downloader markers.",
            notes="mismatched mime and extension variant",
        )
    return rows


def _phishing_seed_rows() -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    modern = [
        ("Action Required: Password Expiring", "Your mailbox quota exceeded. Verify now.", "support@secure-it-helpdesk.com", "secure-it-helpdesk.com", "http://198.51.100.22/login", "ip_url;urgent_cta", "none", "en", "urgent_imperative", "phishing"),
        ("Invoice Past Due", "Open secure portal to avoid service interruption.", "billing@vendor-secure-pay.com", "vendor-secure-pay.com", "http://bit.ly/invoice-now", "shortener;cta", "none", "en", "urgent_imperative", "phishing"),
        ("Unusual Sign-In Attempt", "Confirm sign-in from unknown location.", "alerts@microsoft-security-verify.com", "microsoft-security-verify.com", "https://login-micr0soft.com/verify", "lookalike_domain", "none", "en", "brand_impersonation", "phishing"),
    ]
    for subject, body, sender, sdom, urls, urlf, attach, lang, style, label in modern:
        rows.append(
            {
                "label": label,
                "scenario": "modern_phishing",
                "subject": subject,
                "body_text": body,
                "sender_email": sender,
                "sender_domain": sdom,
                "urls": urls,
                "url_features": urlf,
                "attachment_features": attach,
                "language": lang,
                "style_shift": style,
                "notes": "modern phishing lure",
            }
        )

    legitimate = [
        ("Your Order Receipt #10451", "Thank you for your purchase. Track order in account.", "no-reply@trustedshop.com", "trustedshop.com", "https://trustedshop.com/orders/10451", "known_good_domain", "receipt.pdf", "en", "neutral_transactional", "ham"),
        ("Monthly Statement Available", "Statement ready in your secure portal.", "alerts@bankexample.com", "bankexample.com", "https://bankexample.com/login", "known_good_domain", "none", "en", "formal_transactional", "ham"),
        ("Shipping Update", "Carrier marked shipment in transit.", "notify@parcelco.com", "parcelco.com", "https://parcelco.com/track/A123", "known_good_domain", "none", "en", "neutral_transactional", "ham"),
    ]
    for subject, body, sender, sdom, urls, urlf, attach, lang, style, label in legitimate:
        rows.append(
            {
                "label": label,
                "scenario": "legitimate_transactional",
                "subject": subject,
                "body_text": body,
                "sender_email": sender,
                "sender_domain": sdom,
                "urls": urls,
                "url_features": urlf,
                "attachment_features": attach,
                "language": lang,
                "style_shift": style,
                "notes": "legitimate transactional email",
            }
        )

    sender_metadata = [
        ("Security Notice", "Confirm account details immediately.", "alerts@paypa1-security.com", "paypa1-security.com", "https://paypa1-security.com/confirm", "lookalike_domain", "none", "en", "brand_impersonation", "phishing"),
        ("Account Activity", "We detected unusual activity.", "service@arnazon-billing.com", "arnazon-billing.com", "https://arnazon-billing.com/review", "lookalike_domain", "none", "en", "brand_impersonation", "phishing"),
        ("Billing Statement Ready", "Review monthly statement in portal.", "billing@telecom.example.com", "telecom.example.com", "https://telecom.example.com/billing", "known_good_domain", "statement.pdf", "en", "formal_transactional", "ham"),
    ]
    for subject, body, sender, sdom, urls, urlf, attach, lang, style, label in sender_metadata:
        rows.append(
            {
                "label": label,
                "scenario": "sender_domain_metadata",
                "subject": subject,
                "body_text": body,
                "sender_email": sender,
                "sender_domain": sdom,
                "urls": urls,
                "url_features": urlf,
                "attachment_features": attach,
                "language": lang,
                "style_shift": style,
                "notes": "sender and domain metadata sample",
            }
        )

    url_feature_rich = [
        ("Payroll Action Needed", "Open payroll statement now.", "hr@corp-payroll-alerts.com", "corp-payroll-alerts.com", "http://bit.ly/payroll-open", "shortener;redirect_chain;suspicious_tld", "none", "en", "urgent_imperative", "phishing"),
        ("Document Shared With You", "Preview shared document.", "docs@share-files-team.top", "share-files-team.top", "http://share-files-team.top/doc?id=991", "suspicious_tld;tracking_query", "none", "en", "generic_prompt", "phishing"),
        ("Policy Update", "Read updated policy document.", "policy@corp.example.com", "corp.example.com", "https://corp.example.com/policy", "known_good_domain", "none", "en", "formal_transactional", "ham"),
    ]
    for subject, body, sender, sdom, urls, urlf, attach, lang, style, label in url_feature_rich:
        rows.append(
            {
                "label": label,
                "scenario": "url_feature_rich",
                "subject": subject,
                "body_text": body,
                "sender_email": sender,
                "sender_domain": sdom,
                "urls": urls,
                "url_features": urlf,
                "attachment_features": attach,
                "language": lang,
                "style_shift": style,
                "notes": "url-focused signal sample",
            }
        )

    attachment_rich = [
        ("Invoice Attached", "Enable content to view invoice.", "billing@vendor-mail.com", "vendor-mail.com", "none", "none", "invoice.xlsm;password_zip", "en", "attachment_lure", "phishing"),
        ("Payment Advice", "Review attached remittance.", "finance@payments-help.net", "payments-help.net", "none", "none", "remittance.docm", "en", "attachment_lure", "phishing"),
        ("Meeting Minutes", "Please find attached approved minutes.", "pm@corp.example.com", "corp.example.com", "none", "none", "minutes.pdf", "en", "neutral_transactional", "ham"),
    ]
    for subject, body, sender, sdom, urls, urlf, attach, lang, style, label in attachment_rich:
        rows.append(
            {
                "label": label,
                "scenario": "attachment_feature_rich",
                "subject": subject,
                "body_text": body,
                "sender_email": sender,
                "sender_domain": sdom,
                "urls": urls,
                "url_features": urlf,
                "attachment_features": attach,
                "language": lang,
                "style_shift": style,
                "notes": "attachment-focused sample",
            }
        )

    multilingual = [
        ("Votre livraison est confirmee", "Merci pour votre commande. Suivi dans votre compte.", "service@trustedshop.com", "trustedshop.com", "https://trustedshop.com/tracking/ABCD", "known_good_domain", "none", "fr", "formal_transactional", "ham"),
        ("Actualizacion de seguridad requerida", "Confirme su cuenta para evitar bloqueo.", "alertas@seguridad-banco.com", "seguridad-banco.com", "https://seguridad-banco.com/confirmar", "lookalike_domain", "none", "es", "urgent_imperative", "phishing"),
        ("Benutzerkonto bestaetigen", "Bitte melden Sie sich sofort an.", "support@konto-sicherheit.net", "konto-sicherheit.net", "http://konto-sicherheit.net/login", "suspicious_tld;urgent_cta", "none", "de", "urgent_imperative", "phishing"),
        ("Aggiornamento ordine", "Il tuo ordine e stato spedito.", "notify@shop.example.com", "shop.example.com", "https://shop.example.com/order/77", "known_good_domain", "none", "it", "neutral_transactional", "ham"),
    ]
    for subject, body, sender, sdom, urls, urlf, attach, lang, style, label in multilingual:
        rows.append(
            {
                "label": label,
                "scenario": "multilingual_style_shift",
                "subject": subject,
                "body_text": body,
                "sender_email": sender,
                "sender_domain": sdom,
                "urls": urls,
                "url_features": urlf,
                "attachment_features": attach,
                "language": lang,
                "style_shift": style,
                "notes": "multilingual and style-shift sample",
            }
        )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate richer seed datasets for SQL, file, and phishing evaluation corpus.")
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing seed CSV files.")
    args = parser.parse_args()

    root = _corpus_root()
    outputs = [
        (root / "sql" / "raw" / "sql_corpus_seed.csv", _sql_seed_rows()),
        (root / "file" / "raw" / "file_corpus_seed.csv", _file_seed_rows()),
        (root / "phishing" / "raw" / "phishing_corpus_seed.csv", _phishing_seed_rows()),
    ]
    for path, rows in outputs:
        if path.exists() and not args.overwrite:
            print(f"skip:{path}")
            continue
        _write_rows(path, rows)
        print(f"wrote:{path} rows={len(rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
