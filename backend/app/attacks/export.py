"""Export Service for ApexShield Attack Lab.

Generates RFC-4180 CSV exports and professional executive PDF reports
for AttackRun batch execution assessments using ReportLab.
"""

import csv
from datetime import datetime, timezone
import html
import io
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.attacks.scenarios import RISK_CATEGORIES, get_scenario_by_id
from app.database.models import AttackResult, AttackRun


class AttackRunReportCanvas(canvas.Canvas):
    """Two-pass canvas for ReportLab to compute total page count ('Page X of Y')
    and draw consistent running headers and footers."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, total_pages: int):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))

        # Running header (pages 2 and later)
        if self._pageNumber > 1:
            self.drawString(40, letter[1] - 32, "APEXSHIELD AI SECURITY ASSESSMENT — BATCH EXECUTION REPORT")
            self.setStrokeColor(colors.HexColor("#CBD5E1"))
            self.setLineWidth(0.5)
            self.line(40, letter[1] - 36, letter[0] - 40, letter[1] - 36)

        # Running footer (all pages)
        footer_text = f"Page {self._pageNumber} of {total_pages}"
        self.drawRightString(letter[0] - 40, 26, footer_text)
        self.drawString(40, 26, "ApexShield AI Security Testing Framework • Confidential")
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)
        self.line(40, 34, letter[0] - 40, 34)
        self.restoreState()


def resolve_risk_info(results: List[AttackResult]) -> Tuple[str, str]:
    """Resolves OWASP Risk ID and Risk Name from attack results."""
    if not results:
        return "UNKNOWN", "Unknown Assessment"
    risk_ids = sorted(list({r.risk_id.upper() for r in results if r.risk_id}))
    if len(risk_ids) == 1:
        risk_id = risk_ids[0]
        match = next((r for r in RISK_CATEGORIES if r.risk_id.upper() == risk_id), None)
        risk_name = match.risk_name if match else risk_id
        return risk_id, risk_name
    elif len(risk_ids) > 1:
        return "ALL", f"All 10 OWASP Top 10 Risks ({len(results)} Scenarios)"
    return "UNKNOWN", "Unknown Assessment"


def compute_run_verdict(run: AttackRun) -> Tuple[str, str, str]:
    """Computes consolidated security verdict, badge color hex, and explanatory description."""
    executed = len(run.results)
    if run.succeeded_count > 0:
        text = f"VULNERABLE ({run.succeeded_count} ATTACK{'S' if run.succeeded_count > 1 else ''} SUCCEEDED)"
        color = "#DC2626"
        desc = f"{run.succeeded_count} of {executed} attacks bypassed active guardrails, exposing vulnerabilities."
    elif run.partial_count > 0:
        text = f"PARTIAL EXPOSURE ({run.partial_count} WARNING{'S' if run.partial_count > 1 else ''})"
        color = "#D97706"
        desc = f"{run.partial_count} attacks resulted in partial security exposure or warning conditions."
    elif run.blocked_count == executed and executed > 0:
        text = "SECURED (ALL ATTACKS BLOCKED)"
        color = "#16A34A"
        desc = f"All {run.blocked_count} attack scenarios were successfully intercepted by active guardrails."
    else:
        text = "EVALUATED"
        color = "#2563EB"
        desc = f"Batch evaluation finished with {executed} executed scenarios."
    return text, color, desc


def generate_batch_csv(run: AttackRun) -> str:
    """Exports only the scenarios belonging to the selected AttackRun in RFC-4180 CSV format."""
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerow([
        "Run ID",
        "Scenario ID",
        "Scenario Name",
        "OWASP Risk",
        "Provider",
        "Model",
        "Stage",
        "Execution Mode",
        "Outcome",
        "Latency (ms)",
        "Evaluation Reason",
        "Execution Timestamp",
    ])

    for r in run.results:
        sc = get_scenario_by_id(r.scenario_id)
        sc_name = sc.scenario_name if sc else r.scenario_id
        writer.writerow([
            r.run_id,
            r.scenario_id,
            sc_name,
            r.risk_id,
            r.provider,
            r.model,
            r.stage,
            r.execution_mode.upper(),
            r.result_classification,
            f"{r.latency_ms:.2f}" if r.latency_ms is not None else "0.00",
            r.evaluation_reason or "",
            r.created_at.isoformat() if r.created_at else "",
        ])

    return output.getvalue()


def generate_batch_pdf(run: AttackRun) -> bytes:
    """Renders a high-fidelity, professional executive PDF security assessment report."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=40,
        rightMargin=40,
        topMargin=46,
        bottomMargin=46,
    )

    styles = getSampleStyleSheet()

    # Typography hierarchy
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=20,
        leading=24,
        textColor=colors.HexColor("#0F172A"),
        fontName="Helvetica-Bold",
        alignment=0,
    )
    subtitle_style = ParagraphStyle(
        "ReportSubtitle",
        parent=styles["Normal"],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#475569"),
        fontName="Helvetica",
    )
    section_heading = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#1E293B"),
        fontName="Helvetica-Bold",
        spaceBefore=14,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "ReportBody",
        parent=styles["Normal"],
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155"),
        fontName="Helvetica",
    )
    code_style = ParagraphStyle(
        "ReportCode",
        parent=styles["Normal"],
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#0F172A"),
        fontName="Courier",
    )
    table_cell = ParagraphStyle(
        "ReportTableCell",
        parent=styles["Normal"],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#1E293B"),
        fontName="Helvetica",
    )
    table_head = ParagraphStyle(
        "ReportTableHead",
        parent=styles["Normal"],
        fontSize=8,
        leading=11,
        textColor=colors.white,
        fontName="Helvetica-Bold",
    )

    story = []

    # 1. Header & Title Block
    story.append(Paragraph("APEXSHIELD SECURITY ASSESSMENT REPORT", title_style))
    story.append(Spacer(1, 3))
    story.append(Paragraph(
        "<b>Attack Lab Consolidated Batch Evaluation & Guardrail Verification Analysis</b>",
        subtitle_style,
    ))
    story.append(Spacer(1, 8))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#4F46E5"), spaceAfter=10))

    # 2. Mock Mode Disclaimer Box (Mandatory when execution_mode is mock)
    is_mock = run.execution_mode.lower() == "mock"
    if is_mock:
        disclaimer_p = Paragraph(
            "<b>NOTICE — SYNTHETIC MOCK EXECUTION:</b> "
            "These results were generated using synthetic mock-provider responses and do not represent validation against a live AI model. "
            "Configure <code>AI_PROVIDER_MODE=live</code> with verified API credentials to execute live model evaluations.",
            ParagraphStyle(
                "MockAlert",
                parent=styles["Normal"],
                fontSize=8.5,
                leading=12,
                textColor=colors.HexColor("#581C87"),
                fontName="Helvetica",
            ),
        )
        alert_table = Table([[disclaimer_p]], colWidths=[532])
        alert_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FAF5FF")),
            ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#C084FC")),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ]))
        story.append(alert_table)
        story.append(Spacer(1, 10))

    # 3. Assessment Scope & Execution Parameters
    risk_code, risk_title = resolve_risk_info(run.results)
    exec_time_str = run.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if run.created_at else "N/A"

    meta_data = [
        [
            Paragraph("<b>Assessment / Run ID</b>", table_cell),
            Paragraph(f"<code>{html.escape(run.id)}</code>", code_style),
            Paragraph("<b>Execution Mode</b>", table_cell),
            Paragraph(
                f"<font color='{'#16A34A' if not is_mock else '#7C3AED'}'><b>{'LIVE API' if not is_mock else 'MOCK (SYNTHETIC)'}</b></font>",
                table_cell,
            ),
        ],
        [
            Paragraph("<b>Target OWASP Risk</b>", table_cell),
            Paragraph(f"<b>{html.escape(risk_code)}</b> — {html.escape(risk_title)}", table_cell),
            Paragraph("<b>Evaluation Stage</b>", table_cell),
            Paragraph(f"<b>{html.escape(run.stage)}</b>", table_cell),
        ],
        [
            Paragraph("<b>AI Provider / Target</b>", table_cell),
            Paragraph(f"<b>{html.escape(run.provider.upper())}</b> ({html.escape(run.model)})", table_cell),
            Paragraph("<b>Timestamp (UTC)</b>", table_cell),
            Paragraph(exec_time_str, table_cell),
        ],
    ]

    meta_table = Table(meta_data, colWidths=[120, 180, 100, 132])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#E2E8F0")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 12))

    # 4. Consolidated Verdict & Scorecard Banner
    verdict_text, verdict_hex, verdict_desc = compute_run_verdict(run)
    total_executed = len(run.results)
    block_rate = (run.blocked_count / total_executed * 100) if total_executed > 0 else 0.0
    total_duration_ms = round(sum((r.latency_ms or 0.0) for r in run.results), 2)

    verdict_p = Paragraph(
        f"<font size='13' color='white'><b>CONSOLIDATED VERDICT: {html.escape(verdict_text)}</b></font><br/>"
        f"<font size='8.5' color='white'>{html.escape(verdict_desc)}</font>",
        ParagraphStyle("VerdictBanner", parent=styles["Normal"], leading=16, alignment=1),
    )
    verdict_box = Table([[verdict_p]], colWidths=[532])
    verdict_box.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(verdict_hex)),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor(verdict_hex)),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
    ]))
    story.append(verdict_box)
    story.append(Spacer(1, 8))

    # Metrics Scorecard Grid
    scorecard_data = [
        [
            Paragraph("TOTAL", table_cell),
            Paragraph("EXECUTED", table_cell),
            Paragraph("🛡️ BLOCKED", table_cell),
            Paragraph("⚠️ PARTIAL", table_cell),
            Paragraph("❌ SUCCEEDED", table_cell),
            Paragraph("BLOCK RATE", table_cell),
            Paragraph("DURATION", table_cell),
        ],
        [
            Paragraph(f"<b>{run.total_scenarios}</b>", table_cell),
            Paragraph(f"<b>{total_executed}</b>", table_cell),
            Paragraph(f"<font color='#16A34A'><b>{run.blocked_count}</b></font>", table_cell),
            Paragraph(f"<font color='#D97706'><b>{run.partial_count}</b></font>", table_cell),
            Paragraph(f"<font color='#DC2626'><b>{run.succeeded_count}</b></font>", table_cell),
            Paragraph(f"<b>{block_rate:.1f}%</b>", table_cell),
            Paragraph(f"<b>{total_duration_ms:.1f}ms</b>", table_cell),
        ],
    ]
    scorecard_table = Table(scorecard_data, colWidths=[76, 76, 76, 76, 76, 76, 76])
    scorecard_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F1F5F9")),
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#FFFFFF")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(scorecard_table)
    story.append(Spacer(1, 14))

    # 5. Attack Scenario Outcomes Table
    story.append(Paragraph("Attack Scenarios & Outcome Ledger", section_heading))

    scenario_rows = [
        [
            Paragraph("Scenario ID", table_head),
            Paragraph("Scenario Name", table_head),
            Paragraph("Risk", table_head),
            Paragraph("Outcome", table_head),
            Paragraph("Latency", table_head),
        ]
    ]

    for r in run.results:
        sc = get_scenario_by_id(r.scenario_id)
        sc_name = sc.scenario_name if sc else r.scenario_id

        outcome_color = "#16A34A" if r.result_classification == "BLOCKED" else (
            "#D97706" if r.result_classification == "PARTIAL" else "#DC2626"
        )

        scenario_rows.append([
            Paragraph(f"<b>{html.escape(r.scenario_id)}</b>", table_cell),
            Paragraph(html.escape(sc_name), table_cell),
            Paragraph(html.escape(r.risk_id), table_cell),
            Paragraph(f"<font color='{outcome_color}'><b>{html.escape(r.result_classification)}</b></font>", table_cell),
            Paragraph(f"{r.latency_ms:.1f}ms" if r.latency_ms is not None else "-", table_cell),
        ])

    sc_table = Table(scenario_rows, colWidths=[76, 252, 60, 84, 60])
    sc_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1E293B")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#CBD5E1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#FFFFFF"), colors.HexColor("#F8FAFC")]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(sc_table)
    story.append(Spacer(1, 14))

    # 6. Detailed Evaluation Evidence & Analysis
    story.append(Paragraph("Detailed Scenario Evaluation & Evidence", section_heading))

    for idx, r in enumerate(run.results, start=1):
        sc = get_scenario_by_id(r.scenario_id)
        sc_name = sc.scenario_name if sc else r.scenario_id
        outcome_color = "#16A34A" if r.result_classification == "BLOCKED" else (
            "#D97706" if r.result_classification == "PARTIAL" else "#DC2626"
        )

        detail_flowables = [
            Paragraph(
                f"<b>{idx}. {html.escape(r.scenario_id)}: {html.escape(sc_name)}</b> &nbsp;|&nbsp; "
                f"Outcome: <font color='{outcome_color}'><b>{html.escape(r.result_classification)}</b></font>",
                ParagraphStyle("DetailTitle", parent=styles["Normal"], fontSize=9, leading=12, fontName="Helvetica-Bold", textColor=colors.HexColor("#0F172A")),
            ),
            Spacer(1, 3),
            Paragraph(f"<b>Evaluation Reason:</b> {html.escape(r.evaluation_reason or 'No evaluation reason recorded.')}", table_cell),
        ]

        if sc and sc.attack_description:
            detail_flowables.append(Spacer(1, 2))
            detail_flowables.append(Paragraph(f"<b>Attack Description:</b> {html.escape(sc.attack_description)}", table_cell))

        if sc and sc.expected_secure_behavior:
            detail_flowables.append(Spacer(1, 2))
            detail_flowables.append(Paragraph(f"<b>Expected Behavior:</b> {html.escape(sc.expected_secure_behavior)}", table_cell))

        if r.error_details:
            detail_flowables.append(Spacer(1, 2))
            detail_flowables.append(Paragraph(f"<font color='#DC2626'><b>Error Details:</b> {html.escape(r.error_details)}</font>", table_cell))

        box = Table([[detail_flowables]], colWidths=[532])
        box.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FFFFFF")),
            ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor("#E2E8F0")),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))

        story.append(KeepTogether(box))
        story.append(Spacer(1, 6))

    # Build the document
    doc.build(story, canvasmaker=AttackRunReportCanvas)
    return buffer.getvalue()
