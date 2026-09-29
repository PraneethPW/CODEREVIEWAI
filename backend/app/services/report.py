"""PDF rendering for a single persisted code review."""

from __future__ import annotations

import io
import textwrap
from datetime import datetime, timezone
from html import escape
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import Flowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


INK = colors.HexColor("#182033")
PURPLE = colors.HexColor("#6D28D9")
CYAN = colors.HexColor("#0891B2")
MUTED = colors.HexColor("#64748B")
PALE = colors.HexColor("#F4F1FA")
LINE = colors.HexColor("#D9D3E4")
SEVERITY_COLORS = {
    "critical": colors.HexColor("#BE123C"),
    "high": colors.HexColor("#DC2626"),
    "medium": colors.HexColor("#D97706"),
    "low": colors.HexColor("#0891B2"),
    "info": colors.HexColor("#64748B"),
}


def _font_safe(value: Any) -> str:
    """Keep built-in PDF fonts safe; make unsupported Unicode visible as escapes."""
    text = str(value if value is not None else "")
    return "".join(
        char if (ord(char) <= 255 and not 0xD800 <= ord(char) <= 0xDFFF and (ord(char) >= 32 and not 0x7F <= ord(char) <= 0x9F or char in "\t\r\n")) else f"\\u{ord(char):04x}"
        for char in text
    )


def _paragraph(value: Any, style: ParagraphStyle) -> Paragraph:
    safe = escape(_font_safe(value)).replace("\n", "<br/>") or " "
    return Paragraph(safe, style)


class SeverityChart(Flowable):
    """Compact vector chart that prints cleanly without raster assets."""

    def __init__(self, counts: dict[str, int]):
        super().__init__()
        self.counts = counts
        self.height = 5 * 23 + 8

    def wrap(self, avail_width: float, avail_height: float) -> tuple[float, float]:
        self.width = avail_width
        return self.width, self.height

    def draw(self) -> None:
        canvas = self.canv
        label_width = 66
        count_width = 38
        bar_width = max(30, self.width - label_width - count_width - 12)
        maximum = max(self.counts.values(), default=0) or 1
        for index, severity in enumerate(("critical", "high", "medium", "low", "info")):
            y = self.height - (index + 1) * 23 + 6
            count = self.counts.get(severity, 0)
            canvas.setFont("Helvetica-Bold", 8)
            canvas.setFillColor(SEVERITY_COLORS[severity])
            canvas.drawString(0, y + 3, severity.upper())
            canvas.setFillColor(PALE)
            canvas.roundRect(label_width, y, bar_width, 11, 4, stroke=0, fill=1)
            canvas.setFillColor(SEVERITY_COLORS[severity])
            fill_width = bar_width * count / maximum if count else 0
            if fill_width:
                canvas.roundRect(label_width, y, max(4, fill_width), 11, 4, stroke=0, fill=1)
            canvas.setFont("Helvetica", 8)
            canvas.setFillColor(INK)
            canvas.drawRightString(self.width, y + 2, str(count))


def _styles() -> dict[str, ParagraphStyle]:
    return {
        "title": ParagraphStyle("ReportTitle", fontName="Helvetica-Bold", fontSize=24, leading=29, textColor=INK, spaceAfter=5),
        "subtitle": ParagraphStyle("ReportSubtitle", fontName="Helvetica", fontSize=10, leading=14, textColor=MUTED, spaceAfter=13),
        "section": ParagraphStyle("ReportSection", fontName="Helvetica-Bold", fontSize=15, leading=19, textColor=PURPLE, spaceBefore=13, spaceAfter=7, keepWithNext=True),
        "finding": ParagraphStyle("FindingTitle", fontName="Helvetica-Bold", fontSize=11, leading=14, textColor=INK, spaceBefore=9, spaceAfter=5, keepWithNext=True),
        "body": ParagraphStyle("ReportBody", fontName="Helvetica", fontSize=8.5, leading=12, textColor=INK, spaceAfter=5),
        "small": ParagraphStyle("ReportSmall", fontName="Helvetica", fontSize=7.5, leading=10, textColor=MUTED, spaceAfter=3),
        "cell": ParagraphStyle("ReportCell", fontName="Helvetica", fontSize=7.5, leading=9, textColor=INK),
        "cell_small": ParagraphStyle("ReportCellSmall", fontName="Helvetica", fontSize=6.8, leading=8.2, textColor=INK),
        "cell_header": ParagraphStyle("ReportCellHeader", fontName="Helvetica-Bold", fontSize=7, leading=8.5, textColor=colors.white),
        "code": ParagraphStyle("ReportCode", fontName="Courier", fontSize=6.8, leading=8.5, textColor=INK, leftIndent=0, rightIndent=0, spaceAfter=0),
    }


def _table_style(header: bool = True) -> TableStyle:
    commands: list[tuple[Any, ...]] = [
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("GRID", (0, 0), (-1, -1), 0.35, LINE),
    ]
    if header:
        commands.extend([("BACKGROUND", (0, 0), (-1, 0), INK), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white)])
        commands.append(("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PALE]))
    else:
        commands.extend([("BACKGROUND", (0, 0), (-1, -1), PALE), ("BOX", (0, 0), (-1, -1), 0.5, LINE)])
    return TableStyle(commands)


def _code_block(story: list[Any], code: Any, width: float, styles: dict[str, ParagraphStyle], max_chars: int = 12_000) -> None:
    text = str(code if code is not None else "")
    truncated = len(text) > max_chars
    text = text[:max_chars]
    lines = text.splitlines() or [""]
    rows: list[list[Paragraph]] = []
    for line_number, line in enumerate(lines[:500], start=1):
        safe_line = _font_safe(line.expandtabs(4))
        wrapped = textwrap.wrap(safe_line, width=105, break_long_words=True, break_on_hyphens=False, drop_whitespace=False) or [""]
        for wrapped_index, chunk in enumerate(wrapped):
            prefix = f"{line_number:>4} " if wrapped_index == 0 else "     "
            rows.append([Paragraph(escape(prefix + chunk) or " ", styles["code"])])
    if len(lines) > 500:
        rows.append([Paragraph("... remaining lines omitted ...", styles["small"])])
    if truncated:
        rows.append([Paragraph("... code excerpt truncated for report size ...", styles["small"])])
    table = Table(rows, colWidths=[width], hAlign="LEFT", splitByRow=1)
    table.setStyle(_table_style(header=False))
    table.setStyle(TableStyle([("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7), ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]))
    story.extend([table, Spacer(1, 5)])


def _display_time(value: Any) -> str:
    if not value:
        return "Not recorded"
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return str(value)


def build_scan_report(
    *,
    scan: dict[str, Any],
    project_name: str,
    files: dict[str, str],
    findings: list[dict[str, Any]],
    proposals: list[dict[str, Any]],
    audit_logs: list[dict[str, Any]],
    events: list[dict[str, Any]],
) -> bytes:
    """Build a downloadable, evidence-grounded review PDF."""
    output = io.BytesIO()
    doc = SimpleDocTemplate(
        output,
        pagesize=A4,
        rightMargin=0.62 * inch,
        leftMargin=0.62 * inch,
        topMargin=0.62 * inch,
        bottomMargin=0.62 * inch,
        title=f"Code review report - {scan.get('filename', 'scan')}",
        author="CodeReview AI",
        subject="Static code review findings, code evidence, and remediation history",
    )
    styles = _styles()
    story: list[Any] = []
    counts = {severity: sum(item.get("severity") == severity for item in findings) for severity in ("critical", "high", "medium", "low", "info")}
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    story.append(_paragraph("Code Review Report", styles["title"]))
    story.append(_paragraph(f"{scan.get('filename', 'Code review')} · {project_name}", styles["subtitle"]))
    metadata = [
        [_paragraph("SCAN STATUS", styles["cell_header"]), _paragraph("LANGUAGE", styles["cell_header"]), _paragraph("REVIEW MODE", styles["cell_header"]), _paragraph("GENERATED", styles["cell_header"])],
        [_paragraph(scan.get("status", "Unknown"), styles["cell"]), _paragraph(scan.get("language", "Unknown"), styles["cell"]), _paragraph(scan.get("review_mode", "Balanced"), styles["cell"]), _paragraph(generated, styles["cell"])],
    ]
    summary_table = Table(metadata, colWidths=[doc.width * 0.21, doc.width * 0.20, doc.width * 0.20, doc.width * 0.39])
    summary_table.setStyle(_table_style(header=True))
    story.extend([summary_table, Spacer(1, 8)])
    summary_rows = [
        ["Scan ID", scan.get("id", ""), "Created", _display_time(scan.get("created_at"))],
        ["Files", len(files), "Lines", sum(len(content.splitlines()) for content in files.values())],
        ["Findings", len(findings), "OWASP mapped", sum(bool(item.get("owasp")) for item in findings)],
        ["Input type", scan.get("input_type", ""), "Completed", _display_time(scan.get("completed_at"))],
    ]
    compact = [[_paragraph(label, styles["small"]), _paragraph(value, styles["cell"]), _paragraph(label2, styles["small"]), _paragraph(value2, styles["cell"])] for label, value, label2, value2 in summary_rows]
    summary_table = Table(compact, colWidths=[doc.width * 0.17, doc.width * 0.33, doc.width * 0.17, doc.width * 0.33])
    summary_table.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("BACKGROUND", (0, 0), (-1, -1), PALE), ("BOX", (0, 0), (-1, -1), 0.5, LINE), ("INNERGRID", (0, 0), (-1, -1), 0.25, LINE), ("LEFTPADDING", (0, 0), (-1, -1), 6), ("RIGHTPADDING", (0, 0), (-1, -1), 6), ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]))
    story.extend([summary_table, _paragraph("Severity distribution", styles["section"]), SeverityChart(counts), Spacer(1, 5)])

    story.append(_paragraph("Files analyzed", styles["section"]))
    file_rows = [[_paragraph("FILE", styles["cell_header"]), _paragraph("LINES", styles["cell_header"]), _paragraph("CODE", styles["cell_header"])]]
    for path, content in files.items():
        file_rows.append([_paragraph(path, styles["cell_small"]), _paragraph(len(content.splitlines()), styles["cell"]), _paragraph("Included as finding evidence and fix excerpts where available", styles["cell_small"])])
    file_table = Table(file_rows, colWidths=[doc.width * 0.42, doc.width * 0.12, doc.width * 0.46], repeatRows=1, splitByRow=1)
    file_table.setStyle(_table_style(header=True))
    story.extend([file_table, _paragraph("Source code is included for each finding as redacted evidence excerpts. Suggested changes include before and replacement code when a fix proposal exists.", styles["small"])])

    story.append(_paragraph("Findings and recommendations", styles["section"]))
    if not findings:
        story.append(_paragraph("No supported findings were produced by the enabled static rules for this scan. A clean result does not prove that the code is free of issues.", styles["body"]))
    for index, finding in enumerate(findings, start=1):
        story.append(_paragraph(f"{index}. {finding.get('title', 'Finding')}", styles["finding"]))
        mapping = finding.get("owasp") or {}
        evidence = str(finding.get("evidence", ""))
        path = evidence.split(" — ", 1)[0] if " — " in evidence else (next(iter(files), scan.get("filename", "")))
        finding_rows = [
            [_paragraph("SEVERITY", styles["cell_header"]), _paragraph("CATEGORY", styles["cell_header"]), _paragraph("RULE", styles["cell_header"]), _paragraph("STATUS", styles["cell_header"]), _paragraph("LOCATION", styles["cell_header"])],
            [_paragraph(finding.get("severity", "unknown").upper(), styles["cell"]), _paragraph(finding.get("category", ""), styles["cell"]), _paragraph(finding.get("rule_id", ""), styles["cell"]), _paragraph(finding.get("status", "OPEN"), styles["cell"]), _paragraph(f"{path}:{finding.get('line', '?')}", styles["cell"])],
        ]
        finding_table = Table(finding_rows, colWidths=[doc.width * 0.15, doc.width * 0.17, doc.width * 0.20, doc.width * 0.15, doc.width * 0.33])
        finding_table.setStyle(_table_style(header=True))
        story.extend([finding_table, Spacer(1, 4)])
        if mapping:
            story.append(_paragraph(f"OWASP Top 10:2025: {mapping.get('category_id', '')} · {mapping.get('category_name', '')} (limited static mapping)", styles["small"]))
        story.append(_paragraph(f"Evidence: {finding.get('evidence', 'No detector detail recorded.')}", styles["body"]))
        story.append(_paragraph(f"Code evidence · {path}:{finding.get('line', '?')}", styles["small"]))
        _code_block(story, finding.get("excerpt", "No source excerpt recorded."), doc.width, styles, max_chars=2_000)
        explanation = finding.get("ai_explanation") or {}
        for label, key in (("Why it matters", "why_it_matters"), ("Recommended remediation", "recommendation"), ("Safer pattern", "safer_pattern"), ("Limitations", "limitations")):
            value = explanation.get(key)
            if value:
                story.append(_paragraph(f"{label}: {value}", styles["body"]))

    story.append(_paragraph("Suggested changes and code diffs", styles["section"]))
    if not proposals:
        story.append(_paragraph("No fix proposals have been generated for this scan yet. Generate a fix proposal from a finding to include its before and replacement code in a future report.", styles["body"]))
    for proposal_index, proposal in enumerate(proposals, start=1):
        story.append(_paragraph(f"{proposal_index}. {proposal.get('file_path', 'Source file')} · {proposal.get('status', 'PROPOSED')}", styles["finding"]))
        story.append(_paragraph(f"Finding {proposal.get('finding_id', '')} · {proposal.get('confidence_note', 'No rationale recorded.')}", styles["small"]))
        story.append(_paragraph("Before", styles["small"]))
        _code_block(story, proposal.get("before_code", ""), doc.width, styles, max_chars=8_000)
        story.append(_paragraph("Suggested replacement", styles["small"]))
        _code_block(story, proposal.get("replacement_code", ""), doc.width, styles, max_chars=8_000)

    story.append(_paragraph("Analysis errors and processing history", styles["section"]))
    error_events = [item for item in events if str(item.get("status", "")).upper() in {"FAILED", "ERROR"}]
    if error_events:
        story.append(_paragraph("The scan recorded the following failed processing stages:", styles["body"]))
        for event in error_events:
            story.append(_paragraph(f"{event.get('stage', 'UNKNOWN')}: {event.get('message', 'No error detail recorded.')}", styles["body"]))
    elif str(scan.get("status", "")).upper() == "FAILED":
        story.append(_paragraph("The scan failed, but no detailed failure event was persisted.", styles["body"]))
    else:
        story.append(_paragraph("No failed scan-processing stages were recorded.", styles["body"]))
    event_rows = [[_paragraph(label, styles["cell_header"]) for label in ("TIME", "STAGE", "STATUS", "DETAIL")]]
    for event in events:
        event_rows.append([
            _paragraph(_display_time(event.get("created_at")), styles["cell_small"]),
            _paragraph(event.get("stage", ""), styles["cell"]),
            _paragraph(event.get("status", ""), styles["cell"]),
            _paragraph(event.get("message", ""), styles["cell_small"]),
        ])
    if len(event_rows) > 1:
        event_table = Table(event_rows, colWidths=[doc.width * 0.22, doc.width * 0.17, doc.width * 0.17, doc.width * 0.44], repeatRows=1, splitByRow=1)
        event_table.setStyle(_table_style(header=True))
        story.append(event_table)

    story.append(_paragraph("Review and change history", styles["section"]))
    if audit_logs:
        audit_rows = [[_paragraph(label, styles["cell_header"]) for label in ("TIME", "ACTION", "FINDING", "RATIONALE")]]
        for item in audit_logs:
            audit_rows.append([
                _paragraph(_display_time(item.get("created_at")), styles["cell_small"]),
                _paragraph(item.get("action", ""), styles["cell"]),
                _paragraph(item.get("finding_id") or "Scan", styles["cell_small"]),
                _paragraph(item.get("rationale") or "No rationale recorded.", styles["cell_small"]),
            ])
        audit_table = Table(audit_rows, colWidths=[doc.width * 0.22, doc.width * 0.18, doc.width * 0.25, doc.width * 0.35], repeatRows=1, splitByRow=1)
        audit_table.setStyle(_table_style(header=True))
        story.append(audit_table)
    else:
        story.append(_paragraph("No review decisions or verification actions have been recorded yet.", styles["body"]))

    story.extend([
        _paragraph("Scope and limitations", styles["section"]),
        _paragraph("This report describes static evidence from the submitted files and enabled analysis rules. Submitted programs are not executed. OWASP labels are limited classifications and do not certify security or compliance. Review code suggestions before applying them and validate behavior in your own environment.", styles["body"]),
    ])

    def draw_page(canvas: Any, page_doc: Any) -> None:
        canvas.saveState()
        canvas.setStrokeColor(LINE)
        canvas.setLineWidth(0.45)
        canvas.line(page_doc.leftMargin, 0.42 * inch, A4[0] - page_doc.rightMargin, 0.42 * inch)
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(MUTED)
        canvas.drawString(page_doc.leftMargin, 0.27 * inch, "CodeReview AI · Static analysis report")
        canvas.drawRightString(A4[0] - page_doc.rightMargin, 0.27 * inch, f"Page {page_doc.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=draw_page, onLaterPages=draw_page)
    return output.getvalue()
