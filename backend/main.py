"""
SIH26106 Email Threat Detection, GeoLocation & Forensic Intelligence Platform.
FastAPI Application Entry Point with Case Management & Evidence Persistence.
"""

from fastapi import FastAPI, UploadFile, File, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import logging
import json
from typing import Optional, Dict, Any

try:
    from .models import HealthResponse
    from .db_models import CaseListResponse, CaseDetailResponse, EvidenceRecord, AnalysisRecord
    from .analyzer import PARSER_VERSION
    from .database import init_db
    from .case_service import CaseService
    from .blockchain_service import get_blockchain_service
    from .services.llm_narrative import generate_narrative, check_ollama_health
except ImportError:
    from models import HealthResponse
    from db_models import CaseListResponse, CaseDetailResponse, EvidenceRecord, AnalysisRecord
    from analyzer import PARSER_VERSION
    from database import init_db
    from case_service import CaseService
    from blockchain_service import get_blockchain_service
    from services.llm_narrative import generate_narrative, check_ollama_health

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("backend.main")

# Max upload size limit: 15MB
MAX_FILE_SIZE_BYTES = 15 * 1024 * 1024

# Initialize DB schema on module load
try:
    init_db()
except Exception as exc:
    logger.warning(f"Initial DB check: {exc}")

# Default Case Service instance
case_service = CaseService()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: ensure database schema on startup."""
    try:
        init_db()
        logger.info("Forensic database schema verified and initialized.")
    except Exception as exc:
        logger.error(f"Database initialization failed: {exc}", exc_info=True)
    yield


app = FastAPI(
    title="SIH26106 Email Threat Detection API",
    description="Forensic analysis pipeline for .eml email threats, authentication validation, IOC extraction, relay tracing, and evidence persistence.",
    version=PARSER_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Enable CORS for local frontend development and integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(ValueError)
async def value_error_handler(request, exc: ValueError):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"error": "Bad Request", "detail": str(exc)}
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request, exc: Exception):
    logger.error(f"Unhandled server error: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": "Internal Server Error", "detail": "An unexpected error occurred during email analysis."}
    )


@app.get("/", response_model=HealthResponse, tags=["Health"])
async def root():
    """Root status endpoint returning service health and version."""
    return HealthResponse(
        status="online",
        service="SIH26106 Email Threat Detection API",
        version=PARSER_VERSION,
        timestamp=datetime.now(timezone.utc).isoformat()
    )


@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health():
    """Health check endpoint for monitoring and uptime probes."""
    return HealthResponse(
        status="online",
        service="SIH26106 Email Threat Detection API",
        version=PARSER_VERSION,
        timestamp=datetime.now(timezone.utc).isoformat()
    )


@app.post(
    "/analyze",
    tags=["Analysis"],
    summary="Analyze .eml email file and persist case evidence"
)
async def analyze_email(file: UploadFile = File(...)):
    """
    Accepts an uploaded raw .eml file, parses RFC headers, verifies SPF/DKIM/DMARC status,
    extracts IOCs, maps the Received-header relay path, computes exact SHA-256 payload hash,
    stores case & evidence in SQLite, and returns a structured forensic risk report.
    """
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No filename provided in upload."
        )

    # Read uploaded content
    try:
        content = await file.read()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to read uploaded file: {str(exc)}"
        )

    # Validate file size
    if len(content) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The uploaded file is empty. Please provide a valid .eml file."
        )

    if len(content) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Uploaded file exceeds maximum allowed size of {MAX_FILE_SIZE_BYTES // (1024 * 1024)}MB."
        )

    try:
        # returns frontend-shaped dict via ml_bridge
        analysis_result = case_service.process_and_store_email(
            raw_bytes=content,
            filename=file.filename
        )
        return analysis_result
    except ValueError as val_err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(val_err))
    except Exception as exc:
        logger.error(f"Analysis and persistence failed for {file.filename}: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process and analyze the email file."
        )


@app.get(
    "/cases",
    response_model=CaseListResponse,
    tags=["Cases"],
    summary="List stored forensic cases"
)
async def list_cases(
    limit: int = Query(default=50, ge=1, le=200, description="Max records to return"),
    offset: int = Query(default=0, ge=0, description="Pagination offset")
):
    """Retrieves paginated list of analyzed cases sorted newest first."""
    return case_service.list_cases(limit=limit, offset=offset)


@app.get(
    "/cases/{case_id}",
    tags=["Cases"],
    summary="Get case details and forensic analysis report"
)
async def get_case(case_id: str):
    """Fetches case metadata, associated digital evidence record, and full analysis report."""
    case_detail = case_service.get_case_detail(case_id)
    if not case_detail:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Case with ID '{case_id}' was not found."
        )
    # The case_detail.analysis is already the frontend-shaped JSON from DB
    return case_detail


@app.get(
    "/cases/{case_id}/evidence",
    response_model=EvidenceRecord,
    tags=["Cases"],
    summary="Get digital evidence and SHA-256 hash for a case"
)
async def get_case_evidence(case_id: str):
    """Fetches digital evidence, exact SHA-256 digest, and chain-of-custody reference for a case."""
    evidence = case_service.get_case_evidence(case_id)
    if not evidence:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence for case ID '{case_id}' was not found."
        )
    return evidence


@app.get(
    "/cases/{case_id}/geo",
    tags=["Cases"],
    summary="Get geolocation intelligence for a specific case"
)
async def get_case_geo(case_id: str):
    """Returns geolocation and network intelligence for all IPs associated with a case."""
    case_detail = case_service.get_case_detail(case_id)
    if not case_detail or not case_detail.analysis:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case or analysis not found.")
    
    # Return the ip_intelligence part of the frontend-shaped analysis
    return {
        "case_id": case_id,
        "ip_intelligence": case_detail.analysis.get("ip_intelligence", []),
        "domain_intelligence": case_detail.analysis.get("domain_intelligence", [])
    }


# ============ REPORT ENDPOINTS ============

@app.get(
    "/cases/{case_id}/report",
    tags=["Reports"],
    summary="Get forensic report with narrative summary"
)
async def get_case_report(case_id: str):
    """Returns JSON report with AI-generated or deterministic narrative summary."""
    case_detail = case_service.get_case_detail(case_id)
    if not case_detail or not case_detail.analysis:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case or analysis not found.")
    
    analysis = case_detail.analysis
    evidence = case_detail.evidence
    
    # Check if narrative already stored
    narrative_data = analysis.get("metadata", {}).get("narrative")
    
    if not narrative_data:
        # Generate narrative using the new service
        narrative_result = await generate_narrative(analysis, case_id)
        narrative = narrative_result.get("narrative", "")
        
        # Store narrative in metadata
        if "metadata" in analysis:
            analysis["metadata"]["narrative"] = narrative
            analysis["metadata"]["narrative_metadata"] = {
                "generation_method": narrative_result.get("generation_method"),
                "model": narrative_result.get("model"),
                "generated_at": narrative_result.get("timestamp")
            }
            # Update DB
            try:
                case_service.analysis_repo.save_analysis(
                    AnalysisRecord(
                        case_id=case_id,
                        analysis_json=json.dumps(analysis),
                        analysis_timestamp=analysis["metadata"]["analysis_timestamp"],
                        parser_version=analysis["metadata"]["parser_version"],
                    )
                )
            except Exception as exc:
                logger.warning(f"Failed to persist narrative: {exc}")
    else:
        narrative = narrative_data
    
    return {
        "case_id": case_id,
        "analysis": analysis,
        "evidence": evidence.model_dump() if evidence else None,
        "narrative": narrative,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


@app.get(
    "/cases/{case_id}/report/pdf",
    tags=["Reports"],
    summary="Get forensic report as PDF"
)
async def get_case_report_pdf(case_id: str):
    """Returns PDF forensic report."""
    case_detail = case_service.get_case_detail(case_id)
    if not case_detail or not case_detail.analysis:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case or analysis not found.")
    
    analysis = case_detail.analysis
    evidence = case_detail.evidence
    
    try:
        pdf_bytes = generate_pdf_report(case_id, analysis, evidence)
        return StreamingResponse(
            iter([pdf_bytes]),
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=ThreatLens-Report-{case_id}.pdf"}
        )
    except ImportError:
        # ReportLab not installed - return JSON with gap info
        logger.warning("ReportLab not installed, returning JSON instead of PDF")
        return JSONResponse(
            status_code=501,
            content={
                "error": "PDF generation unavailable",
                "detail": "ReportLab library not installed. Install with: pip install reportlab",
                "json_report": {
                    "case_id": case_id,
                    "analysis": analysis,
                    "evidence": evidence.model_dump() if evidence else None,
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                }
            }
        )
    except Exception as exc:
        logger.error(f"PDF generation failed: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to generate PDF report: {str(exc)}"
        )


# ============ BLOCKCHAIN ENDPOINTS ============

# ============ LLM SERVICE ENDPOINTS ============

@app.get("/llm/health", tags=["LLM"], summary="Check Ollama service health")
async def get_llm_health():
    """Returns Ollama connectivity and model availability status."""
    return await check_ollama_health()


@app.get("/blockchain/status", tags=["Blockchain"], summary="Get blockchain service status")
async def get_blockchain_status():
    """Returns blockchain service availability and network information."""
    blockchain_service = get_blockchain_service()
    
    if not blockchain_service:
        return {
            "available": False,
            "message": "Blockchain service is not available. Missing dependencies or configuration."
        }
    
    try:
        info = blockchain_service.get_blockchain_info()
        return {
            "available": True,
            "connected": info["connected"],
            "network_id": info["network_id"],
            "latest_block": info["latest_block"],
            "contract_address": info["contract_address"],
            "account_address": info["account_address"]
        }
    except Exception as exc:
        logger.error(f"Blockchain status check failed: {exc}", exc_info=True)
        return {
            "available": False,
            "message": f"Blockchain service error: {str(exc)}"
        }


@app.post("/blockchain/register", tags=["Blockchain"], summary="Register evidence on blockchain")
async def register_evidence_blockchain(
    evidence_id: str = Query(..., description="Evidence ID to register"),
    case_id: str = Query(..., description="Associated case ID"),
    stage: str = Query(default="FORENSIC_ANALYSIS", description="Processing stage")
):
    """
    Registers forensic evidence hash on blockchain for tamper-proof verification.
    Uses the existing SHA-256 hash from the evidence record.
    """
    blockchain_service = get_blockchain_service()
    
    if not blockchain_service:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Blockchain service is not available."
        )
    
    # Get evidence record to obtain SHA-256 hash
    evidence = case_service.get_case_evidence(case_id)
    if not evidence:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence for case ID '{case_id}' was not found."
        )
    
    try:
        result = blockchain_service.register_evidence(
            evidence_id=evidence_id,
            sha256_hash=evidence.sha256,
            stage=stage
        )
        
        logger.info(f"Registered evidence {evidence_id} on blockchain: {result['transaction_hash']}")
        return result
        
    except Exception as exc:
        logger.error(f"Blockchain registration failed for {evidence_id}: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to register evidence on blockchain: {str(exc)}"
        )


@app.get("/blockchain/verify/{evidence_id}", tags=["Blockchain"], summary="Verify evidence integrity on blockchain")
async def verify_evidence_blockchain(evidence_id: str):
    """
    Verifies evidence integrity by comparing current hash with blockchain record.
    Returns VERIFIED or EVIDENCE_TAMPERED status.
    """
    blockchain_service = get_blockchain_service()
    
    if not blockchain_service:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Blockchain service is not available."
        )
    
    try:
        # In a real scenario, we would recalculate the hash from the evidence file.
        # Here we get it from the DB as the "current" hash to verify registration.
        evidence_record = case_service.evidence_repo.get_evidence(evidence_id)
        if not evidence_record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Evidence record {evidence_id} not found in local database."
            )
        
        current_hash = evidence_record.sha256
        
        result = blockchain_service.verify_evidence(
            evidence_id=evidence_id,
            current_sha256_hash=current_hash
        )
        
        logger.info(f"Verified evidence {evidence_id}: {result['status']}")
        return result
        
    except HTTPException:
        raise
    except Exception as exc:
        logger.error(f"Blockchain verification failed for {evidence_id}: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to verify evidence on blockchain: {str(exc)}"
        )


@app.get("/blockchain/evidence/{evidence_id}", tags=["Blockchain"], summary="Get blockchain evidence record")
async def get_blockchain_evidence(evidence_id: str):
    """Retrieves complete evidence record from blockchain."""
    blockchain_service = get_blockchain_service()
    
    if not blockchain_service:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Blockchain service is not available."
        )
    
    try:
        evidence = blockchain_service.get_evidence(evidence_id)
        
        if not evidence:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Evidence ID '{evidence_id}' not found on blockchain."
            )
        
        return evidence
    except Exception as exc:
        logger.error(f"Failed to retrieve blockchain evidence {evidence_id}: {exc}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve evidence from blockchain: {str(exc)}"
        )


# ============ REPORT GENERATION HELPERS ============
# Now imported from backend.services.llm_narrative
# async def generate_narrative(...) -> Dict[str, Any]:
#     ...


def generate_pdf_report(case_id: str, analysis: Dict[str, Any], evidence: Optional[EvidenceRecord]) -> bytes:
    """
    Generate PDF forensic report using ReportLab.
    Returns PDF bytes.
    """
    try:
        from reportlab.lib.pagesizes import letter, A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib.colors import HexColor
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
        from reportlab.lib.enums import TA_LEFT, TA_CENTER
        from io import BytesIO
    except ImportError:
        raise ImportError("ReportLab not installed")
    
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=72)
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=18, textColor=HexColor('#00e5ff'), spaceAfter=12)
    heading_style = ParagraphStyle('CustomHeading', parent=styles['Heading2'], fontSize=14, textColor=HexColor('#ffa000'), spaceBefore=12, spaceAfter=6)
    subheading_style = ParagraphStyle('CustomSubHeading', parent=styles['Heading3'], fontSize=11, textColor=HexColor('#ffffff'), spaceBefore=8, spaceAfter=4)
    body_style = ParagraphStyle('CustomBody', parent=styles['Normal'], fontSize=9, textColor=HexColor('#cccccc'), spaceAfter=4)
    mono_style = ParagraphStyle('CustomMono', parent=styles['Normal'], fontName='Courier', fontSize=8, textColor=HexColor('#888888'), spaceAfter=2)
    
    story = []
    
    # Title
    story.append(Paragraph("THREATLENS FORENSIC ANALYSIS REPORT", title_style))
    story.append(Paragraph(f"Case ID: {case_id}", subheading_style))
    story.append(Spacer(1, 12))
    
    # Metadata
    meta = analysis.get("metadata", {})
    story.append(Paragraph("EXECUTIVE SUMMARY", heading_style))
    story.append(Paragraph(f"<b>File:</b> {meta.get('file_name', 'N/A')}", body_style))
    story.append(Paragraph(f"<b>Size:</b> {meta.get('file_size_bytes', 0)} bytes", body_style))
    story.append(Paragraph(f"<b>Analyzed:</b> {meta.get('analysis_timestamp', 'N/A')}", body_style))
    story.append(Paragraph(f"<b>Parser Version:</b> {meta.get('parser_version', 'N/A')}", body_style))
    story.append(Paragraph(f"<b>Evidence Hash:</b> {meta.get('evidence_hash', 'N/A')}", body_style))
    story.append(Spacer(1, 12))
    
    # Risk Assessment
    risk = analysis.get("risk", {})
    score = risk.get("score", 0)
    classification = risk.get("classification", "UNKNOWN")
    story.append(Paragraph("RISK ASSESSMENT", heading_style))
    story.append(Paragraph(f"<b>Score:</b> {score}/100", body_style))
    story.append(Paragraph(f"<b>Classification:</b> {classification}", body_style))
    story.append(Paragraph(f"<b>Scoring Method:</b> {risk.get('scoring_type', 'N/A')}", body_style))
    story.append(Spacer(1, 6))
    
    # ML Signals
    ml_signals = risk.get("ml_signals", {})
    if ml_signals:
        story.append(Paragraph("AI/ML ANALYSIS", heading_style))
        story.append(Paragraph(f"<b>Model:</b> {ml_signals.get('model_name', 'N/A')}", body_style))
        story.append(Paragraph(f"<b>Phishing Probability:</b> {ml_signals.get('phishing_probability', 0):.1%}", body_style))
        story.append(Paragraph(f"<b>BEC Probability:</b> {ml_signals.get('bec_probability', 0):.1%}", body_style))
        story.append(Paragraph(f"<b>Confidence:</b> {ml_signals.get('confidence', 0):.1%}", body_style))
        story.append(Spacer(1, 6))
    
    # Reasons/Signals
    reasons = risk.get("reasons", [])
    signals = risk.get("signals", [])
    if reasons or signals:
        story.append(Paragraph("TRIGGERED FORENSIC SIGNALS", heading_style))
        all_signals = []
        for r in reasons:
            all_signals.append(f"• {r}")
        for s in signals:
            all_signals.append(f"• [{s.get('severity', '')}] {s.get('signal', '')} ({s.get('category', '')}: +{s.get('weight', 0)})")
        
        for sig in all_signals[:20]:  # Limit for PDF
            story.append(Paragraph(sig, body_style))
        if len(all_signals) > 20:
            story.append(Paragraph(f"... and {len(all_signals) - 20} more signals", mono_style))
        story.append(Spacer(1, 6))
    
    # Authentication
    auth = analysis.get("authentication", {})
    story.append(Paragraph("AUTHENTICATION RESULTS", heading_style))
    auth_data = [
        ["Protocol", "Status", "Detail"],
        ["SPF", auth.get("spf", {}).get("status", "N/A"), auth.get("spf", {}).get("detail", "")[:80]],
        ["DKIM", auth.get("dkim", {}).get("status", "N/A"), auth.get("dkim", {}).get("detail", "")[:80]],
        ["DMARC", auth.get("dmarc", {}).get("status", "N/A"), auth.get("dmarc", {}).get("detail", "")[:80]],
    ]
    auth_table = Table(auth_data, colWidths=[1*inch, 1*inch, 4*inch])
    auth_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#1a1a2e')),
        ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#00e5ff')),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#333333')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [HexColor('#111111'), HexColor('#1a1a2e')]),
    ]))
    story.append(auth_table)
    story.append(Spacer(1, 12))
    
    # Email Metadata
    email = analysis.get("email", {})
    story.append(Paragraph("EMAIL METADATA", heading_style))
    email_data = [
        ["Field", "Value"],
        ["From", email.get("from", "N/A")],
        ["To", ", ".join(email.get("to", []))],
        ["Subject", email.get("subject", "N/A")],
        ["Date", email.get("date", "N/A")],
        ["Message-ID", email.get("message_id", "N/A")],
        ["Return-Path", email.get("return_path", "N/A")],
        ["Reply-To", email.get("reply_to", "N/A")],
    ]
    email_table = Table(email_data, colWidths=[1.5*inch, 4.5*inch])
    email_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#1a1a2e')),
        ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#00e5ff')),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#333333')),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [HexColor('#111111'), HexColor('#1a1a2e')]),
    ]))
    story.append(email_table)
    story.append(Spacer(1, 12))
    
    # IOCs
    iocs = analysis.get("iocs", {})
    story.append(Paragraph("INDICATORS OF COMPROMISE", heading_style))
    if iocs.get("urls"):
        story.append(Paragraph("<b>URLs:</b>", subheading_style))
        for url in iocs["urls"][:10]:
            story.append(Paragraph(f"• {url}", mono_style))
    if iocs.get("domains"):
        story.append(Paragraph("<b>Domains:</b>", subheading_style))
        for domain in iocs["domains"][:10]:
            story.append(Paragraph(f"• {domain}", mono_style))
    if iocs.get("ip_addresses"):
        story.append(Paragraph("<b>IP Addresses:</b>", subheading_style))
        for ip in iocs["ip_addresses"][:10]:
            story.append(Paragraph(f"• {ip}", mono_style))
    if iocs.get("email_addresses"):
        story.append(Paragraph("<b>Email Addresses:</b>", subheading_style))
        for addr in iocs["email_addresses"][:10]:
            story.append(Paragraph(f"• {addr}", mono_style))
    story.append(Spacer(1, 12))
    
    # Narrative
    narrative = analysis.get("metadata", {}).get("narrative") or "Narrative not generated."
    story.append(Paragraph("NARRATIVE SUMMARY", heading_style))
    story.append(Paragraph(narrative, body_style))
    story.append(Spacer(1, 12))
    
    # Evidence & Blockchain
    story.append(Paragraph("EVIDENCE & CHAIN OF CUSTODY", heading_style))
    if evidence:
        story.append(Paragraph(f"<b>Evidence ID:</b> {evidence.evidence_id}", body_style))
        story.append(Paragraph(f"<b>SHA-256:</b> {evidence.sha256}", mono_style))
        story.append(Paragraph(f"<b>Collected:</b> {evidence.collected_at}", body_style))
        story.append(Paragraph(f"<b>Storage:</b> {evidence.storage_reference}", body_style))
    story.append(Paragraph(f"<b>On-Chain Status:</b> {meta.get('on_chain_status', 'pending')}", body_style))
    if meta.get("blockchain_tx_hash"):
        story.append(Paragraph(f"<b>Transaction:</b> {meta.get('blockchain_tx_hash')}", mono_style))
    
    doc.build(story)
    buffer.seek(0)
    return buffer.read()
