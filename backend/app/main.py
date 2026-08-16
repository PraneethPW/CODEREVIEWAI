from __future__ import annotations
import os, uuid, json, hashlib, secrets, re, io, zipfile, asyncio, difflib
from datetime import datetime, timedelta, timezone
from typing import Literal
import httpx
from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Form, BackgroundTasks
from fastapi.responses import PlainTextResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import create_engine, String, Text, DateTime, ForeignKey, Integer, JSON, select, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session, relationship, sessionmaker
from .analysis import analyze_source
from .services.ingestion import SourceFile, decode_source, extract_zip, MAX_FILES

def utc_now()->datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)

DB=os.getenv("DATABASE_URL","sqlite:///./codereview.db").replace("postgresql://","postgresql+psycopg://")
engine=create_engine(DB, connect_args={"check_same_thread":False} if DB.startswith("sqlite") else {})
SessionLocal=sessionmaker(engine, expire_on_commit=False)
class Base(DeclarativeBase): pass
class User(Base):
    __tablename__="users"; id:Mapped[str]=mapped_column(String,primary_key=True,default=lambda:str(uuid.uuid4())); email:Mapped[str]=mapped_column(String,unique=True,index=True); password_hash:Mapped[str]=mapped_column(String); name:Mapped[str]=mapped_column(String); created_at:Mapped[datetime]=mapped_column(DateTime,default=utc_now)
class Project(Base):
    __tablename__="projects"; id:Mapped[str]=mapped_column(String,primary_key=True,default=lambda:str(uuid.uuid4())); user_id:Mapped[str]=mapped_column(ForeignKey("users.id"),index=True); name:Mapped[str]=mapped_column(String); language:Mapped[str]=mapped_column(String); framework:Mapped[str|None]=mapped_column(String,nullable=True); repository_url:Mapped[str|None]=mapped_column(String,nullable=True); description:Mapped[str|None]=mapped_column(Text,nullable=True); security_profile:Mapped[str]=mapped_column(String,default="Standard"); created_at:Mapped[datetime]=mapped_column(DateTime,default=utc_now)
class Scan(Base):
    __tablename__="scans"; id:Mapped[str]=mapped_column(String,primary_key=True,default=lambda:str(uuid.uuid4())); project_id:Mapped[str]=mapped_column(ForeignKey("projects.id"),index=True); user_id:Mapped[str]=mapped_column(ForeignKey("users.id"),index=True); status:Mapped[str]=mapped_column(String,default="CREATED"); input_type:Mapped[str]=mapped_column(String); source:Mapped[str]=mapped_column(Text); filename:Mapped[str]=mapped_column(String); language:Mapped[str]=mapped_column(String,default="text"); review_mode:Mapped[str]=mapped_column(String,default="Balanced"); created_at:Mapped[datetime]=mapped_column(DateTime,default=utc_now); completed_at:Mapped[datetime|None]=mapped_column(DateTime,nullable=True)
class Finding(Base):
    __tablename__="findings"; id:Mapped[str]=mapped_column(String,primary_key=True,default=lambda:str(uuid.uuid4())); scan_id:Mapped[str]=mapped_column(ForeignKey("scans.id"),index=True); rule_id:Mapped[str]=mapped_column(String); title:Mapped[str]=mapped_column(String); category:Mapped[str]=mapped_column(String); severity:Mapped[str]=mapped_column(String); line:Mapped[int]=mapped_column(Integer); excerpt:Mapped[str]=mapped_column(Text); evidence:Mapped[str]=mapped_column(Text); status:Mapped[str]=mapped_column(String,default="OPEN"); ai_explanation:Mapped[dict]=mapped_column(JSON,default=dict)
class AuditLog(Base):
    __tablename__="audit_logs"; id:Mapped[str]=mapped_column(String,primary_key=True,default=lambda:str(uuid.uuid4())); user_id:Mapped[str]=mapped_column(ForeignKey("users.id")); scan_id:Mapped[str|None]=mapped_column(String,nullable=True); finding_id:Mapped[str|None]=mapped_column(String,nullable=True); action:Mapped[str]=mapped_column(String); rationale:Mapped[str|None]=mapped_column(Text,nullable=True); created_at:Mapped[datetime]=mapped_column(DateTime,default=utc_now)
# Compatibility tables reserved for expanded deployments.
class ScanFile(Base): __tablename__="scan_files"; id:Mapped[str]=mapped_column(String,primary_key=True,default=lambda:str(uuid.uuid4())); scan_id:Mapped[str]=mapped_column(String); filename:Mapped[str]=mapped_column(String)
class FindingEvidence(Base): __tablename__="finding_evidence"; id:Mapped[str]=mapped_column(String,primary_key=True,default=lambda:str(uuid.uuid4())); finding_id:Mapped[str]=mapped_column(String); detail:Mapped[str]=mapped_column(Text)
class ReviewAction(Base): __tablename__="review_actions"; id:Mapped[str]=mapped_column(String,primary_key=True,default=lambda:str(uuid.uuid4())); finding_id:Mapped[str]=mapped_column(String); action:Mapped[str]=mapped_column(String)
class DeveloperRationale(Base): __tablename__="developer_rationale"; id:Mapped[str]=mapped_column(String,primary_key=True,default=lambda:str(uuid.uuid4())); finding_id:Mapped[str]=mapped_column(String); rationale:Mapped[str]=mapped_column(Text)
class Escalation(Base): __tablename__="escalations"; id:Mapped[str]=mapped_column(String,primary_key=True,default=lambda:str(uuid.uuid4())); finding_id:Mapped[str]=mapped_column(String); note:Mapped[str|None]=mapped_column(Text,nullable=True)
class PolicyConfig(Base): __tablename__="policy_config"; id:Mapped[str]=mapped_column(String,primary_key=True,default=lambda:str(uuid.uuid4())); project_id:Mapped[str]=mapped_column(String); config:Mapped[dict]=mapped_column(JSON,default=dict)
class AIExplanation(Base): __tablename__="ai_explanations"; id:Mapped[str]=mapped_column(String,primary_key=True,default=lambda:str(uuid.uuid4())); finding_id:Mapped[str]=mapped_column(String); payload:Mapped[dict]=mapped_column(JSON,default=dict)
class ScanStatistic(Base): __tablename__="scan_statistics"; id:Mapped[str]=mapped_column(String,primary_key=True,default=lambda:str(uuid.uuid4())); scan_id:Mapped[str]=mapped_column(String); values:Mapped[dict]=mapped_column(JSON,default=dict)
class ModelMetadata(Base): __tablename__="model_metadata"; id:Mapped[str]=mapped_column(String,primary_key=True,default=lambda:str(uuid.uuid4())); name:Mapped[str]=mapped_column(String); metadata_json:Mapped[dict]=mapped_column(JSON,default=dict)
class ScanEvent(Base):
    __tablename__="scan_events"; id:Mapped[str]=mapped_column(String,primary_key=True,default=lambda:str(uuid.uuid4())); scan_id:Mapped[str]=mapped_column(String,index=True); user_id:Mapped[str]=mapped_column(String,index=True); sequence:Mapped[int]=mapped_column(Integer); stage:Mapped[str]=mapped_column(String); status:Mapped[str]=mapped_column(String); message:Mapped[str]=mapped_column(Text); metrics:Mapped[dict]=mapped_column(JSON,default=dict); created_at:Mapped[datetime]=mapped_column(DateTime,default=utc_now)
class FixProposal(Base):
    __tablename__="fix_proposals"; id:Mapped[str]=mapped_column(String,primary_key=True,default=lambda:str(uuid.uuid4())); finding_id:Mapped[str]=mapped_column(String,index=True); scan_id:Mapped[str]=mapped_column(String,index=True); user_id:Mapped[str]=mapped_column(String,index=True); file_path:Mapped[str]=mapped_column(String); before_code:Mapped[str]=mapped_column(Text); replacement_code:Mapped[str]=mapped_column(Text); unified_diff:Mapped[str]=mapped_column(Text); confidence_note:Mapped[str]=mapped_column(Text); can_apply:Mapped[int]=mapped_column(Integer,default=0); status:Mapped[str]=mapped_column(String,default="PROPOSED"); created_at:Mapped[datetime]=mapped_column(DateTime,default=utc_now)
class WorkingCopy(Base):
    __tablename__="working_copies"; id:Mapped[str]=mapped_column(String,primary_key=True,default=lambda:str(uuid.uuid4())); scan_id:Mapped[str]=mapped_column(String,unique=True,index=True); user_id:Mapped[str]=mapped_column(String,index=True); files_json:Mapped[dict]=mapped_column(JSON,default=dict); updated_at:Mapped[datetime]=mapped_column(DateTime,default=utc_now)
Base.metadata.create_all(engine)

app=FastAPI(title="CodeReview AI",version="1.0.0")
app.add_middleware(CORSMiddleware,allow_origins=[os.getenv("FRONTEND_URL","http://localhost:5173")],allow_credentials=True,allow_methods=["*"],allow_headers=["*"])
oauth=OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login"); secret=os.getenv("JWT_SECRET","change-this-in-production")
def hash_password(password:str)->str:
    salt=secrets.token_hex(16)
    digest=hashlib.pbkdf2_hmac("sha256",password.encode(),salt.encode(),310_000).hex()
    return f"pbkdf2_sha256${salt}${digest}"
def verify_password(password:str, encoded:str)->bool:
    try:
        _,salt,expected=encoded.split("$",2)
        actual=hashlib.pbkdf2_hmac("sha256",password.encode(),salt.encode(),310_000).hex()
        return secrets.compare_digest(actual,expected)
    except ValueError: return False
def db():
    with SessionLocal() as s: yield s
def token_for(user:User): return jwt.encode({"sub":user.id,"exp":datetime.now(timezone.utc)+timedelta(hours=12)},secret,algorithm=os.getenv("JWT_ALGORITHM","HS256"))
def me(token:str=Depends(oauth),s:Session=Depends(db)):
    try: uid=jwt.decode(token,secret,algorithms=[os.getenv("JWT_ALGORITHM","HS256")])["sub"]
    except JWTError: raise HTTPException(401,"Invalid session")
    user=s.get(User,uid)
    if not user: raise HTTPException(401,"User not found")
    return user
class Register(BaseModel): email:EmailStr; password:str=Field(min_length=8); name:str=Field(min_length=2,max_length=80)
class Login(BaseModel): email:EmailStr; password:str
class ProjectIn(BaseModel): name:str=Field(min_length=2,max_length=100); language:str; framework:str|None=None; repository_url:str|None=None; description:str|None=None; security_profile:str="Standard"
class ScanIn(BaseModel): project_id:str; input_type:Literal["paste","diff","upload"]="paste"; source:str=Field(min_length=1,max_length=500_000); filename:str=Field(default="snippet.py",max_length=200); language:str="auto"; review_mode:Literal["Quick","Balanced","Deep"]="Balanced"; checks:dict[str,bool]=Field(default_factory=dict)
class Decision(BaseModel): rationale:str=Field(min_length=1,max_length=2000)
class GroundedExplanation(BaseModel):
    finding_id:str; summary:str; why_it_matters:str; recommendation:str; safer_pattern:str; limitations:str
class GroundedFix(BaseModel):
    finding_id:str; file_path:str; replacement_code:str=Field(min_length=1,max_length=20_000); confidence_note:str; limitations:str
class FixRequest(BaseModel): use_ai:bool=False
def redact_text(value:str)->str:
    value=re.sub(r"(?i)(token|secret|password|api[_-]?key)(\s*[:=]\s*)['\"]?[^'\"\s,;}]+",r"\1\2***REDACTED***",value)
    return re.sub(r"(?i)(authorization\s*:\s*bearer\s+)[A-Za-z0-9._~-]+",r"\1***REDACTED***",value)
def redact_payload(payload:dict)->dict:
    return {key:(redact_text(value) if isinstance(value,str) else value) for key,value in payload.items()}
def serialize_finding(f): return {"id":f.id,"rule_id":f.rule_id,"title":f.title,"category":f.category,"severity":f.severity,"line":f.line,"excerpt":redact_text(f.excerpt),"evidence":redact_text(f.evidence),"status":f.status,"ai_explanation":redact_payload(f.ai_explanation or {})}
def explain(f:Finding):
    fixes={
        "PY-UNSAFE-EVAL":"Parse the expected input format instead of executing it; use ast.literal_eval only for trusted Python literals.",
        "JS-UNSAFE-EVAL":"Replace eval with explicit parsing and an allow-listed operation map.",
        "PY-SQL-CONCAT":"Pass values separately through your database driver's parameterised-query API.",
        "PY-SHELL-TRUE":"Use subprocess.run with a list of fixed arguments and shell=False.",
        "GEN-HARDCODED-SECRET":"Remove the value, rotate it, and load it from a secret manager or runtime environment variable.",
        "JS-DOM-SINK":"Avoid raw HTML, or sanitise with a reviewed HTML sanitiser before rendering.",
        "PY-BARE-EXCEPT":"Catch the expected exception types and re-raise or log unexpected failures.",
        "PY-MUTABLE-DEFAULT":"Use None as the default and construct a new list or dictionary inside the function.",
    }; recommendation=fixes.get(f.rule_id,"Replace the risky pattern with a constrained, explicit API and validate untrusted input.")
    return redact_payload({"finding_id":f.id,"summary":f"{f.title} at line {f.line}.","why_it_matters":f.evidence,"recommendation":recommendation,"safer_pattern":recommendation,"limitations":"This is deterministic guidance; confirm runtime data flow before treating it as exploitable."})
def reviewed_source(source:str, findings:list[Finding], language:str)->str:
    """Applies only deterministic, semantics-conscious edits; ambiguous findings remain review-only."""
    rules={f.rule_id for f in findings}; updated=source
    if language=="python":
        if "PY-UNSAFE-EVAL" in rules:
            if "import ast" not in updated: updated="import ast\n"+updated
            updated=re.sub(r"\beval\s*\(","ast.literal_eval(",updated)
        if "PY-BARE-EXCEPT" in rules: updated=re.sub(r"except\s*:","except Exception as exc:",updated)
        if "GEN-HARDCODED-SECRET" in rules:
            if "import os" not in updated: updated="import os\n"+updated
            updated=re.sub(r"^([A-Za-z_][A-Za-z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY)[A-Za-z0-9_]*)\s*=\s*['\"][^'\"]+['\"]",lambda m:f'{m.group(1)} = os.environ["{m.group(1)}"]',updated,flags=re.M|re.I)
    elif language in {"javascript","typescript"} and "JS-UNSAFE-EVAL" in rules:
        updated=re.sub(r"\beval\s*\(","JSON.parse(",updated)
    return updated

def finding_path(finding:Finding,scan:Scan)->str:
    if " — " in finding.evidence:
        candidate=finding.evidence.split(" — ",1)[0]
        if candidate in source_files(scan): return candidate
    return scan.filename

def build_fix_proposal(finding:Finding,scan:Scan)->dict:
    path=finding_path(finding,scan); content=source_files(scan).get(path,""); lines=content.splitlines()
    before=lines[finding.line-1] if 0<finding.line<=len(lines) else finding.excerpt
    replacement=before; can_apply=True; note="Deterministic source rewrite; inspect the diff before applying."
    if finding.rule_id=="PY-UNSAFE-EVAL": replacement=before.replace("eval(","ast.literal_eval(")
    elif finding.rule_id=="JS-UNSAFE-EVAL": replacement=before.replace("eval(","JSON.parse("); note="Safe only when the input contract is valid JSON; verify behavior after applying."
    elif finding.rule_id=="PY-BARE-EXCEPT": replacement=re.sub(r"except\s*:","except Exception as exc:",before)
    elif finding.rule_id=="GEN-HARDCODED-SECRET":
        match=re.match(r"(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*=",before)
        if match: replacement=f'{match.group(1)}{match.group(2)} = os.environ["{match.group(2)}"]'
        else: can_apply=False;note="The secret-like value must be moved to runtime configuration manually."
    elif finding.rule_id=="PY-MUTABLE-DEFAULT":
        replacement=re.sub(r"=\s*(\[\]|\{\})", "=None",before);note="Initialize a fresh value inside the function before using this parameter."
    else:
        can_apply=False;note="No semantics-safe automatic rewrite is available. Use the recommendation as guided remediation."
    if replacement==before: can_apply=False
    diff="\n".join(difflib.unified_diff([before+"\n"],[replacement+"\n"],fromfile=f"a/{path}",tofile=f"b/{path}",lineterm=""))
    return {"file_path":path,"before_code":redact_text(before),"replacement_code":redact_text(replacement),"raw_before":before,"raw_replacement":replacement,"unified_diff":redact_text(diff),"confidence_note":note,"can_apply":can_apply}

def working_files(scan:Scan,s:Session)->dict[str,str]:
    working=s.scalar(select(WorkingCopy).where(WorkingCopy.scan_id==scan.id))
    return dict(working.files_json) if working else source_files(scan)

def serialize_proposal(proposal:FixProposal)->dict:
    return {"id":proposal.id,"finding_id":proposal.finding_id,"scan_id":proposal.scan_id,"file_path":proposal.file_path,"before_code":redact_text(proposal.before_code),"replacement_code":redact_text(proposal.replacement_code),"unified_diff":redact_text(proposal.unified_diff),"confidence_note":proposal.confidence_note,"can_apply":bool(proposal.can_apply),"status":proposal.status,"created_at":proposal.created_at}

def apply_proposal(files:dict[str,str],proposal:FixProposal,finding:Finding)->dict[str,str]:
    if proposal.file_path not in files: raise ValueError("The target file is no longer present")
    lines=files[proposal.file_path].splitlines(keepends=True); index=finding.line-1
    if index<0 or index>=len(lines): raise ValueError("The target line is no longer present")
    ending="\r\n" if lines[index].endswith("\r\n") else "\n" if lines[index].endswith("\n") else ""
    if lines[index].rstrip("\r\n")!=proposal.before_code: raise ValueError("The working copy changed at this line; regenerate the fix")
    lines[index]=proposal.replacement_code+ending; updated="".join(lines)
    if finding.rule_id=="PY-UNSAFE-EVAL" and "import ast" not in updated: updated="import ast\n"+updated
    if finding.rule_id=="GEN-HARDCODED-SECRET" and proposal.file_path.lower().endswith(".py") and "import os" not in updated: updated="import os\n"+updated
    result=dict(files);result[proposal.file_path]=updated;return result
ALLOWED_SUFFIXES=(".py",".js",".jsx",".ts",".tsx",".java",".json",".yml",".yaml")
def safe_source_path(path:str)->bool:
    return bool(path) and not path.startswith(("/","\\")) and ".." not in path.replace("\\","/").split("/") and path.lower().endswith(ALLOWED_SUFFIXES)
async def run_multi_file_scan(project_id:str, user:User, files:list[tuple[str,str]], input_type:str, s:Session)->dict:
    if not s.scalar(select(Project).where(Project.id==project_id,Project.user_id==user.id)): raise HTTPException(404,"Project not found")
    if not files: raise HTTPException(422,"No supported source files were received")
    packed=json.dumps({name:content for name,content in files})
    scan=Scan(project_id=project_id,user_id=user.id,input_type=input_type,source=packed,filename=f"{len(files)} files",review_mode="Balanced",status="ANALYSING");s.add(scan);s.flush(); total=0
    for filename,source in files:
        language,signals=analyze_source(filename,source,"auto"); scan.language=language
        s.add(ScanFile(scan_id=scan.id,filename=filename))
        for sig in signals:
            f=Finding(scan_id=scan.id,rule_id=sig.rule_id,title=sig.title,category=sig.category,severity=sig.severity,line=sig.line,excerpt=sig.excerpt,evidence=f"{filename} — {sig.message}");s.add(f);s.flush();f.ai_explanation=await grounded_explanation(f);total+=1
    scan.status="COMPLETED";scan.completed_at=utc_now();s.add(AuditLog(user_id=user.id,scan_id=scan.id,action="CODEBASE_SCAN_COMPLETED"));s.commit()
    return {"id":scan.id,"status":scan.status,"files_scanned":len(files),"lines":sum(len(src.splitlines()) for _,src in files),"finding_count":total}
async def grounded_explanation(f:Finding)->dict:
    """OpenRouter is optional and may only rephrase detector-supported evidence."""
    fallback=explain(f); key=os.getenv("OPENROUTER_API_KEY")
    if not key: return fallback
    prompt=("Return JSON only matching: finding_id, summary, why_it_matters, recommendation, safer_pattern, limitations. "
            "Do not invent vulnerabilities, lines, packages, or exploitability. Base every statement only on this detector evidence: "
            +json.dumps(redact_payload({"finding_id":f.id,"title":f.title,"rule":f.rule_id,"line":f.line,"excerpt":f.excerpt,"evidence":f.evidence})))
    payload={"model":os.getenv("OPENROUTER_MODEL","openrouter/free"),"messages":[{"role":"system","content":"You are a careful code review explainer. You do not create findings."},{"role":"user","content":prompt}],"response_format":{"type":"json_object"}}
    for _ in range(2):
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                response=await client.post(os.getenv("OPENROUTER_BASE_URL","https://openrouter.ai/api/v1").rstrip("/")+"/chat/completions",headers={"Authorization":f"Bearer {key}","Content-Type":"application/json"},json=payload)
                response.raise_for_status(); content=response.json()["choices"][0]["message"]["content"]
                parsed=GroundedExplanation.model_validate_json(content)
                if parsed.finding_id==f.id: return parsed.model_dump()
        except Exception: pass
    return fallback

async def grounded_fix(finding:Finding,built:dict)->tuple[dict,str]:
    """Optionally asks OpenRouter for a replacement, while preserving deterministic apply boundaries."""
    key=os.getenv("OPENROUTER_API_KEY")
    if not key: return built,"deterministic"
    prompt=("Return JSON only with finding_id, file_path, replacement_code, confidence_note, limitations. "
            "Suggest the smallest replacement for the supplied source line. Do not invent other files, dependencies, findings, or runtime behavior. "
            +json.dumps(redact_payload({"finding_id":finding.id,"file_path":built["file_path"],"rule_id":finding.rule_id,"evidence":finding.evidence,"before_code":built["raw_before"],"deterministic_guidance":explain(finding)["recommendation"]})))
    payload={"model":os.getenv("OPENROUTER_MODEL","openrouter/free"),"messages":[{"role":"system","content":"You propose minimal code fixes grounded only in supplied static evidence. A developer must approve every change."},{"role":"user","content":prompt}],"response_format":{"type":"json_object"}}
    for _ in range(2):
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                response=await client.post(os.getenv("OPENROUTER_BASE_URL","https://openrouter.ai/api/v1").rstrip("/")+"/chat/completions",headers={"Authorization":f"Bearer {key}","Content-Type":"application/json"},json=payload)
                response.raise_for_status();parsed=GroundedFix.model_validate_json(response.json()["choices"][0]["message"]["content"])
                if parsed.finding_id!=finding.id or parsed.file_path!=built["file_path"]: continue
                updated=dict(built);updated["raw_replacement"]=parsed.replacement_code;updated["replacement_code"]=redact_text(parsed.replacement_code);updated["confidence_note"]=f"{parsed.confidence_note} Limitation: {parsed.limitations}"
                updated["unified_diff"]=redact_text("\n".join(difflib.unified_diff([built["raw_before"]+"\n"],[parsed.replacement_code+"\n"],fromfile=f'a/{built["file_path"]}',tofile=f'b/{built["file_path"]}',lineterm="")))
                return updated,"openrouter"
        except Exception: pass
    return built,"deterministic_fallback"

def source_files(scan:Scan)->dict[str,str]:
    if scan.input_type in {"folder","project"}:
        try:
            decoded=json.loads(scan.source)
            if isinstance(decoded,dict): return {str(k):str(v) for k,v in decoded.items()}
        except json.JSONDecodeError: pass
    return {scan.filename:scan.source}

def record_event(s:Session,scan:Scan,stage:str,event_status:str,message:str,metrics:dict|None=None)->None:
    sequence=(s.scalar(select(func.max(ScanEvent.sequence)).where(ScanEvent.scan_id==scan.id)) or 0)+1
    s.add(ScanEvent(scan_id=scan.id,user_id=scan.user_id,sequence=sequence,stage=stage,status=event_status,message=message,metrics=metrics or {}))
    s.commit()

async def process_queued_scan(scan_id:str)->None:
    """Runs deterministic analysis outside the request and records only completed stages."""
    with SessionLocal() as s:
        scan=s.get(Scan,scan_id)
        if not scan: return
        try:
            scan.status="VALIDATING"; record_event(s,scan,"VALIDATE","RUNNING","Validating submitted text and file boundaries")
            files=source_files(scan)
            line_count=sum(len(content.splitlines()) for content in files.values())
            record_event(s,scan,"VALIDATE","PASSED","Input accepted",{"files":len(files),"lines":line_count})
            scan.status="PARSING"; record_event(s,scan,"PARSE","RUNNING","Detecting languages and parsing supported syntax")
            analysed:list[tuple[str,str,list]]=[]
            for path,content in files.items():
                language,signals=analyze_source(path,content,"auto")
                analysed.append((path,language,signals))
            languages=sorted({language for _,language,_ in analysed})
            scan.language=languages[0] if len(languages)==1 else "mixed"
            record_event(s,scan,"PARSE","PASSED","Syntax validators completed",{"languages":languages})
            scan.status="STATIC_ANALYSIS"; record_event(s,scan,"STATIC_RULES","RUNNING","Running security, quality, complexity and reliability rules")
            existing=list(s.scalars(select(Finding).where(Finding.scan_id==scan.id)))
            for finding in existing: s.delete(finding)
            for path,_,signals in analysed:
                for signal in signals:
                    s.add(Finding(scan_id=scan.id,rule_id=signal.rule_id,title=signal.title,category=signal.category,severity=signal.severity,line=signal.line,excerpt=signal.excerpt,evidence=(f"{path} — {signal.message}" if len(files)>1 else signal.message)))
            s.commit()
            findings_for_scan=list(s.scalars(select(Finding).where(Finding.scan_id==scan.id)))
            record_event(s,scan,"STATIC_RULES","PASSED","Deterministic rule engine completed",{"files_checked":len(files),"signals":len(findings_for_scan)})
            scan.status="RANKING"; record_event(s,scan,"RANK","RUNNING","Ranking evidence by severity and confidence")
            record_event(s,scan,"RANK","PASSED","Finding priorities prepared",{"findings":len(findings_for_scan)})
            scan.status="AI_CONTEXT"; record_event(s,scan,"AI_CONTEXT","RUNNING","Generating explanations grounded in detector evidence")
            for finding in findings_for_scan:
                finding.ai_explanation=await grounded_explanation(finding)
            s.commit()
            record_event(s,scan,"AI_CONTEXT","PASSED","Evidence explanations prepared",{"explained":len(findings_for_scan)})
            scan.status="COMPLETED";scan.completed_at=utc_now();s.add(AuditLog(user_id=scan.user_id,scan_id=scan.id,action="SCAN_COMPLETED"));s.commit()
            record_event(s,scan,"COMPLETE","PASSED","Review workspace is ready",{"files":len(files),"lines":line_count,"findings":len(findings_for_scan)})
        except Exception as exc:
            s.rollback();scan=s.get(Scan,scan_id)
            if scan:
                scan.status="FAILED"
                record_event(s,scan,"FAILED","FAILED",f"Analysis stopped: {type(exc).__name__}")
@app.get("/health")
def health(): return {"status":"healthy"}
@app.post("/api/v1/auth/register")
def register(data:Register,s:Session=Depends(db)):
    if s.scalar(select(User).where(User.email==data.email)): raise HTTPException(409,"Email already registered")
    u=User(email=data.email,name=data.name,password_hash=hash_password(data.password)); s.add(u);s.commit(); return {"access_token":token_for(u),"token_type":"bearer","user":{"id":u.id,"email":u.email,"name":u.name}}
@app.post("/api/v1/auth/login")
def login(data:Login,s:Session=Depends(db)):
    u=s.scalar(select(User).where(User.email==data.email))
    if not u or not verify_password(data.password,u.password_hash): raise HTTPException(401,"Incorrect email or password")
    return {"access_token":token_for(u),"token_type":"bearer","user":{"id":u.id,"email":u.email,"name":u.name}}
@app.get("/api/v1/auth/me")
def current(u:User=Depends(me)): return {"id":u.id,"email":u.email,"name":u.name}
@app.get("/api/v1/projects")
def projects(u:User=Depends(me),s:Session=Depends(db)): return [dict(id=p.id,name=p.name,language=p.language,framework=p.framework,security_profile=p.security_profile,created_at=p.created_at) for p in s.scalars(select(Project).where(Project.user_id==u.id).order_by(Project.created_at.desc()))]
@app.post("/api/v1/projects")
def create_project(data:ProjectIn,u:User=Depends(me),s:Session=Depends(db)):
    p=Project(user_id=u.id,**data.model_dump());s.add(p);s.commit();return {"id":p.id,"name":p.name,"language":p.language}
@app.get("/api/v1/projects/{project_id}")
def get_project(project_id:str,u:User=Depends(me),s:Session=Depends(db)):
    p=s.scalar(select(Project).where(Project.id==project_id,Project.user_id==u.id))
    if not p: raise HTTPException(404,"Project not found")
    return {"id":p.id,"name":p.name,"language":p.language,"framework":p.framework,"repository_url":p.repository_url,"description":p.description,"security_profile":p.security_profile}
@app.patch("/api/v1/projects/{project_id}")
def update_project(project_id:str,data:ProjectIn,u:User=Depends(me),s:Session=Depends(db)):
    p=s.scalar(select(Project).where(Project.id==project_id,Project.user_id==u.id))
    if not p: raise HTTPException(404,"Project not found")
    for k,v in data.model_dump().items(): setattr(p,k,v)
    s.commit(); return {"id":p.id,"name":p.name}
@app.delete("/api/v1/projects/{project_id}")
def delete_project(project_id:str,u:User=Depends(me),s:Session=Depends(db)):
    p=s.scalar(select(Project).where(Project.id==project_id,Project.user_id==u.id))
    if not p: raise HTTPException(404,"Project not found")
    s.delete(p);s.commit();return {"deleted":True}
@app.post("/api/v1/scans")
async def scan(data:ScanIn,u:User=Depends(me),s:Session=Depends(db)):
    if not s.scalar(select(Project).where(Project.id==data.project_id,Project.user_id==u.id)): raise HTTPException(404,"Project not found")
    safe_name=os.path.basename(data.filename)
    if safe_name!=data.filename or not safe_name.endswith((".py",".js",".jsx",".ts",".tsx",".java",".diff",".patch")): raise HTTPException(422,"Unsupported or unsafe filename")
    scan=Scan(project_id=data.project_id,user_id=u.id,input_type=data.input_type,source=data.source,filename=safe_name,review_mode=data.review_mode,status="ANALYSING");s.add(scan);s.flush()
    language,signals=analyze_source(safe_name,data.source,data.language,data.checks);scan.language=language
    for sig in signals:
        f=Finding(scan_id=scan.id,rule_id=sig.rule_id,title=sig.title,category=sig.category,severity=sig.severity,line=sig.line,excerpt=sig.excerpt,evidence=sig.message);s.add(f);s.flush();f.ai_explanation=await grounded_explanation(f)
    scan.status="COMPLETED";scan.completed_at=utc_now();s.add(AuditLog(user_id=u.id,scan_id=scan.id,action="SCAN_COMPLETED"));s.commit()
    return {"id":scan.id,"status":scan.status,"finding_count":len(signals),"language":language}
@app.post("/api/v1/scans/start",status_code=202)
async def start_scan(data:ScanIn,background:BackgroundTasks,u:User=Depends(me),s:Session=Depends(db)):
    if not s.scalar(select(Project).where(Project.id==data.project_id,Project.user_id==u.id)): raise HTTPException(404,"Project not found")
    safe_name=os.path.basename(data.filename)
    if safe_name!=data.filename: raise HTTPException(422,"Unsafe filename")
    if data.input_type!="diff":
        try: decoded=decode_source(safe_name,data.source.encode("utf-8"))
        except ValueError as exc: raise HTTPException(422,str(exc))
        if not decoded: raise HTTPException(422,"Unsupported source file")
    elif not safe_name.lower().endswith((".diff",".patch")): raise HTTPException(422,"Diff reviews require a .diff or .patch filename")
    queued=Scan(project_id=data.project_id,user_id=u.id,input_type=data.input_type,source=data.source,filename=safe_name,review_mode=data.review_mode,status="RECEIVED")
    s.add(queued);s.flush();record_event(s,queued,"SOURCE","PASSED","Source received",{"files":1,"bytes":len(data.source.encode("utf-8"))})
    background.add_task(process_queued_scan,queued.id)
    return {"id":queued.id,"status":queued.status}
@app.post("/api/v1/scans/{scan_id}/run")
def rerun(scan_id:str,u:User=Depends(me),s:Session=Depends(db)):
    scan=s.scalar(select(Scan).where(Scan.id==scan_id,Scan.user_id==u.id))
    if not scan: raise HTTPException(404,"Scan not found")
    return {"id":scan.id,"status":scan.status,"message":"Scans are run atomically when created in this release."}
@app.post("/api/v1/import/files")
async def import_files(project_id:str=Form(...),files:list[UploadFile]=File(...),u:User=Depends(me),s:Session=Depends(db)):
    if len(files)>100: raise HTTPException(422,"Limit imports to 100 files at a time")
    received=[]
    for upload in files:
        name=(upload.filename or "").replace("\\","/")
        if not safe_source_path(name): continue
        body=await upload.read()
        if len(body)>500_000: raise HTTPException(422,f"{name} exceeds the 500 KB per-file limit")
        try: received.append((name,body.decode("utf-8")))
        except UnicodeDecodeError: continue
    return await run_multi_file_scan(project_id,u,received,"folder",s)
@app.post("/api/v1/import/project")
async def import_project(project_id:str=Form(...),uploads:list[UploadFile]=File(...),u:User=Depends(me),s:Session=Depends(db)):
    if len(uploads)>MAX_FILES: raise HTTPException(422,"Limit imports to 250 uploaded items")
    sources:dict[str,str]={}
    for upload in uploads:
        name=(upload.filename or "").replace("\\","/")
        body=await upload.read()
        if name.lower().endswith(".zip"):
            try: extracted=extract_zip(body)
            except ValueError as exc: raise HTTPException(422,str(exc))
            for item in extracted: sources[item.path]=item.content
        else:
            item=decode_source(name,body)
            if item: sources[item.path]=item.content
    return await run_multi_file_scan(project_id,u,list(sources.items()),"project",s)
@app.post("/api/v1/import/project/start",status_code=202)
async def start_project_scan(background:BackgroundTasks,project_id:str=Form(...),uploads:list[UploadFile]=File(...),u:User=Depends(me),s:Session=Depends(db)):
    if not s.scalar(select(Project).where(Project.id==project_id,Project.user_id==u.id)): raise HTTPException(404,"Project not found")
    if len(uploads)>MAX_FILES: raise HTTPException(422,"Limit imports to 250 uploaded items")
    sources:dict[str,str]={}
    for upload in uploads:
        name=(upload.filename or "").replace("\\","/"); body=await upload.read()
        try:
            if name.lower().endswith(".zip"):
                for item in extract_zip(body): sources[item.path]=item.content
            else:
                item=decode_source(name,body)
                if item: sources[item.path]=item.content
        except ValueError as exc: raise HTTPException(422,str(exc))
    if not sources: raise HTTPException(422,"No supported UTF-8 source files were found")
    queued=Scan(project_id=project_id,user_id=u.id,input_type="project",source=json.dumps(sources),filename=f"{len(sources)} files",review_mode="Balanced",status="RECEIVED")
    s.add(queued);s.flush()
    for path in sources: s.add(ScanFile(scan_id=queued.id,filename=path))
    record_event(s,queued,"SOURCE","PASSED","Project source received",{"files":len(sources),"bytes":sum(len(v.encode("utf-8")) for v in sources.values())})
    background.add_task(process_queued_scan,queued.id)
    return {"id":queued.id,"status":queued.status,"files":len(sources)}
@app.get("/api/v1/scans")
def scans(u:User=Depends(me),s:Session=Depends(db)): return [{"id":x.id,"project_id":x.project_id,"filename":x.filename,"language":x.language,"input_type":x.input_type,"status":x.status,"created_at":x.created_at} for x in s.scalars(select(Scan).where(Scan.user_id==u.id).order_by(Scan.created_at.desc()))]
@app.get("/api/v1/scans/{scan_id}/events")
def scan_events(scan_id:str,u:User=Depends(me),s:Session=Depends(db)):
    scan=s.scalar(select(Scan).where(Scan.id==scan_id,Scan.user_id==u.id))
    if not scan: raise HTTPException(404,"Scan not found")
    return [{"sequence":e.sequence,"stage":e.stage,"status":e.status,"message":e.message,"metrics":e.metrics,"created_at":e.created_at} for e in s.scalars(select(ScanEvent).where(ScanEvent.scan_id==scan_id).order_by(ScanEvent.sequence))]
@app.get("/api/v1/scans/{scan_id}/events/stream")
async def stream_scan_events(scan_id:str,u:User=Depends(me),s:Session=Depends(db)):
    if not s.scalar(select(Scan).where(Scan.id==scan_id,Scan.user_id==u.id)): raise HTTPException(404,"Scan not found")
    async def generate():
        last=0
        while True:
            with SessionLocal() as event_session:
                scan=event_session.get(Scan,scan_id)
                events=list(event_session.scalars(select(ScanEvent).where(ScanEvent.scan_id==scan_id,ScanEvent.sequence>last).order_by(ScanEvent.sequence)))
                for event in events:
                    last=event.sequence
                    payload={"sequence":event.sequence,"stage":event.stage,"status":event.status,"message":event.message,"metrics":event.metrics,"created_at":event.created_at.isoformat()}
                    yield f"event: stage\ndata: {json.dumps(payload)}\n\n"
                if scan and scan.status in {"COMPLETED","FAILED"} and not events: break
            await asyncio.sleep(.25)
    return StreamingResponse(generate(),media_type="text/event-stream",headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})
@app.get("/api/v1/scans/{scan_id}")
def one_scan(scan_id:str,u:User=Depends(me),s:Session=Depends(db)):
    x=s.scalar(select(Scan).where(Scan.id==scan_id,Scan.user_id==u.id))
    if not x: raise HTTPException(404,"Scan not found")
    files=working_files(x,s)
    first_name,first_source=next(iter(files.items()))
    return {"id":x.id,"status":x.status,"source":first_source,"filename":first_name,"files":[{"path":p,"lines":len(c.splitlines()),"content":c} for p,c in files.items()],"total_lines":sum(len(c.splitlines()) for c in files.values()),"language":x.language,"findings":[serialize_finding(f) for f in s.scalars(select(Finding).where(Finding.scan_id==x.id))]}
@app.get("/api/v1/scans/{scan_id}/reviewed-file")
def download_reviewed_file(scan_id:str,u:User=Depends(me),s:Session=Depends(db)):
    scan=s.scalar(select(Scan).where(Scan.id==scan_id,Scan.user_id==u.id))
    if not scan: raise HTTPException(404,"Scan not found")
    files=working_files(scan,s)
    if scan.input_type in {"folder","project"}:
        output=io.BytesIO()
        with zipfile.ZipFile(output,"w",zipfile.ZIP_DEFLATED) as archive:
            for path,content in files.items(): archive.writestr(path,content)
        output.seek(0)
        return StreamingResponse(output,media_type="application/zip",headers={"Content-Disposition":'attachment; filename="codereview_fixed.zip"'})
    name="reviewed_"+scan.filename.replace("/","_")
    return PlainTextResponse(next(iter(files.values())),headers={"Content-Disposition":f'attachment; filename="{name}"'})
@app.get("/api/v1/scans/{scan_id}/status")
def scan_status(scan_id:str,u:User=Depends(me),s:Session=Depends(db)):
    x=s.scalar(select(Scan).where(Scan.id==scan_id,Scan.user_id==u.id))
    if not x: raise HTTPException(404,"Scan not found")
    latest=s.scalar(select(ScanEvent).where(ScanEvent.scan_id==x.id).order_by(ScanEvent.sequence.desc()))
    return {"id":x.id,"status":x.status,"stage":latest.stage if latest else "SOURCE","message":latest.message if latest else "Waiting to start","metrics":latest.metrics if latest else {}}
@app.get("/api/v1/scans/{scan_id}/findings")
def scan_findings(scan_id:str,u:User=Depends(me),s:Session=Depends(db)): return one_scan(scan_id,u,s)["findings"]
@app.get("/api/v1/findings")
def findings(u:User=Depends(me),s:Session=Depends(db)):
    return [serialize_finding(f) for f in s.scalars(select(Finding).join(Scan).where(Scan.user_id==u.id))]
@app.post("/api/v1/findings/{finding_id}/generate-fix")
async def generate_fix(finding_id:str,data:FixRequest,u:User=Depends(me),s:Session=Depends(db)):
    finding=s.scalar(select(Finding).join(Scan).where(Finding.id==finding_id,Scan.user_id==u.id))
    if not finding: raise HTTPException(404,"Finding not found")
    scan=s.get(Scan,finding.scan_id); built=build_fix_proposal(finding,scan);provider="deterministic"
    if data.use_ai: built,provider=await grounded_fix(finding,built)
    proposal=FixProposal(finding_id=finding.id,scan_id=scan.id,user_id=u.id,file_path=built["file_path"],before_code=built["raw_before"],replacement_code=built["raw_replacement"],unified_diff=built["unified_diff"],confidence_note=built["confidence_note"],can_apply=int(built["can_apply"]))
    s.add(proposal);s.add(AuditLog(user_id=u.id,scan_id=scan.id,finding_id=finding.id,action="FIX_PROPOSED",rationale=built["confidence_note"]));s.commit()
    payload=serialize_proposal(proposal);payload["provider"]=provider;payload["ai_requested"]=data.use_ai
    return payload
@app.get("/api/v1/scans/{scan_id}/fixes")
def scan_fixes(scan_id:str,u:User=Depends(me),s:Session=Depends(db)):
    if not s.scalar(select(Scan).where(Scan.id==scan_id,Scan.user_id==u.id)): raise HTTPException(404,"Scan not found")
    return [serialize_proposal(p) for p in s.scalars(select(FixProposal).where(FixProposal.scan_id==scan_id).order_by(FixProposal.created_at.desc()))]
@app.post("/api/v1/fixes/{proposal_id}/apply")
def apply_fix(proposal_id:str,u:User=Depends(me),s:Session=Depends(db)):
    proposal=s.scalar(select(FixProposal).where(FixProposal.id==proposal_id,FixProposal.user_id==u.id))
    if not proposal: raise HTTPException(404,"Fix proposal not found")
    if not proposal.can_apply: raise HTTPException(409,"This recommendation requires a manual code change")
    if proposal.status=="APPLIED": return serialize_proposal(proposal)
    scan=s.get(Scan,proposal.scan_id);finding=s.get(Finding,proposal.finding_id)
    working=s.scalar(select(WorkingCopy).where(WorkingCopy.scan_id==scan.id));files=dict(working.files_json) if working else source_files(scan)
    try: files=apply_proposal(files,proposal,finding)
    except ValueError as exc: raise HTTPException(409,str(exc))
    if working: working.files_json=files;working.updated_at=utc_now()
    else: s.add(WorkingCopy(scan_id=scan.id,user_id=u.id,files_json=files))
    proposal.status="APPLIED";finding.status="REMEDIATION_APPLIED";s.add(AuditLog(user_id=u.id,scan_id=scan.id,finding_id=finding.id,action="FIX_APPLIED",rationale=proposal.confidence_note));s.commit()
    return serialize_proposal(proposal)
@app.post("/api/v1/scans/{scan_id}/verify")
def verify_working_copy(scan_id:str,u:User=Depends(me),s:Session=Depends(db)):
    scan=s.scalar(select(Scan).where(Scan.id==scan_id,Scan.user_id==u.id))
    if not scan: raise HTTPException(404,"Scan not found")
    files=working_files(scan,s);remaining=[]
    for path,content in files.items():
        language,signals=analyze_source(path,content,"auto")
        remaining.extend({"file_path":path,"rule_id":signal.rule_id,"title":signal.title,"severity":signal.severity,"line":signal.line,"category":signal.category} for signal in signals)
    applied=list(s.scalars(select(FixProposal).where(FixProposal.scan_id==scan.id,FixProposal.status=="APPLIED")))
    unresolved={(item["file_path"],item["rule_id"]) for item in remaining}
    for proposal in applied:
        finding=s.get(Finding,proposal.finding_id)
        if (proposal.file_path,finding.rule_id) not in unresolved: proposal.status="VERIFIED";finding.status="REMEDIATED"
    s.add(AuditLog(user_id=u.id,scan_id=scan.id,action="WORKING_COPY_VERIFIED",rationale=f"{len(remaining)} findings remain after deterministic validation"));s.commit()
    return {"status":"PASSED" if not remaining else "FINDINGS_REMAIN","files_checked":len(files),"remaining_count":len(remaining),"remaining":remaining,"tests":{"executed":False,"label":"Static validators only","reason":"Submitted code is never executed outside an isolated sandbox."}}
@app.post("/api/v1/findings/{finding_id}/{action}")
def decision(finding_id:str,action:Literal["accept","dismiss","escalate","remediation"],data:Decision,u:User=Depends(me),s:Session=Depends(db)):
    f=s.scalar(select(Finding).join(Scan).where(Finding.id==finding_id,Scan.user_id==u.id))
    if not f: raise HTTPException(404,"Finding not found")
    f.status={"accept":"ACCEPTED","dismiss":"DISMISSED","escalate":"ESCALATED","remediation":"REMEDIATION_PLANNED"}[action];s.add(AuditLog(user_id=u.id,finding_id=f.id,scan_id=f.scan_id,action=action.upper(),rationale=data.rationale));s.commit();return serialize_finding(f)
@app.get("/api/v1/dashboard")
def dashboard(u:User=Depends(me),s:Session=Depends(db)):
    scans_count=s.scalar(select(func.count()).select_from(Scan).where(Scan.user_id==u.id)) or 0; fs=list(s.scalars(select(Finding).join(Scan).where(Scan.user_id==u.id))); projects_count=s.scalar(select(func.count()).select_from(Project).where(Project.user_id==u.id)) or 0
    return {"scans":scans_count,"projects":projects_count,"open":sum(f.status=="OPEN" for f in fs),"high_risk":sum(f.severity in {"high","critical"} and f.status=="OPEN" for f in fs),"reviewed":sum(f.status!="OPEN" for f in fs),"severity":{x:sum(f.severity==x for f in fs) for x in ["critical","high","medium","low","info"]},"recent":[{"action":x.action,"created_at":x.created_at,"rationale":x.rationale} for x in s.scalars(select(AuditLog).where(AuditLog.user_id==u.id).order_by(AuditLog.created_at.desc()).limit(8))]}
@app.get("/api/v1/audit")
def audit(u:User=Depends(me),s:Session=Depends(db)): return [{"id":x.id,"action":x.action,"scan_id":x.scan_id,"finding_id":x.finding_id,"rationale":x.rationale,"created_at":x.created_at} for x in s.scalars(select(AuditLog).where(AuditLog.user_id==u.id).order_by(AuditLog.created_at.desc()))]
@app.post("/api/v1/ai/explain-finding")
def ai_explain(finding_id:str,u:User=Depends(me),s:Session=Depends(db)):
    f=s.scalar(select(Finding).join(Scan).where(Finding.id==finding_id,Scan.user_id==u.id))
    if not f: raise HTTPException(404,"Finding not found")
    return f.ai_explanation or explain(f)
@app.post("/api/v1/ai/summarize-scan")
def summarize_scan(scan_id:str,u:User=Depends(me),s:Session=Depends(db)):
    x=s.scalar(select(Scan).where(Scan.id==scan_id,Scan.user_id==u.id))
    if not x: raise HTTPException(404,"Scan not found")
    fs=list(s.scalars(select(Finding).where(Finding.scan_id==scan_id)))
    return {"summary":f"{len(fs)} evidence-backed findings in {x.filename}.","priority":[f.id for f in fs if f.severity in {"critical","high"}],"limitations":"Only enabled deterministic rules and submitted source were considered."}
class Ask(BaseModel): scan_id:str; question:str=Field(min_length=1,max_length=2000)
@app.post("/api/v1/ai/ask")
def ask(data:Ask,u:User=Depends(me),s:Session=Depends(db)):
    x=s.scalar(select(Scan).where(Scan.id==data.scan_id,Scan.user_id==u.id))
    if not x: raise HTTPException(404,"Scan not found")
    fs=list(s.scalars(select(Finding).where(Finding.scan_id==x.id)))
    return {"summary":"This response is limited to static evidence from the current scan.","evidence":[{"title":f.title,"line":f.line,"rule_id":f.rule_id} for f in fs],"recommended_approach":"Address high-severity findings first and record a rationale for each decision.","limitations":"No runtime execution, dependency resolution, or unsubmitted code was analysed."}
