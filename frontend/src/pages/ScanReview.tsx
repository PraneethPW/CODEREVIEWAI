import {useEffect, useMemo, useRef, useState} from 'react';
import Editor from '@monaco-editor/react';
import {AnimatePresence, motion} from 'framer-motion';
import {AlertTriangle, ArrowRight, Check, CheckCircle2, ChevronRight, Download, FileCode2, Files, RotateCw, Sparkles, WandSparkles, X} from 'lucide-react';
import {api, downloadArtifact} from '../lib/api';
import {Loading, PageHeader, Shell} from '../components/Shell';
import type {Finding, FixProposal, Scan} from '../types';
import {useParams} from 'react-router-dom';

function pathFor(finding: Finding, scan: Scan) {
  const candidate = finding.evidence.split(' — ')[0];
  return scan.files.some(file=>file.path===candidate) ? candidate : scan.filename;
}

export function ScanReview() {
  const {id} = useParams();
  const editorRef = useRef<any>(null);
  const [scan, setScan] = useState<Scan>();
  const [active, setActive] = useState<Finding>();
  const [filePath, setFilePath] = useState('');
  const [filter, setFilter] = useState('all');
  const [mobileTab, setMobileTab] = useState<'findings'|'code'|'review'>('findings');
  const [rationale, setRationale] = useState('');
  const [proposal, setProposal] = useState<FixProposal>();
  const [verification, setVerification] = useState<any>();
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');

  const load = async (keepFinding?: string) => {
    const response = await api<Scan>(`/scans/${id}`); setScan(response);
    const next = response.findings.find(item=>item.id===keepFinding) || response.findings[0];
    setActive(next); setFilePath(next ? pathFor(next,response) : response.files[0]?.path||'');
  };
  useEffect(()=>{load();},[id]);
  useEffect(()=>{
    if (!active || !editorRef.current) return;
    editorRef.current.revealLineInCenter(active.line);
    const decorations = editorRef.current.deltaDecorations([], [{range:{startLineNumber:active.line,startColumn:1,endLineNumber:active.line,endColumn:999},options:{isWholeLine:true,className:'finding-line',glyphMarginClassName:'finding-glyph'}}]);
    return ()=>editorRef.current?.deltaDecorations(decorations,[]);
  },[active,filePath]);
  const selectFinding = (finding:Finding) => {setActive(finding);if(scan)setFilePath(pathFor(finding,scan));setProposal(undefined);setVerification(undefined);setRationale('');setError('');setMobileTab('review');};
  const generate = async () => {if(!active)return;setBusy('generate');setError('');try{setProposal(await api(`/findings/${active.id}/generate-fix`,{method:'POST',body:JSON.stringify({use_ai:true})}));}catch(caught:any){setError(caught.message);}finally{setBusy('');}};
  const apply = async () => {if(!proposal||!active)return;setBusy('apply');setError('');try{const updated=await api<FixProposal>(`/fixes/${proposal.id}/apply`,{method:'POST'});setProposal(updated);await load(active.id);}catch(caught:any){setError(caught.message);}finally{setBusy('');}};
  const verify = async () => {setBusy('verify');setError('');try{const result:any=await api(`/scans/${id}/verify`,{method:'POST'});setVerification(result);if(proposal&&active&&!result.remaining.some((item:any)=>item.file_path===proposal.file_path&&item.rule_id===active.rule_id))setProposal({...proposal,status:'VERIFIED'});await load(active?.id);}catch(caught:any){setError(caught.message);}finally{setBusy('');}};
  const decide = async (action:string) => {if(!active||!rationale.trim())return setError('Add a developer rationale before recording a decision.');setBusy(action);try{const updated=await api<Finding>(`/findings/${active.id}/${action}`,{method:'POST',body:JSON.stringify({rationale})});setActive(updated);setScan(current=>current?{...current,findings:current.findings.map(item=>item.id===updated.id?updated:item)}:current);setRationale('');}catch(caught:any){setError(caught.message);}finally{setBusy('');}};
  const visible = useMemo(()=>scan?.findings.filter(item=>filter==='all'||item.severity===filter)||[],[scan,filter]);
  const currentFile = scan?.files.find(file=>file.path===filePath) || scan?.files[0];
  const counts = useMemo(()=>Object.fromEntries(['critical','high','medium','low'].map(severity=>[severity,scan?.findings.filter(item=>item.severity===severity).length||0])),[scan]);
  if (!scan) return <Shell><Loading label="OPENING EVIDENCE WORKSPACE"/></Shell>;
  return <Shell><PageHeader kicker={`REVIEW WORKSPACE / ${scan.status}`} title={scan.filename}><div className="workspace-actions"><button onClick={verify} disabled={!!busy}><RotateCw/> {busy==='verify'?'VERIFYING…':'VERIFY WORKING COPY'}</button><button onClick={()=>downloadArtifact(scan.id)}><Download/> DOWNLOAD FIXED</button></div></PageHeader>
    <div className="workspace-telemetry"><span><small>FILES</small><b>{scan.files.length}</b></span><span><small>LINES</small><b>{scan.total_lines}</b></span><span><small>FINDINGS</small><b>{scan.findings.length}</b></span><span><small>CRITICAL</small><b className="critical-text">{counts.critical}</b></span><span><small>HIGH</small><b className="high-text">{counts.high}</b></span><span><small>LANGUAGE</small><b>{scan.language}</b></span><span><small>EXECUTION</small><b className="cyan-text">OFF</b></span></div>
    <div className="review-workspace-v2">
      <div className="workspace-mobile-tabs" role="tablist" aria-label="Review workspace views">{(['findings','code','review'] as const).map(tab=><button aria-selected={mobileTab===tab} className={mobileTab===tab?'active':''} onClick={()=>setMobileTab(tab)} key={tab}>{tab}</button>)}</div>
      <aside className={`finding-navigator ${mobileTab==='findings'?'mobile-active':''}`}><div className="navigator-head"><span><small>REV/FINDINGS</small><b>Evidence navigator</b></span><em>{scan.findings.length}</em></div><div className="severity-filter">{['all','critical','high','medium','low'].map(item=><button className={filter===item?'active':''} onClick={()=>setFilter(item)} key={item}>{item}<b>{item==='all'?scan.findings.length:counts[item]}</b></button>)}</div><div className="file-tree"><small>SOURCE TREE</small>{scan.files.map(file=><button className={filePath===file.path?'active':''} onClick={()=>{setFilePath(file.path);setMobileTab('code');}} key={file.path}><FileCode2/><span>{file.path}</span><small>{file.lines}L</small></button>)}</div><div className="finding-stack"><small>DETECTED SIGNALS</small>{visible.map(finding=><button className={active?.id===finding.id?'selected':''} onClick={()=>selectFinding(finding)} key={finding.id}><i className={`severity-dot ${finding.severity}`}/><span><b>{finding.title}</b><small>{finding.rule_id} · line {finding.line}</small></span><em>{finding.status}</em></button>)}{!visible.length&&<p>No findings match this severity filter.</p>}</div></aside>
      <section className={`code-evidence ${mobileTab==='code'?'mobile-active':''}`}><div className="code-toolbar"><span><Files/> {filePath}</span><div>LN {active?.line||1} · READ ONLY · <b>{scan.language.toUpperCase()}</b></div></div><Editor onMount={editor=>editorRef.current=editor} height="680px" language={filePath.endsWith('.py')?'python':filePath.endsWith('.java')?'java':'typescript'} value={currentFile?.content||''} theme="vs-dark" options={{readOnly:true,minimap:{enabled:true},glyphMargin:true,fontSize:14,lineNumbersMinChars:3,padding:{top:14},scrollBeyondLastLine:false}}/><div className="code-status"><span>UTF-8</span><span>STATIC EVIDENCE</span><span>{currentFile?.lines||0} LINES</span><b>WORKING COPY</b></div></section>
      <aside className={`evidence-inspector ${mobileTab==='review'?'mobile-active':''}`}>{active ? <><div className="inspector-head"><span className={`severity-badge ${active.severity}`}>{active.severity}</span><small>{active.rule_id}</small><em>{active.status}</em></div><h3>{active.title}</h3><div className="evidence-source"><small>SOURCE EVIDENCE / LINE {active.line}</small><code>{active.excerpt}</code></div><div className="evidence-block"><small>RULE EVIDENCE</small><p>{active.evidence}</p></div><div className="ai-block"><div><Sparkles/><small>AI / GROUNDED CONTEXT</small><span>EXPLAINS ONLY</span></div><h4>{active.ai_explanation?.summary||'Explanation unavailable'}</h4><p>{active.ai_explanation?.why_it_matters}</p><b>RECOMMENDED APPROACH</b><p>{active.ai_explanation?.recommendation}</p><small>{active.ai_explanation?.limitations}</small></div><button className="fix-launch" onClick={generate} disabled={!!busy}><WandSparkles/> {busy==='generate'?'BUILDING PROPOSAL…':'GENERATE SAFE FIX'} <ArrowRight/></button><label className="rationale"><small>DEVELOPER RATIONALE</small><textarea value={rationale} onChange={e=>setRationale(e.target.value)} placeholder="Record why you accept, dismiss, or escalate this evidence."/></label><div className="decision-grid"><button onClick={()=>decide('accept')}><Check/> Accept</button><button onClick={()=>decide('dismiss')}><X/> Dismiss</button><button onClick={()=>decide('escalate')}><AlertTriangle/> Escalate</button></div>{error&&<p className="error">{error}</p>}</> : <div className="no-finding"><CheckCircle2/><h3>No supported findings</h3><p>The active static rule set did not produce evidence for this input.</p></div>}</aside>
    </div>
    <AnimatePresence>{proposal&&<motion.div className="fix-drawer" initial={{y:'100%'}} animate={{y:0}} exit={{y:'100%'}}><div className="fix-drawer-head"><span><WandSparkles/><small>FIX PROPOSAL / {proposal.provider||'RULE ENGINE'}</small><b>{proposal.file_path}</b></span><button onClick={()=>setProposal(undefined)}><X/></button></div><div className="diff-view"><section><small>BEFORE</small><pre>{proposal.before_code}</pre></section><ChevronRight/><section><small>PROPOSED REPLACEMENT</small><pre>{proposal.replacement_code}</pre></section></div><p>{proposal.confidence_note}</p><div className="fix-actions"><span>{proposal.can_apply?'APPLY IS AVAILABLE':'MANUAL REMEDIATION REQUIRED'}</span><button disabled={!proposal.can_apply||proposal.status==='APPLIED'||proposal.status==='VERIFIED'||!!busy} onClick={apply}>{proposal.status==='APPLIED'||proposal.status==='VERIFIED'?<><CheckCircle2/> {proposal.status}</>:<><WandSparkles/> {busy==='apply'?'APPLYING…':'APPLY TO WORKING COPY'}</>}</button></div></motion.div>}</AnimatePresence>
    <AnimatePresence>{verification&&<motion.div className="verification-toast" initial={{opacity:0,x:30}} animate={{opacity:1,x:0}}><CheckCircle2/><span><b>{verification.status.replaceAll('_',' ')}</b><small>{verification.files_checked} files checked · {verification.remaining_count} findings remain · static validators only</small></span><button onClick={()=>setVerification(undefined)}><X/></button></motion.div>}</AnimatePresence>
  </Shell>;
}
