import {useEffect, useMemo, useState} from 'react';
import {motion} from 'framer-motion';
import {ArrowRight, Check, CheckCircle2, CircleDot, Code2, FileCheck2, ShieldCheck, Sparkles, XCircle} from 'lucide-react';
import {useNavigate, useParams} from 'react-router-dom';
import {api} from '../lib/api';
import {PageHeader, Shell} from '../components/Shell';
import type {ScanEvent} from '../types';

const stages = [
  ['SOURCE','Source acquired','Input persisted for this review'],
  ['VALIDATE','Safety boundary','File limits and text encoding checked'],
  ['PARSE','Syntax validators','Language-specific parsers inspect source'],
  ['STATIC_RULES','Static rule engine','Security, OWASP mapping, quality and complexity'],
  ['RANK','Evidence ranking','Supported findings prioritised'],
  ['AI_CONTEXT','AI explanation','Detector evidence is explained, not invented'],
  ['COMPLETE','Workspace ready','Results and controlled fixes unlocked'],
] as const;

export function Processing() {
  const {id} = useParams();
  const navigate = useNavigate();
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [status, setStatus] = useState('RECEIVED');
  useEffect(() => {
    let active = true;
    const poll = async () => {
      try {
        const [stream,state]: any[] = await Promise.all([api(`/scans/${id}/events`),api(`/scans/${id}/status`)]);
        if (!active) return;
        setEvents(stream); setStatus(state.status);
        if (['COMPLETED','FAILED'].includes(state.status)) window.clearInterval(timer);
      } catch { if (active) setStatus('FAILED'); }
    };
    const timer=window.setInterval(poll,450);
    poll();
    return ()=>{active=false;window.clearInterval(timer);};
  }, [id]);
  const latest = events[events.length-1];
  const metrics = useMemo(()=>events.reduce((all,event)=>({...all,...event.metrics}),{} as Record<string,any>),[events]);
  const finished = new Map(events.filter(event=>event.status==='PASSED').map(event=>[event.stage,event]));
  const openResults=()=>navigate(`/app/scans/${id}`);
  return <Shell><PageHeader kicker={`SCAN ${String(id).slice(0,8).toUpperCase()} / REAL BACKEND STATE`} title={status==='FAILED'?'Analysis stopped':status==='COMPLETED'?'Analysis complete — review ready':'Code intelligence engine running'}/>
    <div className="processing-grid">
      <section className="glass event-console"><div className="module-head"><span>SYS/EVENT_STREAM</span><b>{status}</b></div><h3>Live analysis events</h3><div className="event-list">{events.map(event=><motion.p initial={{opacity:0,x:-12}} animate={{opacity:1,x:0}} key={event.sequence}><small>{new Date(event.created_at).toLocaleTimeString()}</small><i className={event.status.toLowerCase()}/><span><b>{event.stage}</b>{event.message}</span></motion.p>)}</div></section>
      <section className="scanner-arena"><div className={`analysis-core ${status.toLowerCase()}`}><div className="scanner-radar"/><i/><i/><Code2/><strong>{status==='COMPLETED'?'READY':status==='FAILED'?'FAILED':'ANALYSING'}</strong><small>{latest?.stage||'SOURCE'}</small></div><div className="stage-orbit">{stages.map(([key,label],index)=><span className={finished.has(key)?'done':latest?.stage===key?'active':''} style={{'--i':index} as any} key={key}><i>{finished.has(key)?<Check/>:<CircleDot/>}</i>{label}</span>)}</div><p>{latest?.message||'Preparing the analysis pipeline…'}</p></section>
      <section className="glass live-metrics"><div className="module-head"><span>ENG/DERIVED</span><b>NO DEMO DATA</b></div><h3>Live telemetry</h3>{[['FILES',metrics.files||metrics.files_checked],['LINES',metrics.lines],['SIGNALS',metrics.signals],['OWASP MAPS',metrics.owasp_mapped],['EXPLAINED',metrics.explained]].map(([label,value])=><article key={label}><small>{label}</small><strong>{value??'—'}</strong><span>{value===undefined?'Pending backend stage':'Reported by engine'}</span></article>)}<div className="execution-state"><ShieldCheck/><span><b>STATIC VALIDATORS</b><small>Running safely. Submitted code is not executed.</small></span></div></section>
    </div>
    <section className="analysis-pipeline">{stages.map(([key,label,copy],index)=><article className={finished.has(key)?'done':latest?.stage===key?'active':''} key={key}><div>{finished.has(key)?<FileCheck2/>:status==='FAILED'&&latest?.stage===key?<XCircle/>:<Sparkles/>}</div><small>{String(index+1).padStart(2,'0')} / {key}</small><b>{label}</b><span>{copy}</span></article>)}</section>
    {status==='COMPLETED'&&<motion.section className="completion-handoff" initial={{opacity:0,y:12}} animate={{opacity:1,y:0}} aria-live="polite"><CheckCircle2/><div><small>ANALYSIS / COMPLETE</small><b>Evidence workspace is ready</b><span>This page will remain here. Review every completed stage, then continue whenever you are ready.</span></div><button onClick={openResults}>SEE FINAL RESULT <ArrowRight/></button></motion.section>}
    {status==='FAILED'&&<div className="failure-banner"><XCircle/><span><b>The scan could not finish.</b> No fabricated results were created. Return to New Review and inspect the input limits.</span></div>}
  </Shell>;
}
