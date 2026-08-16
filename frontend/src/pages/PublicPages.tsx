import {useState} from 'react';
import type {FormEvent} from 'react';
import {motion} from 'framer-motion';
import {Activity, ArrowRight, BrainCircuit, CheckCircle2, Code2, FileCode2, Gauge, ShieldAlert, Sparkles} from 'lucide-react';
import {Link, useNavigate} from 'react-router-dom';
import {api} from '../lib/api';

const demoCode = `import os

API_TOKEN = "demo_value_not_real"

def lookup(user):
    query = "SELECT * FROM users WHERE name = '" + user
    return eval(user)`;

const demoSignals = [
  ['SECURITY', '08', [18, 28, 41, 34, 62, 55]],
  ['QUALITY', '14', [42, 38, 48, 58, 51, 70]],
  ['COMPLEXITY', '71', [20, 35, 31, 49, 64, 71]],
  ['RELIABILITY', '92%', [52, 59, 66, 71, 80, 92]],
];

export function Landing() {
  const [previewTab, setPreviewTab] = useState<'findings'|'code'|'review'>('code');
  return <main className="landing-v2">
    <nav><Link className="brand" to="/"><Code2/> CODE<span>REVIEW</span></Link><span/><Link to="/login">Sign in</Link><Link className="mini" to="/login">Initialize review <ArrowRight size={14}/></Link></nav>
    <section className="cockpit">
      <motion.div initial={{opacity: 0, x: -30}} animate={{opacity: 1, x: 0}}>
        <p className="eyebrow">CODEREVIEW AI / INTELLIGENCE ENGINE <b className="online">● ONLINE</b></p>
        <h1>REVIEW CODE.<br/><em>SEE THE EVIDENCE.</em></h1>
        <p className="lead">Upload source, inspect exact rule evidence, generate a controlled fix, verify it, and download the reviewed artifact.</p>
        <Link className="cta" to="/login">ENTER THE ENGINE <ArrowRight/></Link>
        <div className="capability-rail"><span>12+ RULE GROUPS</span><span>8 INPUT LANGUAGES</span><span>FILE / MULTI / ZIP</span><span>HUMAN APPROVAL</span></div>
      </motion.div>
      <motion.div className="cockpit-engine" initial={{opacity: 0, scale: .94}} animate={{opacity: 1, scale: 1}} transition={{delay: .15}}>
        <div className="demo-flag">INTERACTIVE DEMO · ILLUSTRATIVE VALUES</div>
        <div className="hud-ring ring-one"/><div className="hud-ring ring-two"/>
        <div className="demo-editor"><div className="editor-head"><i/><i/><i/> SRC/PY · DEEP SCAN</div><pre>{demoCode}</pre><div className="scanner-line"/><div className="demo-finding"><b>HIGH</b> SQL CONSTRUCTION <small>LINE 6 · SEC/RULE</small></div></div>
        <div className="hud-module top-left"><small>RULE ENGINE</small><b>ACTIVE</b><span>STATIC / 12 GROUPS</span></div>
        <div className="hud-module bottom-right"><small>AI CONTEXT</small><b>STANDBY</b><span>EXPLAINS EVIDENCE</span></div>
      </motion.div>
    </section>
    <section className="demo-telemetry"><div className="section-title"><p className="eyebrow">CODE INTELLIGENCE / LIVE SIGNAL</p><h2>Analysis telemetry</h2><span>DEMO TELEMETRY</span></div><div className="signal-grid">
      {demoSignals.map(([label, value, values]: any) => <article key={label}><small>ENG/{label}</small><strong>{value}</strong><b>{label}</b><div className="spark">{values.map((x: number, i: number) => <i key={i} style={{height: `${x}%`}}/>)}</div></article>)}
      <article className="pipeline-map"><small>ENGINE PIPELINE · DEMO</small><div>{['SOURCE','PARSE','RULES','EVIDENCE','AI','REVIEW'].map((x,i)=><span key={x}><i>{i+1}</i>{x}</span>)}</div></article>
      <article className="severity-matrix"><small>SEVERITY MATRIX · DEMO</small>{[['CRITICAL',2],['HIGH',5],['MEDIUM',11],['LOW',8]].map(([x,v]:any)=><p key={x}><b>{x}</b><i style={{width:`${v*6}%`}}/><span>{String(v).padStart(2,'0')}</span></p>)}</article>
    </div></section>
    <section className="workflow-story"><p className="eyebrow">PRODUCT WORKFLOW / REAL CAPABILITY</p><h2>One controlled path from source to safer code.</h2><div className="workflow-nodes">{[[FileCode2,'UPLOAD','Single, multiple, or ZIP'],[Activity,'ANALYSE','Syntax, security, quality'],[BrainCircuit,'EXPLAIN','Grounded in exact evidence'],[ShieldAlert,'FIX','Preview before applying'],[CheckCircle2,'VERIFY','Re-run static validators']].map(([Icon,title,copy]:any)=><article key={title}><Icon/><small>SYS/{title}</small><b>{title}</b><span>{copy}</span></article>)}</div></section>
    <section className="review-preview"><div className="section-title"><p className="eyebrow">WORKSPACE PREVIEW / DEMO</p><h2>Inspect code like technical evidence.</h2></div><div className="preview-mobile-tabs" role="tablist" aria-label="Workspace demonstration views">{(['findings','code','review'] as const).map(tab=><button aria-selected={previewTab===tab} className={previewTab===tab?'active':''} onClick={()=>setPreviewTab(tab)} key={tab}>{tab}</button>)}</div><div className="preview-console"><aside className={previewTab==='findings'?'mobile-active':''}><b>FINDINGS / 03</b><span className="selected">HIGH · SQL construction</span><span>HIGH · Unsafe eval</span><span>MED · Broad exception</span></aside><pre className={previewTab==='code'?'mobile-active':''}><mark>6  query = "SELECT *" + user</mark>{'\n'}7  return eval(user)</pre><section className={previewTab==='review'?'mobile-active':''}><small>SEC/RULE</small><h3>SQL construction</h3><p>Data and query structure are combined on line 6.</p><button>GENERATE FIX</button></section></div></section>
    <section className="engine-cta"><div className="cta-core"><Gauge/><i/><i/></div><p className="eyebrow">STATIC / SECURITY / AI CONTEXT / HUMAN REVIEW</p><h2>READY TO REVIEW</h2><Link className="cta" to="/login">INITIALIZE REVIEW <ArrowRight/></Link></section>
  </main>;
}

export function Auth() {
  const navigate = useNavigate();
  const [register, setRegister] = useState(false);
  const [form, setForm] = useState({name: '', email: '', password: ''});
  const [error, setError] = useState('');
  const submit = async (event: FormEvent) => {
    event.preventDefault(); setError('');
    try {
      const body = register ? form : {email: form.email, password: form.password};
      const response: any = await api(`/auth/${register ? 'register' : 'login'}`, {method: 'POST', body: JSON.stringify(body)});
      localStorage.setItem('cra_token', response.access_token); navigate('/app');
    } catch (caught: any) { setError(caught.message); }
  };
  return <main className="auth auth-v2"><section className="engine"><p className="eyebrow">EVIDENCE REVIEW / CONTROLLED REMEDIATION</p><h1>Source enters.<br/><i>Evidence leaves.</i></h1><div className="auth-telemetry">{['INPUT BOUNDARY / ENFORCED','STATIC ENGINE / READY','SECRET REDACTION / ACTIVE','CODE EXECUTION / DISABLED'].map(x=><span key={x}><CheckCircle2/> {x}</span>)}</div></section><section className="auth-card"><Sparkles/><h2>{register ? 'Create workspace' : 'Enter command center'}</h2><p>Your scans and decisions stay attached to your account.</p><form onSubmit={submit}>{register&&<input required placeholder="Your name" value={form.name} onChange={e=>setForm({...form,name:e.target.value})}/>}<input required type="email" placeholder="Email" value={form.email} onChange={e=>setForm({...form,email:e.target.value})}/><input required minLength={8} type="password" placeholder="Password (8+ characters)" value={form.password} onChange={e=>setForm({...form,password:e.target.value})}/>{error&&<small className="error">{error}</small>}<button>{register?'Create account':'Sign in'} <ArrowRight size={16}/></button></form><button className="text-button" onClick={()=>setRegister(!register)}>{register?'Already have an account? Sign in':'New here? Create an account'}</button></section></main>;
}
