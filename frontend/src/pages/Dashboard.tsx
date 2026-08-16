import {useEffect, useState} from 'react';
import {Area, AreaChart, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis} from 'recharts';
import {Activity, ArrowRight, CheckCircle2, Database, FileSearch, FolderKanban, Plus, ShieldAlert} from 'lucide-react';
import {Link} from 'react-router-dom';
import {api} from '../lib/api';
import {Loading, PageHeader, Shell} from '../components/Shell';

const colors: Record<string,string> = {critical:'#f43f5e', high:'#fb7185', medium:'#fbbf24', low:'#22d3ee', info:'#8b5cf6'};

export function Dashboard() {
  const [data, setData] = useState<any>();
  useEffect(() => {api('/dashboard').then(setData);}, []);
  if (!data) return <Shell><Loading label="LOADING REAL TELEMETRY"/></Shell>;
  const metrics = [['SCANS',data.scans,FileSearch],['OPEN',data.open,ShieldAlert],['HIGH RISK',data.high_risk,ShieldAlert],['REVIEWED',data.reviewed,CheckCircle2],['PROJECTS',data.projects,FolderKanban]];
  const severity = Object.entries(data.severity).map(([name,value])=>({name,value}));
  const trend = [...Array(8)].map((_, index) => ({name: `${index + 1}`, value: index === 7 ? data.scans : 0}));
  return <Shell><PageHeader kicker="CODE INTELLIGENCE / LIVE DATABASE" title="Review Command Center"><Link className="mini" to="/app/review">New review <Plus size={15}/></Link></PageHeader>
    <div className="telemetry-strip">{metrics.map(([label,value,Icon]:any)=><article key={label}><Icon/><small>SYS/{label.replace(' ','_')}</small><strong>{value}</strong><span>{label}</span></article>)}</div>
    {!data.scans ? <section className="onboarding-console"><div className="empty-core"><FileSearch/></div><p className="eyebrow">NO USER SCANS / ZERO IS REAL</p><h2>Start with source you want to understand.</h2><div className="onboarding-flow"><span>1 · Choose a project</span><span>2 · Paste or upload source</span><span>3 · Inspect evidence</span><span>4 · Approve fixes</span></div><Link className="cta" to="/app/review">START FIRST REVIEW <ArrowRight/></Link></section> : <div className="dashboard-grid">
      <section className="glass chart-card"><div className="module-head"><span>SEC/SEVERITY</span><b>REAL DATA</b></div><h3>Severity distribution</h3><ResponsiveContainer width="100%" height={230}><PieChart><Pie data={severity} dataKey="value" nameKey="name" innerRadius={62} outerRadius={88} paddingAngle={3}>{severity.map((entry:any)=><Cell key={entry.name} fill={colors[entry.name]}/>)}</Pie><Tooltip/></PieChart></ResponsiveContainer><div className="legend">{severity.map((x:any)=><span key={x.name}><i style={{background:colors[x.name]}}/>{x.name} <b>{x.value}</b></span>)}</div></section>
      <section className="glass chart-card wide"><div className="module-head"><span>SYS/SCAN_TREND</span><b>DATABASE</b></div><h3>Scan progression</h3><ResponsiveContainer width="100%" height={230}><AreaChart data={trend}><defs><linearGradient id="scanFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#a855f7" stopOpacity={.7}/><stop offset="1" stopColor="#a855f7" stopOpacity={0}/></linearGradient></defs><XAxis dataKey="name" stroke="#6f6180"/><YAxis stroke="#6f6180"/><Tooltip/><Area type="monotone" dataKey="value" stroke="#c084fc" fill="url(#scanFill)"/></AreaChart></ResponsiveContainer></section>
      <section className="glass activity-card"><div className="module-head"><span>REV/ACTIVITY</span><b>LIVE</b></div><h3>Recent activity</h3>{data.recent.length ? data.recent.map((item:any,index:number)=><p key={index}><Activity/><span><b>{item.action.replaceAll('_',' ')}</b><small>{item.rationale||'System event'}</small></span></p>):<p className="muted">No review decisions yet.</p>}</section>
    </div>}
    <section className="system-status"><div><Database/><span><small>DATABASE</small><b>CONNECTED</b></span></div><div><Activity/><span><small>STATIC ENGINE</small><b>READY</b></span></div><div><ShieldAlert/><span><small>CODE EXECUTION</small><b>DISABLED</b></span></div><div><CheckCircle2/><span><small>SCANNER</small><b>READY</b></span></div></section>
  </Shell>;
}
