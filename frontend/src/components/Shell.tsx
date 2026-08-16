import type {ReactNode} from 'react';
import {Activity, BarChart3, Code2, FileSearch, LogOut, Plus, ShieldAlert} from 'lucide-react';
import {Link, useLocation, useNavigate} from 'react-router-dom';

const links = [
  ['/app', 'Command center', BarChart3],
  ['/app/review', 'New review', Plus],
  ['/app/scans', 'Scans', FileSearch],
  ['/app/findings', 'Findings', ShieldAlert],
  ['/app/audit', 'Audit', Activity],
] as const;

export function Shell({children}: {children: ReactNode}) {
  const navigate = useNavigate();
  const location = useLocation();
  return <div className="shell rescue-shell">
    <aside>
      <Link className="brand" to="/app"><Code2/> CODE<span>REVIEW</span></Link>
      <div className="engine-state"><i/> ENG/STATIC <b>READY</b></div>
      {links.map(([to, label, Icon]) => <Link className={location.pathname === to ? 'active' : ''} key={to} to={to}><Icon size={17}/>{label}</Link>)}
      <div className="side-signal"><small>SYSTEM</small><strong>LOCAL INPUT ONLY</strong><span>Source is analysed, never executed.</span></div>
      <button className="logout" onClick={() => {localStorage.removeItem('cra_token'); navigate('/');}}><LogOut size={17}/> Logout</button>
    </aside>
    <div className="app-content">{children}</div>
    <nav className="mobile-dock" aria-label="Application navigation">{links.map(([to, label, Icon]) => <Link className={location.pathname === to ? 'active' : ''} key={to} to={to}><Icon size={18}/><span>{label.replace('Command center','Home').replace('New review','Review')}</span></Link>)}</nav>
  </div>;
}

export function PageHeader({kicker, title, children}: {kicker: string; title: string; children?: ReactNode}) {
  return <header className="page-header"><div><p className="eyebrow">{kicker}</p><h2>{title}</h2></div>{children}</header>;
}

export function Loading({label = 'INITIALISING ENGINE'}: {label?: string}) {
  return <div className="system-loading"><div className="load-rings"><i/><i/><Code2/></div><strong>{label}</strong><small>SOURCE → VALIDATE → PARSE → EVIDENCE</small></div>;
}
