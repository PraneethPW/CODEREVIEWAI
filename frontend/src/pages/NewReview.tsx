import {useEffect, useMemo, useRef, useState} from 'react';
import Editor from '@monaco-editor/react';
import {AnimatePresence, motion} from 'framer-motion';
import {Archive, ArrowRight, CheckCircle2, Code2, FileCode2, Files, FolderPlus, Gauge, ShieldCheck, Sparkles, UploadCloud} from 'lucide-react';
import {useNavigate} from 'react-router-dom';
import {api} from '../lib/api';
import {PageHeader, Shell} from '../components/Shell';

type InputMode = 'paste' | 'file' | 'project' | 'zip';
const starter = `def calculate_total(items):
    total = 0
    for item in items:
        total += item["price"]
    return total
`;
const allowed = /\.(py|js|jsx|ts|tsx|java|html|css|json|yml|yaml)$/i;

export function NewReview() {
  const navigate = useNavigate();
  const fileInput = useRef<HTMLInputElement>(null);
  const [projects, setProjects] = useState<any[]>([]);
  const [project, setProject] = useState('');
  const [newProject, setNewProject] = useState('');
  const [mode, setMode] = useState<InputMode>('paste');
  const [source, setSource] = useState(starter);
  const [filename, setFilename] = useState('student_code.py');
  const [files, setFiles] = useState<File[]>([]);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => {api<any[]>('/projects').then(setProjects);}, []);

  const metrics = useMemo(() => {
    if (mode === 'paste' || mode === 'file') return {files: 1, lines: source.split('\n').length, bytes: new Blob([source]).size};
    return {files: files.length, lines: 'after upload', bytes: files.reduce((sum,file)=>sum+file.size,0)};
  }, [mode, source, files]);

  const createProject = async () => {
    if (newProject.trim().length < 2) return setError('Enter a project name with at least 2 characters.');
    try {
      const created: any = await api('/projects', {method:'POST', body:JSON.stringify({name:newProject.trim(),language:'Auto detected'})});
      setProjects(current => [created, ...current]); setProject(created.id); setNewProject(''); setError('');
    } catch (caught:any) {setError(caught.message);}
  };

  const chooseFiles = async (picked: File[]) => {
    setError('');
    if (mode === 'zip') {
      if (picked.length !== 1 || !picked[0].name.toLowerCase().endsWith('.zip')) return setError('Choose one ZIP archive.');
      if (picked[0].size > 10_000_000) return setError('ZIP archives are limited to 10 MB.');
      setFiles(picked); return;
    }
    const supported = picked.filter(file => allowed.test(file.name));
    if (!supported.length) return setError('No supported UTF-8 source files were selected.');
    if (supported.some(file=>file.size>500_000)) return setError('Each source file must be under 500 KB.');
    if (mode === 'file') {
      const file = supported[0]; setFiles([file]); setFilename(file.name); setSource(await file.text());
    } else setFiles(supported.slice(0,250));
  };

  const run = async () => {
    if (!project) return setError('Step 1 is required: select or create a project.');
    if ((mode === 'paste' || mode === 'file') && !source.trim()) return setError('Add source code before starting the review.');
    if ((mode === 'project' || mode === 'zip') && !files.length) return setError('Choose source files or a ZIP archive first.');
    setBusy(true); setError('');
    try {
      let result: any;
      if (mode === 'paste' || mode === 'file') {
        result = await api('/scans/start', {method:'POST',body:JSON.stringify({project_id:project,input_type:mode==='paste'?'paste':'upload',source,filename,language:'auto',review_mode:'Balanced',checks:{security:true,quality:true,complexity:true}})});
      } else {
        const data = new FormData(); data.append('project_id', project);
        files.forEach(file => data.append('uploads', file, (file as any).webkitRelativePath || file.name));
        result = await api('/import/project/start', {method:'POST',body:data});
      }
      navigate(`/app/scans/${result.id}/processing`);
    } catch (caught:any) {setBusy(false);setError(caught.message);}
  };

  const modes: [InputMode,string,string,any][] = [
    ['paste','Paste code','Type or paste a focused snippet',Code2],
    ['file','Single file','Review one complete source file',FileCode2],
    ['project','Multiple files','Review up to 250 related files',Files],
    ['zip','ZIP project','Preserve a project folder structure',Archive],
  ];
  return <Shell><PageHeader kicker="NEW REVIEW / SOURCE → EVIDENCE → CONTROLLED FIX" title="Initialize a code review"/>
    <div className="review-command-grid">
      <section className="glass review-steps">
        <div className="step-head"><i>01</i><span><small>PROJECT CONTEXT</small><b>Choose where this review belongs</b></span><CheckCircle2 className={project?'done':''}/></div>
        <select value={project} onChange={e=>setProject(e.target.value)}><option value="">Select a project</option>{projects.map(item=><option key={item.id} value={item.id}>{item.name} · {item.language}</option>)}</select>
        <div className="project-create"><input value={newProject} onChange={e=>setNewProject(e.target.value)} placeholder="Or create a new project"/><button onClick={createProject}><FolderPlus/> Create</button></div>
        <div className="step-head"><i>02</i><span><small>INPUT METHOD</small><b>Choose what you want analysed</b></span></div>
        <div className="input-modes">{modes.map(([key,label,copy,Icon])=><button key={key} className={mode===key?'active':''} onClick={()=>{setMode(key);setFiles([]);setError('');}}><Icon/><span><b>{label}</b><small>{copy}</small></span></button>)}</div>
        <div className="safety-brief"><ShieldCheck/><span><b>SAFE ANALYSIS BOUNDARY</b><small>Static validators inspect text. Uploaded code is not executed.</small></span></div>
      </section>
      <section className="glass review-stage">
        <div className="stage-toolbar"><span><small>03 / SOURCE INPUT</small><b>{mode.toUpperCase()} MODE</b></span><div><i>{metrics.files}</i> FILES <i>{metrics.lines}</i> LINES <i>{Math.ceil(Number(metrics.bytes)/1024)}</i> KB</div></div>
        {(mode === 'file' || mode === 'project' || mode === 'zip') && <motion.button whileTap={{scale:.98}} className="drop-zone" onClick={()=>fileInput.current?.click()}><UploadCloud/><strong>{mode==='zip'?'Choose a ZIP project':mode==='project'?'Choose source files':'Choose one source file'}</strong><span>{files.length ? `${files.length} item${files.length>1?'s':''} ready` : 'Python · JavaScript · TypeScript · Java · HTML · CSS · JSON · YAML'}</span><input ref={fileInput} hidden type="file" accept={mode==='zip'?'.zip':'.py,.js,.jsx,.ts,.tsx,.java,.html,.css,.json,.yml,.yaml'} multiple={mode==='project'} onChange={e=>chooseFiles(Array.from(e.target.files||[]))}/></motion.button>}
        {(mode === 'paste' || mode === 'file') && <><div className="filename-row"><label>Filename<input value={filename} onChange={e=>setFilename(e.target.value)}/></label><span>A filename is required for language detection.</span></div><Editor height="420px" language={filename.split('.').pop()==='py'?'python':'typescript'} value={source} onChange={value=>setSource(value||'')} theme="vs-dark" options={{minimap:{enabled:true},fontSize:14,lineNumbersMinChars:3,padding:{top:16}}}/></>}
        {(mode === 'project' || mode === 'zip') && files.length>0 && <div className="file-manifest"><div><b>INPUT MANIFEST</b><span>{files.length} upload item{files.length>1?'s':''}</span></div>{files.slice(0,8).map(file=><p key={file.name}><FileCode2/><span>{(file as any).webkitRelativePath||file.name}</span><small>{Math.ceil(file.size/1024)} KB</small></p>)}{files.length>8&&<small>+ {files.length-8} more files</small>}</div>}
        <div className="review-config"><span><CheckCircle2/> Syntax validation</span><span><CheckCircle2/> Security patterns</span><span><CheckCircle2/> Quality & complexity</span><span><Sparkles/> Grounded explanation</span></div>
        {error&&<motion.p initial={{x:-8}} animate={{x:0}} className="error">{error}</motion.p>}
        <button className="cta charge-button" disabled={busy} onClick={run}>{busy?'QUEUING REVIEW…':'RUN CODE REVIEW'} <ArrowRight/></button>
      </section>
      <aside className="glass review-telemetry"><small>REVIEW CONFIGURATION</small><div className="mini-gauge"><Gauge/><strong>BAL</strong><span>MODE</span></div>{[['SEC/RULE','ACTIVE'],['QUAL/STATIC','ACTIVE'],['COMP/AST','ACTIVE'],['AI/CTX','GROUND ONLY'],['EXEC/CODE','DISABLED']].map(([key,value])=><p key={key}><span>{key}</span><b>{value}</b></p>)}<hr/><small>WHAT HAPPENS NEXT</small>{['Input validated','Language detected','Syntax parsed','Rules evaluated','Evidence ranked','Explanation prepared'].map((item,index)=><div className="next-step" key={item}><i>{String(index+1).padStart(2,'0')}</i>{item}</div>)}</aside>
    </div>
    <AnimatePresence>{busy&&<motion.div className="launch-overlay" initial={{opacity:0}} animate={{opacity:1}} exit={{opacity:0}}><div className="launch-core"><i/><i/><Code2/></div><strong>SOURCE ACQUIRED</strong><span>ENTERING ANALYSIS PIPELINE</span></motion.div>}</AnimatePresence>
  </Shell>;
}
