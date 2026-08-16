import React, {lazy, Suspense} from 'react';
import {createRoot} from 'react-dom/client';
import {BrowserRouter, Navigate, Route, Routes} from 'react-router-dom';
import {QueryClient, QueryClientProvider} from '@tanstack/react-query';
import {Auth, Landing} from './pages/PublicPages';
import './styles.css';
import './rescue.css';

const client = new QueryClient();
const Dashboard = lazy(()=>import('./pages/Dashboard').then(module=>({default:module.Dashboard})));
const NewReview = lazy(()=>import('./pages/NewReview').then(module=>({default:module.NewReview})));
const Processing = lazy(()=>import('./pages/Processing').then(module=>({default:module.Processing})));
const ScanReview = lazy(()=>import('./pages/ScanReview').then(module=>({default:module.ScanReview})));
const Scans = lazy(()=>import('./pages/HistoryPages').then(module=>({default:module.Scans})));
const Findings = lazy(()=>import('./pages/HistoryPages').then(module=>({default:module.Findings})));
const Audit = lazy(()=>import('./pages/HistoryPages').then(module=>({default:module.Audit})));
function Protected({children}: {children: React.ReactNode}) {
  return localStorage.getItem('cra_token') ? <>{children}</> : <Navigate to="/login"/>;
}
function App() {
  return <Routes>
    <Route path="/" element={<Landing/>}/>
    <Route path="/login" element={<Auth/>}/>
    <Route path="/app" element={<Protected><Dashboard/></Protected>}/>
    <Route path="/app/review" element={<Protected><NewReview/></Protected>}/>
    <Route path="/app/scans" element={<Protected><Scans/></Protected>}/>
    <Route path="/app/scans/:id/processing" element={<Protected><Processing/></Protected>}/>
    <Route path="/app/scans/:id" element={<Protected><ScanReview/></Protected>}/>
    <Route path="/app/findings" element={<Protected><Findings/></Protected>}/>
    <Route path="/app/audit" element={<Protected><Audit/></Protected>}/>
    <Route path="*" element={<Navigate to="/"/>}/>
  </Routes>;
}
createRoot(document.getElementById('root')!).render(<QueryClientProvider client={client}><BrowserRouter><Suspense fallback={<div className="system-loading"><strong>LOADING COMMAND MODULE</strong></div>}><App/></Suspense></BrowserRouter></QueryClientProvider>);
