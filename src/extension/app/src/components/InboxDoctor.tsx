import { useCallback, useEffect, useState } from 'react';
import { Account } from '../api';
import { DoctorJob, doctorApi, doctorError, isRunning } from '../doctorApi';
import DoctorConnect from './DoctorConnect';
import DoctorResults from './DoctorResults';
import DoctorUpload from './DoctorUpload';

const stages: Record<string, string> = {
  connecting: 'Connecting to mailbox', downloading: 'Downloading recent INBOX messages',
  snapshot: 'Refreshing audit snapshot', starting: 'Starting audit', extract: 'Parsing messages',
  group: 'Grouping sender identities', summarize: 'Building sender summary',
  worklist: 'Preparing cleanup recommendations', report: 'Rendering the report', done: 'Audit complete', healthy: 'Inbox healthy',
};
const statuses: Record<DoctorJob['status'], string> = {
  queued: 'Queued', in_progress: 'In progress', completed: 'Completed', healthy: 'Healthy', failed: 'Failed', discarded: 'Discarded',
};
const storageKey = 'inbox-doctor-selected-job';
function storedJob() { try { return localStorage.getItem(storageKey) || ''; } catch { return ''; } }
function rememberJob(id: string) { try { localStorage.setItem(storageKey, id); } catch { /* History remains available on the server. */ } }
function dateLabel(value: string) { return new Date(value).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }); }
function auditWindow(job: DoctorJob) {
  if (job.window_start && job.window_end) return `${dateLabel(job.window_start)} – ${dateLabel(job.window_end)}`;
  return job.days ? `Last ${job.days} days of INBOX` : '';
}
function elapsed(job: DoctorJob) {
  const seconds = Math.max(0, Math.floor((new Date(job.completed_at || Date.now()).getTime() - new Date(job.created_at).getTime()) / 1000));
  return seconds < 60 ? `${seconds}s` : `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
}

export default function InboxDoctor({ accounts, selectedAccount, onUnlock, onOpenDomain }: {
  accounts: Account[]; selectedAccount: string; onUnlock: () => void;
  onOpenDomain?: (account: string, domains: string[]) => void;
}) {
  const [selectedId, setSelectedId] = useState(storedJob);
  const [page, setPage] = useState<'new' | 'history'>(() => storedJob() ? 'history' : 'new');
  const [jobs, setJobs] = useState<DoctorJob[]>([]);
  const [historyLoading, setHistoryLoading] = useState(true);
  const [historyError, setHistoryError] = useState('');
  const [job, setJob] = useState<DoctorJob | null>(null);
  const [jobError, setJobError] = useState('');
  const [jobLoading, setJobLoading] = useState(false);
  const [discarding, setDiscarding] = useState(false);
  const [filter, setFilter] = useState('');
  const [revision, setRevision] = useState(0);

  const openJob = useCallback((id: string) => {
    rememberJob(id);
    setSelectedId(id);
    setPage('history');
    setJobError('');
    setRevision((current) => current + 1);
  }, []);

  const created = useCallback((newJob: DoctorJob) => {
    setJob(newJob);
    setJobs((current) => [newJob, ...current.filter((item) => item.id !== newJob.id)]);
    openJob(newJob.id);
  }, [openJob]);

  const refreshHistory = useCallback(async () => {
    try {
      setJobs(await doctorApi.jobs());
      setHistoryError('');
    } catch (failure) {
      setHistoryError(doctorError(failure));
    } finally { setHistoryLoading(false); }
  }, []);

  useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      try {
        const list = await doctorApi.jobs();
        if (active) { setJobs(list); setHistoryError(''); }
      } catch (failure) {
        if (active) setHistoryError(doctorError(failure));
      } finally {
        if (active) { setHistoryLoading(false); timer = setTimeout(() => void poll(), 4000); }
      }
    };
    void poll();
    return () => { active = false; clearTimeout(timer); };
  }, []);

  useEffect(() => {
    if (!selectedId) { setJob(null); return; }
    let active = true;
    let timer: ReturnType<typeof setTimeout>;
    setJobLoading(true);
    setJobError('');
    setJob((current) => current?.id === selectedId ? current : null);
    const poll = async () => {
      try {
        const data = await doctorApi.job(selectedId);
        if (!active) return;
        setJob(data);
        setJobError('');
        setJobLoading(false);
        setJobs((current) => current.map((item) => item.id === data.id ? { ...data, log: '' } : item));
        if (isRunning(data)) timer = setTimeout(() => void poll(), 1500);
      } catch (failure) {
        if (!active) return;
        setJobLoading(false);
        setJobError(doctorError(failure));
        timer = setTimeout(() => void poll(), 4000);
      }
    };
    void poll();
    return () => { active = false; clearTimeout(timer); };
  }, [selectedId, revision]);

  const discard = async () => {
    if (!job || job.status === 'discarded') return;
    if (!window.confirm(`${isRunning(job) ? 'Cancel and discard' : 'Discard'} audit ${job.id.slice(0, 8)} (${job.filename})? ${isRunning(job) ? 'This stops processing and removes' : 'This removes'} this audit's temporary files, message exports, and reports. Your mailbox is unchanged.`)) return;
    setDiscarding(true);
    try {
      const result = await doctorApi.discard(job.id);
      setJob(result);
      await refreshHistory();
      setRevision((current) => current + 1);
    } catch (failure) { setJobError(doctorError(failure)); }
    finally { setDiscarding(false); }
  };

  const visibleJobs = jobs.filter((item) => `${item.filename} ${item.id} ${item.account_email || ''} ${statuses[item.status]}`.toLocaleLowerCase().includes(filter.toLocaleLowerCase()));
  const runningCount = jobs.filter(isRunning).length;

  return <div className="doctor-workspace">
    <header className="doctor-header"><div><p className="doctor-eyebrow">UNDERSTAND · ORGANIZE · RECLAIM</p><h1>Inbox Doctor</h1><p className="muted">A clear picture of your inbox, with a plan for what to keep, archive, and unsubscribe.</p></div><span className="doctor-local-badge"><span className="doctor-dot" />Local analysis</span></header>
    <nav className="doctor-nav" aria-label="Inbox Doctor workspace"><button type="button" className={page === 'new' ? 'active' : ''} aria-pressed={page === 'new'} onClick={() => setPage('new')}>New audit</button><button type="button" className={page === 'history' ? 'active' : ''} aria-pressed={page === 'history'} onClick={() => setPage('history')}>Audit history <span>{jobs.length}</span></button>{runningCount > 0 && <span className="doctor-running-label"><span className="doctor-dot" />{runningCount} running</span>}</nav>
    {page === 'new' ? <>
      <div className="doctor-new-grid"><DoctorUpload onCreated={created} /><DoctorConnect accounts={accounts} selectedAccount={selectedAccount} onCreated={created} onOpenJob={openJob} onUnlock={onUnlock} /></div>
      <div className="doctor-explainer"><div><strong>Know your senders</strong><p>Group sender aliases and see message volume, storage, and subscription signals.</p></div><div><strong>Find the next action</strong><p>Review cleanup recommendations and add your own annotations to refine them.</p></div><div><strong>Take your report with you</strong><p>Keep a standalone HTML report, CSV worklists, and a Markdown briefing.</p></div></div>
    </> : <div className="doctor-history-layout">
      <section className="doctor-history doctor-card" aria-labelledby="history-title"><div className="doctor-history-heading"><h2 id="history-title">Audit history</h2><button type="button" className="doctor-text-button" onClick={() => void refreshHistory()}>Refresh</button></div><label className="field"><span className="sr-only">Search audit history</span><input type="search" value={filter} placeholder="Search audits…" onChange={(event) => setFilter(event.target.value)} /></label>{historyError && <div className="banner error" role="alert">{historyError}</div>}{historyLoading ? <p className="muted" role="status">Loading audit history…</p> : !visibleJobs.length ? <div className="doctor-history-empty"><p className="muted">{jobs.length ? 'No audits match your search.' : 'Your audit history will appear here.'}</p>{!jobs.length && <button type="button" className="btn" onClick={() => setPage('new')}>Create your first audit</button>}</div> : <ul className="doctor-job-list">{visibleJobs.map((item) => <li key={item.id}><button type="button" className={`doctor-job-item ${selectedId === item.id ? 'active' : ''}`} aria-pressed={selectedId === item.id} onClick={() => openJob(item.id)}><span className="doctor-job-name">{item.account_email || item.filename}</span><span className="doctor-job-meta"><span className={`doctor-status ${item.status}`}>{statuses[item.status]}</span><span>{dateLabel(item.created_at)}</span></span><span className="doctor-job-id mono">{item.id.slice(0, 8)}{item.days ? ` · ${item.days} days` : ''}</span></button></li>)}</ul>}</section>
      <div className="doctor-job-detail">
        {!selectedId && <div className="doctor-card doctor-detail-empty"><h2>Select an audit</h2><p className="muted">Open an audit from the history to view its progress, logs, and reports.</p><button type="button" className="btn primary" onClick={() => setPage('new')}>New audit</button></div>}
        {selectedId && !job && <div className="doctor-card"><p className="muted" role="status">{jobLoading ? 'Loading audit…' : 'Audit details are unavailable.'}</p>{jobError && <div className="banner error" role="alert">{jobError}<button type="button" className="doctor-text-button" onClick={() => setRevision((current) => current + 1)}>Retry</button></div>}</div>}
        {job && <>
          <section className="doctor-card doctor-progress-card" aria-labelledby="job-title"><div className="doctor-job-heading"><div><p className="doctor-eyebrow">{job.run_kind === 'scheduled' ? 'SCHEDULED AUDIT' : 'AUDIT'} {job.id.slice(0, 8)}</p><h2 id="job-title">{job.account_email || job.filename}</h2><p className="muted doctor-small">{dateLabel(job.created_at)} · {elapsed(job)}{auditWindow(job) ? ` · ${auditWindow(job)}` : ''}</p></div><span className={`doctor-status ${job.status}`}>{statuses[job.status]}</span></div>
            <div className="doctor-progress-label" aria-live="polite"><span>{stages[job.stage || ''] || statuses[job.status]}</span><strong>{Math.max(0, Math.min(100, job.progress))}%</strong></div><progress className={`doctor-progress ${job.status}`} value={Math.max(0, Math.min(100, job.progress))} max="100" aria-label="Audit progress" />
            {job.source_kind === 'mailbox' && <p className="doctor-small muted"><strong>{job.downloaded_messages.toLocaleString()}</strong>{job.total_messages !== null ? ` of ${job.total_messages.toLocaleString()}` : ''} messages downloaded{job.snapshot_available ? ' · Partial results are ready below' : ''}</p>}
            {job.status === 'healthy' && <div className="banner success doctor-empty-result" role="status">{job.window_start ? 'No INBOX messages were found in the audited window.' : `No INBOX messages were found in the last ${job.days || 7} day(s).`}</div>}
            {job.error_message && <div className="banner error" role="alert">{job.error_message}</div>}{jobError && <div className="banner error" role="alert">{jobError}</div>}
            <details className="doctor-log" open={isRunning(job)}><summary>Processing log</summary><pre tabIndex={0}>{job.log || 'Waiting for processing to start…'}</pre></details>
            <div className="doctor-card-footer"><span className="muted doctor-small">{isRunning(job) ? 'Progress updates automatically.' : job.completed_at ? `Finished ${dateLabel(job.completed_at)}` : 'Processing stopped.'}</span><div className="doctor-actions">{job.status !== 'discarded' && <button type="button" className="btn danger" disabled={discarding} onClick={() => void discard()}>{discarding ? 'Discarding…' : isRunning(job) ? 'Cancel and discard' : 'Discard audit'}</button>}{!isRunning(job) && <button type="button" className="btn" onClick={() => setPage('new')}>New audit</button>}</div></div>
          </section>
          {(job.status === 'completed' || job.snapshot_available) && <DoctorResults key={job.id} job={job} accounts={accounts} selectedAccount={selectedAccount} onOpenDomain={onOpenDomain} onUnlock={onUnlock} />}
        </>}
      </div>
    </div>}
  </div>;
}
