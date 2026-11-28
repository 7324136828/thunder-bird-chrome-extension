import { useCallback, useEffect, useId, useMemo, useRef, useState } from 'react';
import { Account } from '../api';
import {
  emailMetricsApi,
  EmailMetricsHistory,
  EmailMetricsRun,
  EmailMetricsSchedule,
} from '../emailMetricsApi';
import '../emailMetrics.css';

interface Props {
  accounts: Account[];
  onUnlock: () => void;
  onOpenDoctor: () => void;
}

interface Series {
  name: string;
  color: string;
  values: { messages: number; bytes: number }[];
}

const COLORS = ['#74e8b0', '#8ab9ff', '#f4c477', '#d5a0ff', '#f99fba', '#6ed9e4', '#b6d873', '#c6b2a0'];
const number = new Intl.NumberFormat(undefined, { maximumFractionDigits: 0 });
const mb = (bytes: number) => (bytes / 1_000_000).toLocaleString(undefined, { maximumFractionDigits: 6 });
const dateTime = (value: string | null, timezone?: string) => value
  ? new Date(value).toLocaleString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit', ...(timezone ? { timeZone: timezone } : {}) })
  : 'Not yet';
const timeline = (run: EmailMetricsRun) => run.scheduled_for || run.created_at;
const runKind = (run: EmailMetricsRun) => run.run_kind === 'scheduled' ? 'Scheduled' : 'Ad hoc';
const accountName = (run: EmailMetricsRun) => run.account_email || 'Uploaded email export';
const windowLabel = (run: EmailMetricsRun, timezone?: string) => run.window_start && run.window_end
  ? `${dateTime(run.window_start, timezone)} – ${dateTime(run.window_end, timezone)}`
  : run.days ? `Last ${run.days} days of INBOX` : 'Uploaded messages';

function MetricsChart({ title, unit, runs, series, timezone }: {
  title: string;
  unit: 'messages' | 'MB';
  runs: EmailMetricsRun[];
  series: Series[];
  timezone?: string;
}) {
  const chartId = useId();
  const [active, setActive] = useState<number | null>(null);
  const width = 900;
  const left = 65;
  const right = 22;
  const top = 20;
  const bottom = 215;
  const times = runs.map((run) => new Date(timeline(run)).getTime());
  const minTime = Math.min(...times);
  const maxTime = Math.max(...times);
  const value = (item: Series, index: number) => unit === 'messages' ? item.values[index].messages : item.values[index].bytes / 1_000_000;
  const maximum = Math.max(0, ...series.flatMap((item) => item.values.map((_, index) => value(item, index))));
  const magnitude = maximum > 0 ? 10 ** Math.floor(Math.log10(maximum)) : 1;
  const roundedMaximum = maximum > 0 ? Math.ceil(maximum / magnitude) * magnitude : 1;
  const ceiling = unit === 'messages' ? Math.max(4, Math.ceil(roundedMaximum / 4) * 4) : Math.max(0.000004, roundedMaximum);
  const x = (index: number) => maxTime === minTime ? (left + width - right) / 2 : left + (times[index] - minTime) / (maxTime - minTime) * (width - left - right);
  const y = (amount: number) => bottom - amount / ceiling * (bottom - top);
  const tick = (amount: number) => amount.toLocaleString(undefined, { maximumFractionDigits: unit === 'messages' ? 0 : 6, notation: amount >= 100_000 ? 'compact' : 'standard' });
  const axisIndexes = [...new Set([0, Math.floor((runs.length - 1) / 2), runs.length - 1])];
  const activeRun = active === null ? null : runs[active];
  const pointTitle = (item: Series, index: number) => `${item.name}: ${unit === 'messages' ? number.format(item.values[index].messages) : mb(item.values[index].bytes)} ${unit}; ${runKind(runs[index])}, ${dateTime(timeline(runs[index]), timezone)}; ${accountName(runs[index])}; ${windowLabel(runs[index], timezone)}`;

  return <section className="metrics-card metrics-chart-card" aria-labelledby={`${chartId}-heading`}>
    <div className="metrics-card-heading"><h2 id={`${chartId}-heading`}>{title}</h2><span className="metrics-unit">{unit === 'MB' ? 'MB · decimal' : 'Messages'}</span></div>
    <div className="metrics-chart-scroll">
      <svg className="metrics-chart" viewBox={`0 0 ${width} 272`} role="img" aria-labelledby={`${chartId}-heading ${chartId}-description`}>
        <desc id={`${chartId}-description`}>{title} by audit time. Diamonds indicate scheduled audits; circles indicate ad hoc audits. Exact values and audited date windows are available in the run data table below.</desc>
        {[0, 1, 2, 3, 4].map((step) => {
          const amount = ceiling * step / 4;
          return <g key={step}><line x1={left} x2={width - right} y1={y(amount)} y2={y(amount)} className="metrics-gridline" /><text x={left - 12} y={y(amount) + 4} textAnchor="end" className="metrics-axis-text">{tick(amount)}</text></g>;
        })}
        {axisIndexes.map((index) => <g key={index}>
          <line x1={x(index)} x2={x(index)} y1={bottom} y2={bottom + 5} className="metrics-axis-line" />
          <text x={x(index)} y={bottom + 24} textAnchor={runs.length === 1 ? 'middle' : index === 0 ? 'start' : index === runs.length - 1 ? 'end' : 'middle'} className="metrics-axis-text">{new Date(timeline(runs[index])).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric', ...(timezone ? { timeZone: timezone } : {}) })}</text>
        </g>)}
        <text x={(left + width - right) / 2} y="263" textAnchor="middle" className="metrics-axis-text">Audit timeline</text>
        {series.map((item, seriesIndex) => <g key={item.name} style={{ color: item.color }}>
          <polyline fill="none" stroke="currentColor" strokeWidth="2.5" strokeDasharray={seriesIndex >= COLORS.length ? '6 3' : undefined} points={runs.map((_, index) => `${x(index)},${y(value(item, index))}`).join(' ')} />
          {runs.map((run, index) => {
            const pointX = x(index);
            const pointY = y(value(item, index));
            const shared = { className: 'metrics-point', tabIndex: 0, 'aria-label': pointTitle(item, index), onFocus: () => setActive(index), onBlur: () => setActive(null), onMouseEnter: () => setActive(index), onMouseLeave: () => setActive(null), fill: item.color, stroke: '#101e30', strokeWidth: 1.7 };
            return run.run_kind === 'scheduled'
              ? <path key={run.id} {...shared} d={`M ${pointX} ${pointY - 6} l 6 6 l -6 6 l -6 -6 Z`}><title>{pointTitle(item, index)}</title></path>
              : <circle key={run.id} {...shared} cx={pointX} cy={pointY} r="4.5"><title>{pointTitle(item, index)}</title></circle>;
          })}
        </g>)}
      </svg>
    </div>
    <div className="metrics-point-detail" aria-live="polite">
      {activeRun && active !== null ? <><strong>{runKind(activeRun)} · {dateTime(timeline(activeRun), timezone)}</strong><span>{accountName(activeRun)} · {series.map((item) => `${item.name}: ${unit === 'messages' ? number.format(item.values[active].messages) : mb(item.values[active].bytes)} ${unit}`).join(' · ')}</span><span>Window: {windowLabel(activeRun, timezone)}</span></> : <span className="muted">Hover over or focus a point to inspect its audit.</span>}
    </div>
  </section>;
}

export default function EmailMetrics({ accounts, onUnlock, onOpenDoctor }: Props) {
  const [history, setHistory] = useState<EmailMetricsHistory | null>(null);
  const [schedule, setSchedule] = useState<EmailMetricsSchedule | null>(null);
  const [account, setAccount] = useState('');
  const [selectedDomains, setSelectedDomains] = useState<string[] | null>(null);
  const [search, setSearch] = useState('');
  const [mode, setMode] = useState<'aggregated' | 'unaggregated'>('aggregated');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [scheduleError, setScheduleError] = useState('');
  const [refreshedAt, setRefreshedAt] = useState<string | null>(null);
  const [knownAccounts, setKnownAccounts] = useState<string[]>([]);
  const request = useRef(0);
  const controller = useRef<AbortController | null>(null);

  const refresh = useCallback(async () => {
    const requestId = ++request.current;
    controller.current?.abort();
    const current = new AbortController();
    controller.current = current;
    setLoading(true);
    const [historyResult, scheduleResult] = await Promise.allSettled([
      emailMetricsApi.history(account, current.signal), emailMetricsApi.schedule(current.signal),
    ]);
    if (current.signal.aborted || requestId !== request.current) return;
    if (historyResult.status === 'fulfilled') {
      setHistory(historyResult.value);
      setKnownAccounts((existing) => [...new Set([...existing, ...historyResult.value.accounts])]);
      setError('');
      setRefreshedAt(new Date().toISOString());
    } else setError(historyResult.reason instanceof Error ? historyResult.reason.message : String(historyResult.reason));
    if (scheduleResult.status === 'fulfilled') {
      setSchedule(scheduleResult.value);
      setScheduleError('');
    } else setScheduleError(scheduleResult.reason instanceof Error ? scheduleResult.reason.message : String(scheduleResult.reason));
    setLoading(false);
  }, [account]);

  const accountKey = accounts.map((item) => item.email).join('\n');
  useEffect(() => {
    setHistory(null);
    void refresh();
    const timer = window.setInterval(() => { void refresh(); }, 12_000);
    return () => { window.clearInterval(timer); controller.current?.abort(); };
  }, [refresh, accountKey]);

  const runs = useMemo(() => [...(history?.runs || [])].sort((a, b) => new Date(timeline(a)).getTime() - new Date(timeline(b)).getTime() || a.id.localeCompare(b.id)), [history]);
  const domains = useMemo(() => [...new Set([...(history?.domains || []), ...runs.flatMap((run) => run.domains.map((item) => item.domain))])].sort((a, b) => a.localeCompare(b)), [history, runs]);
  const selected = domains.filter((domain) => selectedDomains === null || selectedDomains.includes(domain));
  const shownDomains = domains.filter((domain) => domain.toLowerCase().includes(search.trim().toLowerCase()));
  const accountOptions = [...new Set([...accounts.map((item) => item.email), ...knownAccounts, ...(schedule?.accounts.map((item) => item.email) || [])])].sort((a, b) => a.localeCompare(b));
  const selectedKey = selected.join('\n');
  const series = useMemo<Series[]>(() => {
    const chosen = new Set(selected);
    if (mode === 'aggregated' || domains.length === 0) return [{ name: domains.length === 0 ? 'All domains' : 'Selected domains', color: COLORS[0], values: runs.map((run) => run.domains.reduce((sum, domain) => chosen.has(domain.domain) ? { messages: sum.messages + domain.message_count, bytes: sum.bytes + domain.size_bytes } : sum, { messages: 0, bytes: 0 })) }];
    return selected.map((domain, index) => ({ name: domain, color: COLORS[index % COLORS.length], values: runs.map((run) => {
      const match = run.domains.find((item) => item.domain === domain);
      return { messages: match?.message_count || 0, bytes: match?.size_bytes || 0 };
    }) }));
  }, [mode, runs, selectedKey, domains.length]);
  const visibleScheduleAccounts = schedule?.accounts.filter((item) => !account || item.email === account) || [];
  const latest = runs[runs.length - 1];
  const latestMessages = series.reduce((total, item) => total + (item.values[runs.length - 1]?.messages || 0), 0);
  const latestBytes = series.reduce((total, item) => total + (item.values[runs.length - 1]?.bytes || 0), 0);

  return <div className="metrics-workspace">
    <header className="metrics-header"><div><p className="metrics-eyebrow">INBOX INSIGHTS</p><h1>Email Metrics</h1><p className="muted">Track message count and size across your weekly and ad hoc audits.</p></div><button type="button" className="btn" disabled={loading} onClick={() => void refresh()}>{loading ? 'Refreshing…' : 'Refresh metrics'}</button></header>

    <section className="metrics-card metrics-schedule" aria-labelledby="metrics-schedule-title">
      <div className="metrics-schedule-summary"><span className="metrics-schedule-icon" aria-hidden="true">◷</span><div><div className="metrics-schedule-title"><h2 id="metrics-schedule-title">Weekly inbox audit</h2><span className={`metrics-badge ${schedule?.enabled ? 'enabled' : ''}`}>{schedule ? schedule.enabled ? 'Automatic' : 'Paused' : 'Schedule'}</span></div><p>{schedule ? `Every Saturday at 6:00 PM · ${schedule.timezone}` : 'Every Saturday at 6:00 PM · America/New_York'}</p><p className="muted metrics-small">Missed runs are saved and caught up when the app is running and the account is unlocked. Each scheduled audit covers its own seven-day window.</p></div></div>
      {scheduleError && <div className="banner error" role="alert">Could not load the schedule: {scheduleError}</div>}
      {schedule && visibleScheduleAccounts.length > 0 && <ul className="metrics-schedule-accounts">{visibleScheduleAccounts.map((item) => <li key={item.email}><div><strong>{item.email}</strong><span className="muted metrics-small">Next: {dateTime(item.next_run_at, schedule.timezone)} · Last run: {dateTime(item.last_run_at, schedule.timezone)}</span>{item.last_error && <span className="metrics-schedule-error">Last attempt: {item.last_error}</span>}</div><div className="metrics-account-state">{item.pending_runs > 0 && <span className="metrics-badge pending">{item.pending_runs} pending {item.pending_runs === 1 ? 'run' : 'runs'}</span>}{item.unlocked ? <span className="metrics-small muted">Account unlocked</span> : <button type="button" className="btn" onClick={onUnlock}>Unlock account</button>}</div></li>)}</ul>}
      {schedule && schedule.accounts.length === 0 && <div className="metrics-schedule-connect"><p className="muted metrics-small">Connect a mail account to start weekly audits. Export audit history also appears below.</p><button type="button" className="btn" onClick={onUnlock}>Connect account</button></div>}
    </section>

    <section className="metrics-filters" aria-label="Metrics filters">
      <label className="field metrics-account-filter"><span>Account</span><select value={account} onChange={(event) => { setAccount(event.target.value); setSelectedDomains(null); setSearch(''); }}><option value="">All accounts and exports</option>{accountOptions.map((email) => <option key={email} value={email}>{email}</option>)}</select></label>
      <fieldset className="metrics-mode"><legend>Display</legend><div><label className={mode === 'aggregated' ? 'active' : ''}><input type="radio" name="metrics-mode" value="aggregated" checked={mode === 'aggregated'} onChange={() => setMode('aggregated')} />Aggregated</label><label className={mode === 'unaggregated' ? 'active' : ''}><input type="radio" name="metrics-mode" value="unaggregated" checked={mode === 'unaggregated'} onChange={() => setMode('unaggregated')} />Unaggregated</label></div></fieldset>
      <p className="metrics-filter-note muted">{mode === 'aggregated' ? 'Selected domains are added together at each audit.' : 'Each selected domain has its own line and legend.'}<br />{' '}A domain absent from an audit contributes 0.</p>
    </section>

    {error && <div className="banner error metrics-load-error" role="alert">Could not load email metrics: {error}<button className="btn" type="button" disabled={loading} onClick={() => void refresh()}>Retry metrics</button></div>}
    {!history && loading && <div className="metrics-card metrics-empty" role="status">Loading email metrics…</div>}
    {history && runs.length === 0 && <section className="metrics-card metrics-empty"><span className="metrics-empty-icon" aria-hidden="true">▥</span><h2>No audit metrics yet</h2><p className="muted">Completed audits will appear here, including scheduled runs, ad hoc runs, and uploaded exports.</p><button type="button" className="btn primary" onClick={onOpenDoctor}>Open Inbox Doctor</button></section>}
    {history && runs.length > 0 && <div className="metrics-content">
      <aside className="metrics-card metrics-domain-panel" aria-labelledby="metrics-domains-title"><div className="metrics-domain-heading"><h2 id="metrics-domains-title">Domains</h2><span className="metrics-small muted">{selected.length} of {domains.length}</span></div><label className="field"><span className="metrics-sr-only">Search domains</span><input type="search" placeholder="Search domains…" aria-label="Search domains" value={search} onChange={(event) => setSearch(event.target.value)} /></label><div className="metrics-domain-actions"><button className="metrics-text-button" type="button" disabled={selected.length === domains.length} onClick={() => setSelectedDomains(null)}>Select all</button><button className="metrics-text-button" type="button" disabled={selected.length === 0} onClick={() => setSelectedDomains([])}>Clear</button></div><ul className="metrics-domain-list">{shownDomains.map((domain) => <li key={domain}><label><input type="checkbox" checked={selected.includes(domain)} onChange={(event) => setSelectedDomains(event.target.checked ? [...selected, domain] : selected.filter((item) => item !== domain))} /><span>{domain}</span></label></li>)}</ul>{shownDomains.length === 0 && <p className="metrics-small muted">{domains.length === 0 ? 'No sender domains in these audits.' : 'No domains match your search.'}</p>}<p className="metrics-small muted metrics-domain-footnote">Filters apply to every audit on the timeline. Message size includes the full stored message.</p></aside>
      <div className="metrics-visuals">
        <div className="metrics-summary"><div className="metrics-card"><span>Audit runs</span><strong>{number.format(runs.length)}</strong><small>Scheduled and ad hoc</small></div><div className="metrics-card"><span>Latest run · messages</span><strong>{number.format(latestMessages)}</strong><small>{selected.length} selected {selected.length === 1 ? 'domain' : 'domains'}</small></div><div className="metrics-card"><span>Latest run · size</span><strong>{mb(latestBytes)} <small>MB</small></strong><small>{latest && dateTime(timeline(latest), schedule?.timezone)}</small></div></div>
        <div className="metrics-legend" aria-label="Chart legend"><div className="metrics-series-legend">{series.map((item, index) => <span key={item.name}><i style={{ background: item.color, borderTop: index >= COLORS.length ? '2px dashed #07101f' : undefined }} aria-hidden="true" />{item.name}</span>)}</div><div className="metrics-run-legend"><span><i className="metrics-scheduled-symbol" aria-hidden="true" />Scheduled</span><span><i className="metrics-adhoc-symbol" aria-hidden="true" />Ad hoc</span></div></div>
        {selected.length === 0 && domains.length > 0 && <p className="metrics-selection-notice" role="status">Select one or more domains to display on the charts.</p>}
        <MetricsChart title="Number of messages" unit="messages" runs={runs} series={selected.length || domains.length === 0 ? series : []} timezone={schedule?.timezone} />
        <MetricsChart title="Message size" unit="MB" runs={runs} series={selected.length || domains.length === 0 ? series : []} timezone={schedule?.timezone} />
        <p className="metrics-small metrics-chart-caption muted">Each point is one audit. Scheduled points use the scheduled time; ad hoc points use the audit start time. Date windows may overlap. All times are shown in {schedule?.timezone || 'your local timezone'}. 1 MB = 1,000,000 bytes.</p>
        <details className="metrics-card metrics-run-data"><summary>View run data <span className="muted">({runs.length} {runs.length === 1 ? 'run' : 'runs'})</span></summary><p className="metrics-small muted">Values reflect the selected domains. In unaggregated mode, each domain has a separate row for every run, including zero values.</p><div className="metrics-table-scroll"><table aria-label="Email metrics run data"><thead><tr><th scope="col">Audit time</th><th scope="col">Type</th><th scope="col">Account / source</th><th scope="col">Domain</th><th scope="col">Messages</th><th scope="col">Size (MB)</th><th scope="col">Audited window</th><th scope="col">Actual start</th></tr></thead><tbody>{runs.map((run, runIndex) => series.map((item) => <tr key={`${run.id}-${item.name}`}><td>{dateTime(timeline(run), schedule?.timezone)}</td><td><span className={`metrics-badge ${run.run_kind}`}>{runKind(run)}</span></td><td>{accountName(run)}</td><th scope="row">{item.name}</th><td data-metric="messages">{number.format(item.values[runIndex].messages)}</td><td data-metric="size">{mb(item.values[runIndex].bytes)}</td><td>{windowLabel(run, schedule?.timezone)}</td><td>{dateTime(run.created_at, schedule?.timezone)}</td></tr>))}</tbody></table></div></details>
      </div>
    </div>}
    {refreshedAt && <p className="metrics-refresh-note muted">Updated {dateTime(refreshedAt)} · Refreshes automatically every 12 seconds</p>}
  </div>;
}
