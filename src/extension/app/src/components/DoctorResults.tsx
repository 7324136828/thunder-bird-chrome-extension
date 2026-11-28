import { useEffect, useMemo, useState } from 'react';
import { Account } from '../api';
import { DoctorJob, doctorApi, doctorError } from '../doctorApi';
import { backendDownloadClick } from '../platform/downloads';
import SandboxFrame from './SandboxFrame';

interface Summary {
  total_messages: number;
  unique_senders: number;
  unique_domains: number;
  senders_with_unsubscribe: number;
  total_size_bytes: number;
  date_range?: { first: string | null; last: string | null };
  top_senders?: { sender: string; messages: number; size_bytes: number }[];
}

export function parseDoctorCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let quoted = false;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (quoted) {
      if (char === '"') {
        if (text[index + 1] === '"') { field += '"'; index += 1; }
        else quoted = false;
      } else field += char;
    } else if (char === '"') quoted = true;
    else if (char === ',') { row.push(field); field = ''; }
    else if (char === '\n' || char === '\r') {
      if (char === '\r' && text[index + 1] === '\n') index += 1;
      row.push(field);
      if (row.some((value) => value !== '')) rows.push(row);
      row = [];
      field = '';
    } else field += char;
  }
  row.push(field);
  if (row.some((value) => value !== '')) rows.push(row);
  if (rows[0]?.[0]) rows[0][0] = rows[0][0].replace(/^\uFEFF/, '');
  return rows;
}

function originalCsvCell(value: string) {
  return /^'[=+\-@\s\u0000-\u001f\u007f]/u.test(value) ? value.slice(1) : value;
}

function senderDomain(value: string) {
  const domain = value.trim().toLowerCase().replace(/\.$/, '');
  return domain.length <= 253 && domain.split('.').every((part) => part.length <= 63
    && /^[\p{L}\p{N}](?:[\p{L}\p{N}\p{M}-]*[\p{L}\p{N}\p{M}])?$/u.test(part)) ? domain : '';
}

function reportDomains(contents: Record<string, string>) {
  const groups = new Map<string, Set<string>>();
  const add = (group: string, domain: string) => {
    const normalized = senderDomain(domain);
    if (!group || !normalized) return;
    const existing = groups.get(group) || new Set<string>();
    existing.add(normalized);
    groups.set(group, existing);
  };
  try {
    const aliases: unknown = JSON.parse(contents['_domain_aliases.json'] || '{}');
    if (aliases && typeof aliases === 'object' && !Array.isArray(aliases)) {
      Object.entries(aliases).forEach(([domain, group]) => { if (typeof group === 'string') add(group, domain); });
    }
  } catch { /* CSV addresses can still identify the observed sender domains. */ }
  ['report/senders.csv', 'inbox_cleanup_worklist.csv', 'report/unsubscribe.csv'].forEach((path) => {
    const [headers, ...rows] = parseDoctorCsv(contents[path] || '');
    if (!headers) return;
    const groupColumn = headers.indexOf('sender_group');
    if (groupColumn < 0) return;
    const addressColumn = headers.indexOf('addresses');
    const domainColumns = headers.flatMap((header, index) => ['sender_domain', 'sender_domains', 'from_domain'].includes(header) ? [index] : []);
    rows.forEach((row) => {
      const group = originalCsvCell(row[groupColumn] || '');
      domainColumns.forEach((column) => (row[column] || '').split(/[;,|\s]+/).forEach((domain) => add(group, domain)));
      if (addressColumn >= 0) {
        originalCsvCell(row[addressColumn] || '').split(';').forEach((address) => {
          const at = address.lastIndexOf('@');
          if (at >= 0) add(group, address.slice(at + 1).replace(/>$/, ''));
        });
      }
    });
  });
  return new Map(Array.from(groups, ([group, domains]) => [group, Array.from(domains).sort()]));
}

function DomainLinks({ domains, account, onOpenDomain }: {
  domains: string[]; account: string; onOpenDomain?: (account: string, domains: string[]) => void;
}) {
  if (!domains.length) return null;
  return <span className="doctor-domain-links">{domains.map((domain) => <button type="button" className="doctor-domain-link" key={domain} aria-label={`Open inbox for ${domain}`} disabled={!account || !onOpenDomain} onClick={() => { if (account && onOpenDomain) onOpenDomain(account, [domain]); }}>{domain}</button>)}</span>;
}

function CsvPreview({ text, label, domains, account, onOpenDomain }: {
  text: string; label: string; domains: Map<string, string[]>; account: string;
  onOpenDomain?: (account: string, domains: string[]) => void;
}) {
  const [filter, setFilter] = useState('');
  const rows = useMemo(() => parseDoctorCsv(text), [text]);
  const [headers, ...body] = rows;
  const groupColumn = headers?.indexOf('sender_group') ?? -1;
  const query = filter.toLocaleLowerCase();
  const filtered = body.filter((row) => row.some((cell) => cell.toLocaleLowerCase().includes(query))
    || (domains.get(originalCsvCell(row[groupColumn] || '')) || []).some((domain) => domain.includes(query)));
  if (!headers) return <p className="muted">No rows in this report.</p>;
  return <>
    <div className="doctor-table-toolbar"><label className="field"><span className="sr-only">Filter {label}</span><input type="search" placeholder={`Search ${label.toLowerCase()}…`} value={filter} onChange={(event) => setFilter(event.target.value)} /></label><span className="muted doctor-small">{filtered.length.toLocaleString()} {filtered.length === 1 ? 'row' : 'rows'}</span></div>
    <div className="doctor-table-wrap" tabIndex={0} aria-label={`${label} table`}><table><caption className="sr-only">{label}</caption><thead><tr>{headers.map((header, index) => <th key={index} scope="col">{header.replaceAll('_', ' ')}</th>)}</tr></thead><tbody>{filtered.slice(0, 100).map((row, index) => <tr key={index}>{headers.map((header, column) => <td key={column}>{row[column] || '—'}{header === 'sender_group' && <DomainLinks domains={domains.get(originalCsvCell(row[column] || '')) || []} account={account} onOpenDomain={onOpenDomain} />}</td>)}</tr>)}</tbody></table></div>
    {!filtered.length && <p className="muted">No rows match your search.</p>}
    {filtered.length > 100 && <p className="muted doctor-small">Showing the first 100 matches. Download the CSV for every row.</p>}
  </>;
}

function safeReportHtml(html: string) {
  const policy = `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; form-action 'none'; base-uri 'none';">`;
  return /<head\b[^>]*>/i.test(html) ? html.replace(/<head\b[^>]*>/i, (head) => head + policy) : policy + html;
}

type ResultTab = 'overview' | 'briefing' | 'senders' | 'worklist' | 'unsubscribe' | 'html' | 'files';
const tabLabels: Record<ResultTab, string> = { overview: 'Overview', briefing: 'Daily briefing', senders: 'Senders', worklist: 'Cleanup worklist', unsubscribe: 'Unsubscribe', html: 'HTML report', files: 'All files' };
const reportPaths = ['report/summary.json', 'report/summary.md', 'report/email_briefing.md', 'report/senders.csv', 'inbox_cleanup_worklist.csv', 'report/unsubscribe.csv', 'inbox_audit.html', '_domain_aliases.json'];

export default function DoctorResults({ job, accounts = [], selectedAccount = '', onOpenDomain, onUnlock }: {
  job: DoctorJob; accounts?: Account[]; selectedAccount?: string;
  onOpenDomain?: (account: string, domains: string[]) => void; onUnlock?: () => void;
}) {
  const snapshot = job.status !== 'completed';
  const [files, setFiles] = useState<string[]>([]);
  const [contents, setContents] = useState<Record<string, string>>({});
  const [summary, setSummary] = useState<Summary | null>(null);
  const [tab, setTab] = useState<ResultTab>('overview');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [revision, setRevision] = useState(0);
  const [reviewAccount, setReviewAccount] = useState(selectedAccount);
  const mailboxAudit = job.source_kind === 'mailbox' || Boolean(job.account_email);
  const auditAccount = accounts.find((account) => account.email.toLowerCase() === job.account_email?.toLowerCase());
  const uploadAccount = accounts.find((account) => account.email === reviewAccount)
    || accounts.find((account) => account.email === selectedAccount) || accounts[0];
  const inboxAccount = (mailboxAudit ? auditAccount : uploadAccount)?.email || '';
  const domains = useMemo(() => reportDomains(contents), [contents]);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError('');
    const load = async () => {
      try {
        const response = await doctorApi.files(job.id, snapshot);
        const texts = await Promise.allSettled(reportPaths.filter((path) => response.files.includes(path)).map(async (path) => [path, await doctorApi.text(job.id, path, snapshot)] as const));
        if (!active) return;
        const nextContents: Record<string, string> = {};
        const failures: string[] = [];
        texts.forEach((result) => {
          if (result.status === 'fulfilled') nextContents[result.value[0]] = result.value[1];
          else failures.push(doctorError(result.reason));
        });
        setFiles(response.files);
        setContents(nextContents);
        if (nextContents['report/summary.json']) {
          try { setSummary(JSON.parse(nextContents['report/summary.json']) as Summary); }
          catch { setSummary(null); failures.push('The summary JSON could not be read. Other report files are available below.'); }
        } else setSummary(null);
        if (failures.length) setError(failures.join(' '));
      } catch (failure) {
        if (active) setError(doctorError(failure));
      } finally {
        if (active) setLoading(false);
      }
    };
    void load();
    return () => { active = false; };
  }, [job.id, job.snapshot_at, snapshot, revision]);

  const fileUrl = (path: string) => doctorApi.fileUrl(job.id, path, snapshot);
  const pathForTab = { overview: 'report/summary.md', briefing: 'report/email_briefing.md', senders: 'report/senders.csv', worklist: 'inbox_cleanup_worklist.csv', unsubscribe: 'report/unsubscribe.csv', html: 'inbox_audit.html', files: '' }[tab];
  const text = contents[pathForTab] || '';

  return <section className="doctor-results" aria-labelledby="results-title">
    <div className="doctor-results-header"><div><h3 id="results-title">{snapshot ? 'Live audit snapshot' : 'Your audit results'}</h3><p className="muted doctor-small">{snapshot ? 'Partial results refresh as messages arrive.' : 'Explore the report, then download the files you need.'}</p></div>{!snapshot && <a className="btn primary" href={doctorApi.zipUrl(job.id)} download onClick={backendDownloadClick({ fallbackName: 'audit.zip' })}>Download audit ZIP</a>}</div>
    {snapshot && <div className="doctor-info" role="status">This snapshot covers the messages downloaded so far.{job.snapshot_at && <small>Updated {new Date(job.snapshot_at).toLocaleTimeString()}</small>}</div>}
    <div className="doctor-domain-review">
      {!mailboxAudit && accounts.length > 0 && <label className="field"><span>Inbox account</span><select aria-label="Inbox account" value={inboxAccount} onChange={(event) => setReviewAccount(event.target.value)}>{accounts.map((account) => <option key={account.email} value={account.email}>{account.email}</option>)}</select></label>}
      {inboxAccount ? <p className="muted doctor-small"><span>{mailboxAudit ? `Review matching messages in ${inboxAccount}.` : 'Review matching messages in the selected inbox.'}</span> Choose a sender domain to open the inbox. Only messages on the current inbox page will be selected.</p> : <p className="muted doctor-small"><span>{mailboxAudit ? "Unlock this audit's mailbox to review these messages in the inbox." : 'Connect a mailbox to review these domains in its inbox.'}</span> {onUnlock && <button type="button" className="doctor-text-button" onClick={onUnlock}>{mailboxAudit ? 'Connect audit mailbox' : 'Connect mailbox'}</button>}</p>}
    </div>
    {summary && <div className="doctor-stats"><div><strong>{summary.total_messages.toLocaleString()}</strong><span>Messages</span></div><div><strong>{summary.unique_senders.toLocaleString()}</strong><span>Sender groups</span></div><div><strong>{summary.senders_with_unsubscribe.toLocaleString()}</strong><span>Unsubscribe-ready</span></div><div><strong>{summary.total_size_bytes >= 1048576 ? `${(summary.total_size_bytes / 1048576).toFixed(1)} MB` : `${(summary.total_size_bytes / 1024).toFixed(1)} KB`}</strong><span>Total message size</span></div></div>}
    <div className="doctor-result-tabs" aria-label="Audit results">{(Object.keys(tabLabels) as ResultTab[]).map((key) => <button type="button" key={key} className={tab === key ? 'active' : ''} aria-pressed={tab === key} onClick={() => setTab(key)}>{tabLabels[key]}</button>)}</div>
    <div className="doctor-result-pane" aria-label={tabLabels[tab]}>
      {error && <div className="banner error" role="alert">{error} <button type="button" className="doctor-text-button" onClick={() => setRevision((current) => current + 1)}>Retry loading reports</button></div>}
      {loading && !files.length ? <p className="muted" role="status">Loading report files…</p> : <>
        <div className="doctor-pane-heading"><h4>{tabLabels[tab]}</h4>{pathForTab && files.includes(pathForTab) && <a className="doctor-file-link" href={fileUrl(pathForTab)} download onClick={backendDownloadClick({ fallbackName: pathForTab.split('/').pop() })}>Download {pathForTab.endsWith('.csv') ? 'CSV' : pathForTab.endsWith('.md') ? 'Markdown' : 'HTML'}</a>}</div>
        {(tab === 'overview' || tab === 'briefing') && (text ? <pre className="doctor-markdown">{text}</pre> : <p className="muted">{tab === 'briefing' ? 'A daily briefing is generated for audits of connected inboxes.' : 'The summary will appear when this part of the report is ready.'}</p>)}
        {tab === 'overview' && summary?.top_senders && summary.top_senders.length > 0 && <div className="doctor-top-senders"><h4>Most frequent senders</h4>{summary.top_senders.slice(0, 5).map((sender) => <div key={sender.sender}><span>{sender.sender}<DomainLinks domains={domains.get(sender.sender) || []} account={inboxAccount} onOpenDomain={onOpenDomain} /></span><div className="doctor-sender-bar"><span style={{ width: `${Math.max(3, sender.messages / Math.max(1, summary.total_messages) * 100)}%` }} /></div><strong>{sender.messages}</strong></div>)}</div>}
        {(tab === 'senders' || tab === 'worklist' || tab === 'unsubscribe') && (text ? <CsvPreview key={pathForTab} text={text} label={tabLabels[tab]} domains={domains} account={inboxAccount} onOpenDomain={onOpenDomain} /> : <p className="muted">This report is not available yet.</p>)}
        {tab === 'worklist' && <p className="muted doctor-small">Recommendations are for review. Running an audit does not change your mailbox.</p>}
        {tab === 'unsubscribe' && <p className="muted doctor-small">Review the sender and its unsubscribe address before using a link from the downloaded report.</p>}
        {tab === 'html' && (text ? <SandboxFrame className="doctor-report-frame" title="Standalone inbox audit report" srcDoc={safeReportHtml(text)} referrerPolicy="no-referrer" /> : <p className="muted">The standalone HTML report is not available yet.</p>)}
        {tab === 'files' && (files.length ? <ul className="doctor-output-files">{files.map((file) => <li key={file}><span className="mono">{file}</span><a className="doctor-file-link" href={fileUrl(file)} download onClick={backendDownloadClick({ fallbackName: file.split('/').pop() })}>Download<span className="sr-only"> {file}</span></a></li>)}</ul> : <p className="muted">No report files are available yet.</p>)}
      </>}
    </div>
  </section>;
}
