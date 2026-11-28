import { useEffect, useRef, useState } from 'react';
import { Account } from '../api';
import { DoctorJob, MailDiscovery, doctorApi, doctorError } from '../doctorApi';

const providerName = { google: 'Google', microsoft: 'Microsoft', credentials: 'IMAP' };

interface Props {
  accounts: Account[];
  selectedAccount: string;
  onCreated: (job: DoctorJob) => void;
  onOpenJob: (id: string) => void;
  onUnlock: () => void;
}

export default function DoctorConnect({ accounts, selectedAccount, onCreated, onOpenJob, onUnlock }: Props) {
  const [mode, setMode] = useState<'account' | 'connect'>(accounts.length ? 'account' : 'connect');
  const [account, setAccount] = useState(selectedAccount || accounts[0]?.email || '');
  const [days, setDays] = useState('7');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [discovery, setDiscovery] = useState<MailDiscovery | null>(null);
  const [server, setServer] = useState('');
  const [port, setPort] = useState('993');
  const [ssl, setSsl] = useState(true);
  const [appPassword, setAppPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [discovering, setDiscovering] = useState(false);
  const [waiting, setWaiting] = useState(false);
  const [error, setError] = useState('');
  const popup = useRef<Window | null>(null);
  const expectedOrigin = useRef('');
  const discoveryVersion = useRef(0);

  useEffect(() => {
    if (selectedAccount) setAccount(selectedAccount);
    else setAccount((current) => accounts.some((item) => item.email === current) ? current : accounts[0]?.email || '');
  }, [selectedAccount, accounts]);

  useEffect(() => {
    const receive = (event: MessageEvent) => {
      if (!popup.current || event.source !== popup.current || !expectedOrigin.current || event.origin !== expectedOrigin.current) return;
      const data = event.data as { type?: string; jobId?: string; error?: string } | null;
      if (data?.type !== 'email-doctor-oauth') return;
      popup.current?.close();
      popup.current = null;
      expectedOrigin.current = '';
      setBusy(false);
      setWaiting(false);
      if (data.error) setError(data.error);
      if (data.jobId) onOpenJob(data.jobId);
    };
    window.addEventListener('message', receive);
    return () => { window.removeEventListener('message', receive); popup.current?.close(); };
  }, [onOpenJob]);

  useEffect(() => {
    if (!waiting) return;
    const timer = window.setInterval(() => {
      if (popup.current?.closed) {
        popup.current = null;
        expectedOrigin.current = '';
        setWaiting(false);
        setBusy(false);
        setError('The sign-in window closed. You can try connecting again.');
      }
    }, 800);
    return () => window.clearInterval(timer);
  }, [waiting]);

  const discover = async () => {
    const address = email.trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(address)) throw new Error('Enter a valid email address.');
    const version = ++discoveryVersion.current;
    setDiscovering(true);
    try {
      const info = await doctorApi.discover(address);
      if (version !== discoveryVersion.current) throw new Error('The email address changed. Detect its provider again.');
      setDiscovery(info);
      setServer(info.imap_server);
      setPort(String(info.imap_port));
      setSsl(info.use_ssl);
      setAppPassword(info.provider === 'google' && !info.oauth_configured);
      return info;
    } finally {
      if (version === discoveryVersion.current) setDiscovering(false);
    }
  };

  const start = async () => {
    setError('');
    const dayCount = Number(days);
    if (!Number.isInteger(dayCount) || dayCount < 1 || dayCount > 3650) {
      setError('Choose a whole number of days between 1 and 3650.');
      return;
    }
    setBusy(true);
    let oauthPending = false;
    try {
      if (mode === 'account') {
        if (!account) throw new Error('Select an unlocked mail account first.');
        onCreated(await doctorApi.account(account, dayCount));
        return;
      }
      const info = discovery ?? await discover();
      const wantsOAuth = info.provider !== 'credentials' && !(info.provider === 'google' && appPassword);
      if (wantsOAuth) {
        if (!info.oauth_configured) throw new Error(`${providerName[info.provider]} sign-in is not configured. ${info.provider === 'google' ? 'Choose a Google app password, or configure OAuth for this application.' : 'Configure Microsoft OAuth for this application to connect.'}`);
        popup.current = window.open('about:blank', 'inbox-doctor-sign-in', 'width=600,height=720');
        if (!popup.current) throw new Error('Allow the sign-in pop-up, then try again.');
        const started = await doctorApi.oauth(info.provider, email.trim(), dayCount);
        expectedOrigin.current = new URL(started.message_origin).origin;
        popup.current.location.href = started.authorization_url;
        oauthPending = true;
        setWaiting(true);
      } else {
        if (!password) throw new Error('Enter your mailbox password or provider app password.');
        const imapPort = Number(port);
        if (!server.trim() || !Number.isInteger(imapPort) || imapPort < 1 || imapPort > 65535) throw new Error('Enter an IMAP server and a valid port.');
        onCreated(await doctorApi.connect({ email: email.trim(), password, days: dayCount, imap_server: server.trim(), imap_port: imapPort, use_ssl: ssl, use_app_password: info.provider === 'google' }));
        setPassword('');
      }
    } catch (failure) {
      popup.current?.close();
      popup.current = null;
      setError(doctorError(failure));
    } finally {
      if (!oauthPending) setBusy(false);
    }
  };

  const oauth = discovery && discovery.provider !== 'credentials' && !(discovery.provider === 'google' && appPassword);
  const blocked = oauth && !discovery.oauth_configured;

  return <section className="doctor-card" aria-labelledby="inbox-title">
    <div className="doctor-card-heading"><span className="doctor-step">02</span><div><h2 id="inbox-title">Audit recent INBOX mail</h2><p className="muted">Get a daily briefing and cleanup recommendations from your recent messages.</p></div></div>
    <div className="doctor-segmented" aria-label="Mailbox connection">
      <button type="button" className={mode === 'account' ? 'active' : ''} aria-pressed={mode === 'account'} disabled={busy} onClick={() => { setMode('account'); setError(''); }}>Unlocked account</button>
      <button type="button" className={mode === 'connect' ? 'active' : ''} aria-pressed={mode === 'connect'} disabled={busy} onClick={() => { setMode('connect'); setError(''); }}>Connect another inbox</button>
    </div>
    <div className="form-grid">
      {mode === 'account' ? <label className="field field-wide"><span>Mail account</span><select value={account} onChange={(event) => setAccount(event.target.value)} disabled={!accounts.length || busy}><option value="" disabled>Select an unlocked account</option>{accounts.map((item) => <option key={item.email} value={item.email}>{item.email}</option>)}</select>{!accounts.length && <small>No unlocked accounts yet. <button type="button" className="doctor-text-button" onClick={onUnlock}>Add a mail account</button></small>}</label> : <>
        <label className="field field-wide"><span>Email address</span><div className="doctor-inline-field"><input type="email" autoComplete="username" value={email} placeholder="you@example.com" disabled={busy} onChange={(event) => { setEmail(event.target.value); setDiscovery(null); setPassword(''); ++discoveryVersion.current; setDiscovering(false); }} /><button type="button" className="btn" disabled={busy || discovering || !email.trim()} onClick={() => { setError(''); void discover().catch((failure) => setError(doctorError(failure))); }}>{discovering ? 'Detecting…' : 'Detect provider'}</button></div></label>
        {discovery && <div className="doctor-provider-note field-wide"><strong>{providerName[discovery.provider]} connection</strong><span className="mono">{discovery.imap_server}:{discovery.imap_port}</span></div>}
        {discovery?.provider === 'google' && <fieldset className="doctor-auth-method field-wide"><legend>Google authentication</legend><label className="check-field"><input type="radio" name="doctor-google-auth" checked={!appPassword} disabled={!discovery.oauth_configured || busy} onChange={() => setAppPassword(false)} />Google sign-in {discovery.oauth_configured ? '' : '(unavailable)'}</label><label className="check-field"><input type="radio" name="doctor-google-auth" checked={appPassword} disabled={busy} onChange={() => setAppPassword(true)} />Google app password</label></fieldset>}
        {discovery && !oauth && <label className="field field-wide"><span>{discovery.provider === 'google' ? 'Google app password' : 'Password / app password'}</span><input type="password" autoComplete="current-password" value={password} disabled={busy} onChange={(event) => setPassword(event.target.value)} /><small>{discovery.provider === 'google' ? 'Use the 16-character app password from your Google account. Spaces are accepted.' : 'The password is used only for this audit connection.'}</small></label>}
        {blocked && <div className="doctor-info field-wide" role="status"><strong>{providerName[discovery.provider]} sign-in needs configuration.</strong><span>{discovery.provider === 'google' ? 'You can choose a Google app password above.' : 'Ask the application administrator to configure Microsoft sign-in.'}</span>{discovery.oauth_callback_url && <details><summary>Connection callback URL</summary><code>{discovery.oauth_callback_url}</code></details>}</div>}
      </>}
      <label className="field"><span>Look back (days)</span><input type="number" min="1" max="3650" step="1" value={days} disabled={busy} onChange={(event) => setDays(event.target.value)} /></label>
      <div className="doctor-readonly-note"><span className="doctor-dot" />Read-only audit<small>Messages stay unread. No mail is moved or deleted.</small></div>
    </div>
    {mode === 'connect' && discovery && !oauth && <details><summary>Advanced IMAP settings</summary><div className="form-grid"><label className="field field-wide"><span>IMAP server</span><input value={server} disabled={busy} onChange={(event) => setServer(event.target.value)} /></label><label className="field"><span>Port</span><input type="number" min="1" max="65535" value={port} disabled={busy} onChange={(event) => setPort(event.target.value)} /></label><label className="check-field"><input type="checkbox" checked={ssl} disabled={busy} onChange={(event) => setSsl(event.target.checked)} />SSL/TLS at connection start</label></div></details>}
    {error && <div className="banner error" role="alert">{error}</div>}
    {waiting && <div className="doctor-info" role="status">Complete sign-in in the provider window.<button type="button" className="doctor-text-button" onClick={() => { popup.current?.close(); popup.current = null; expectedOrigin.current = ''; setBusy(false); setWaiting(false); }}>Cancel sign-in</button></div>}
    <div className="doctor-card-footer"><span className="muted doctor-small">Includes sender statistics and daily briefing.</span><button type="button" className="btn primary" disabled={busy || discovering || !days || (mode === 'account' ? !account : !email.trim() || Boolean(blocked))} onClick={() => void start()}>{busy ? waiting ? 'Waiting for sign-in…' : 'Starting audit…' : oauth ? `Continue with ${providerName[discovery.provider]}` : 'Start INBOX audit'}</button></div>
  </section>;
}
