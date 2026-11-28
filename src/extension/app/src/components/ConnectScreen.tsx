import { useEffect, useRef, useState } from 'react';
import { api, ApiError, ServerProfile } from '../api';
import { defaultIncomingPort, DEFAULT_INCOMING_PORTS, POP3_COMPAT_NOTE, portAfterProtocolChange } from '../platform/mailProtocol';

interface Props {
  /** When set, only the password is requested to re-unlock this account. */
  relockEmail?: string;
  onUnlocked: () => void;
  onCancel?: () => void;
}

const PROTOCOLS = ['SSL/TLS', 'STARTTLS', 'NONE'];
// Extension (Rust backend): POP3 compatibility mode. '' leaves the choice to
// the backend (the matching profile, else IMAP).
const MAIL_PROTOCOLS = [
  { value: 'imap', label: 'IMAP' },
  { value: 'pop3', label: 'POP3 (Inbox only: read and download)' },
];

function savedDisplayName(
  email: string,
  names: Record<string, string>,
  profiles: Record<string, ServerProfile>,
  selected?: ServerProfile,
) {
  const address = email.trim().toLowerCase();
  if (Object.prototype.hasOwnProperty.call(names, address)) return names[address];
  if (selected?.email_address && selected.email_address.trim().toLowerCase() === address) {
    return selected.display_name || '';
  }
  const exact = Object.values(profiles).find((profile) =>
    profile.email_address && profile.email_address.trim().toLowerCase() === address,
  );
  if (exact) return exact.display_name || '';
  if (selected && (!selected.email_address || selected.email_address.trim().toLowerCase() === address)) {
    return selected.display_name || '';
  }
  return '';
}

export default function ConnectScreen({ relockEmail, onUnlocked, onCancel }: Props) {
  const [profiles, setProfiles] = useState<Record<string, ServerProfile>>({});
  const [displayNames, setDisplayNames] = useState<Record<string, string>>({});
  const [profilesPath, setProfilesPath] = useState('');
  const [profileKey, setProfileKey] = useState('');
  const [email, setEmail] = useState(relockEmail ?? '');
  const [displayName, setDisplayName] = useState('');
  const [password, setPassword] = useState('');
  const [incoming, setIncoming] = useState({ server: '', port: 993, protocol: 'SSL/TLS' });
  const [outgoing, setOutgoing] = useState({ server: '', port: 587, protocol: 'STARTTLS' });
  const [mailProtocol, setMailProtocol] = useState('');
  const [saveProfile, setSaveProfile] = useState(false);
  const [advanced, setAdvanced] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const currentEmail = useRef(email);
  const fieldsEdited = useRef(false);
  const nameEdited = useRef(false);

  useEffect(() => {
    api
      .servers()
      .then((data) => {
        setProfiles(data.servers);
        const names = data.display_names ?? {};
        setDisplayNames(names);
        setProfilesPath(data.path);
        if (data.display_names_error) setError(data.display_names_error);
        const first = Object.keys(data.servers)[0];
        if (!relockEmail && !fieldsEdited.current && first) {
          applyProfile(first, data.servers[first], names, data.servers);
        } else if (!relockEmail && !nameEdited.current) {
          setDisplayName(savedDisplayName(currentEmail.current, names, data.servers));
        }
      })
      .catch((e) => setError(e.message));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const applyProfile = (
    key: string,
    profile?: ServerProfile,
    names = displayNames,
    availableProfiles = profiles,
  ) => {
    const p = profile ?? profiles[key];
    setProfileKey(key);
    if (!p) return;
    const address = p.email_address && !relockEmail ? p.email_address : currentEmail.current;
    if (p.email_address && !relockEmail) {
      currentEmail.current = address;
      setEmail(address);
    }
    nameEdited.current = false;
    setDisplayName(savedDisplayName(address, names, availableProfiles, p));
    setIncoming({
      server: p.incoming_server,
      port: p.incoming_port,
      protocol: p.incoming_protocol || 'SSL/TLS',
    });
    setOutgoing({
      server: p.outgoing_server,
      port: p.outgoing_port,
      protocol: p.outgoing_protocol || 'STARTTLS',
    });
    setMailProtocol((p.incoming_mail_protocol || '').toLowerCase());
  };

  // Extension: follow the default port (993/143 IMAP, 995/110 POP3) when the
  // protocol or security changes, unless the user typed another port.
  const changeMailProtocol = (next: string) => {
    setIncoming({ ...incoming, port: portAfterProtocolChange(incoming.port, mailProtocol, next) });
    setMailProtocol(next);
  };

  const changeIncomingSecurity = (security: string) => {
    const defaults = DEFAULT_INCOMING_PORTS[mailProtocol === 'pop3' ? 'pop3' : 'imap'];
    const isDefault = incoming.port === defaults.tls || incoming.port === defaults.plain;
    setIncoming({ ...incoming, protocol: security, port: isDefault ? defaultIncomingPort(mailProtocol, security) : incoming.port });
  };

  const submit = async () => {
    setError('');
    if (!email.includes('@')) {
      setError('Enter a valid email address.');
      return;
    }
    if (!password) {
      setError('Enter the mailbox password.');
      return;
    }
    setBusy(true);
    try {
      // Re-unlocking shows no server fields: let the backend use the saved
      // profile instead of overriding it with this form's untouched defaults
      // (port 993 / SSL/TLS would break STARTTLS and POP3 profiles).
      const servers = relockEmail ? {} : {
        incoming_server: incoming.server || undefined,
        incoming_port: incoming.port || undefined,
        incoming_protocol: incoming.protocol || undefined,
        outgoing_server: outgoing.server || undefined,
        outgoing_port: outgoing.port || undefined,
        outgoing_protocol: outgoing.protocol || undefined,
        incoming_mail_protocol: mailProtocol || undefined,
      };
      await api.unlock({
        email: email.trim(),
        password,
        profile_key: profileKey || undefined,
        display_name: !relockEmail && (nameEdited.current || displayName.trim()) ? displayName.trim() : undefined,
        ...servers,
        save_profile: saveProfile,
      });
      setPassword('');
      onUnlocked();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="connect-card">
      <h2>{relockEmail ? 'Re-enter password' : 'Connect a mailbox'}</h2>
      <p className="muted">
        The password is kept <strong>in memory only</strong> and is requested again
        whenever the backend restarts.
      </p>

      {!relockEmail && (
        <label className="field">
          <span>Server profile</span>
          <select
            value={profileKey}
            onChange={(e) => {
              fieldsEdited.current = true;
              if (e.target.value) applyProfile(e.target.value);
              else setProfileKey('');
            }}
          >
            <option value="">Custom / manual</option>
            {Object.keys(profiles).map((key) => (
              <option key={key} value={key}>
                {key}
              </option>
            ))}
          </select>
          {profilesPath && (
            <small className="muted">Profiles: {profilesPath}</small>
          )}
        </label>
      )}

      <div className="form-grid">
        {!relockEmail && (
          <>
            <label className="field">
              <span>Email address</span>
              <input
                type="email"
                autoComplete="username"
                value={email}
                onChange={(e) => {
                  const address = e.target.value;
                  currentEmail.current = address;
                  fieldsEdited.current = true;
                  nameEdited.current = false;
                  setEmail(address);
                  setDisplayName(savedDisplayName(address, displayNames, profiles, profiles[profileKey]));
                }}
                placeholder="you@example.com"
              />
            </label>
            <label className="field">
              <span>Display name (optional)</span>
              <input
                value={displayName}
                onChange={(e) => {
                  fieldsEdited.current = true;
                  nameEdited.current = true;
                  setDisplayName(e.target.value);
                }}
                placeholder="Your name"
              />
              <small className="muted">Display name is saved for this email address.</small>
            </label>
          </>
        )}
        <label className="field field-wide">
          <span>Password</span>
          <input
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && submit()}
          />
          <small className="muted">Verified against the {mailProtocol === 'pop3' ? 'POP3' : 'IMAP'} server, then cached in memory.</small>
        </label>
      </div>

      {!relockEmail && (
        <>
          <details open={advanced} onToggle={(e) => setAdvanced(e.currentTarget.open)}>
            <summary>Advanced server settings</summary>
            <div className="form-grid advanced-grid">
              <label className="field field-wide">
                <span>Incoming mail protocol</span>
                <select
                  value={mailProtocol || 'imap'}
                  onChange={(e) => changeMailProtocol(e.target.value)}
                >
                  {MAIL_PROTOCOLS.map((p) => (
                    <option key={p.value} value={p.value}>{p.label}</option>
                  ))}
                </select>
                {mailProtocol === 'pop3' && (
                  <small className="muted">{POP3_COMPAT_NOTE} Sending uses SMTP as usual.</small>
                )}
              </label>
              <label className="field">
                <span>{mailProtocol === 'pop3' ? 'POP3 server' : 'IMAP server'}</span>
                <input
                  value={incoming.server}
                  onChange={(e) => setIncoming({ ...incoming, server: e.target.value })}
                />
              </label>
              <label className="field">
                <span>Port</span>
                <input
                  type="number"
                  value={incoming.port}
                  onChange={(e) => setIncoming({ ...incoming, port: Number(e.target.value) })}
                />
              </label>
              <label className="field">
                <span>Security</span>
                <select
                  value={incoming.protocol}
                  onChange={(e) => changeIncomingSecurity(e.target.value)}
                >
                  {PROTOCOLS.map((p) => (
                    <option key={p}>{p}</option>
                  ))}
                </select>
              </label>
              <label className="field">
                <span>SMTP server</span>
                <input
                  value={outgoing.server}
                  onChange={(e) => setOutgoing({ ...outgoing, server: e.target.value })}
                />
              </label>
              <label className="field">
                <span>Port</span>
                <input
                  type="number"
                  value={outgoing.port}
                  onChange={(e) => setOutgoing({ ...outgoing, port: Number(e.target.value) })}
                />
              </label>
              <label className="field">
                <span>Security</span>
                <select
                  value={outgoing.protocol}
                  onChange={(e) => setOutgoing({ ...outgoing, protocol: e.target.value })}
                >
                  {PROTOCOLS.map((p) => (
                    <option key={p}>{p}</option>
                  ))}
                </select>
              </label>
            </div>
          </details>
          <label className="check-field">
            <input
              type="checkbox"
              checked={saveProfile}
              onChange={(e) => setSaveProfile(e.target.checked)}
            />
            Save these server settings as a profile (never the password)
          </label>
        </>
      )}

      {error && <div className="banner error">{error}</div>}
      <div className="button-row">
        {onCancel && (
          <button className="btn" type="button" onClick={onCancel} disabled={busy}>
            Cancel
          </button>
        )}
        <button className="btn primary" type="button" onClick={submit} disabled={busy}>
          {busy ? 'Checking…' : relockEmail ? 'Unlock' : 'Connect'}
        </button>
      </div>
    </div>
  );
}
