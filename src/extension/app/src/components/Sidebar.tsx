import { Account, Folder } from '../api';
import { isPop3Account, POP3_COMPAT_NOTE } from '../platform/mailProtocol';

const FOLDER_ICONS: Record<string, string> = {
  inbox: '📥',
  sent: '📤',
  drafts: '📝',
  trash: '🗑',
  junk: '🚫',
  archive: '🗄',
  flagged: '⭐',
  all: '📚',
};

interface Props {
  accounts: Account[];
  selectedAccount: string;
  folders: Folder[];
  selectedFolder: string;
  onSelectAccount: (email: string) => void;
  onSelectFolder: (name: string) => void;
  onCompose: () => void;
  onAddAccount: () => void;
  onLock: (email: string) => void;
  onAuditPaste: () => void;
  workspace: 'mail' | 'doctor' | 'metrics';
  onWorkspace: (workspace: 'mail' | 'doctor' | 'metrics') => void;
  onSettings: () => void;
  onConfigureAccount: (email: string) => void;
  deleting: boolean;
}

export default function Sidebar({
  accounts,
  selectedAccount,
  folders,
  selectedFolder,
  onSelectAccount,
  onSelectFolder,
  onCompose,
  onAddAccount,
  onLock,
  onAuditPaste,
  workspace,
  onWorkspace,
  onSettings,
  onConfigureAccount,
  deleting,
}: Props) {
  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <h1 className="app-title">Webmail</h1>
        <button className="btn primary block" type="button" onClick={onCompose} disabled={!selectedAccount || deleting}>
          ✉ Compose
        </button>
      </div>

      <nav className="sidebar-section workspace-navigation" aria-label="Application workspace">
        <button className={`folder-item ${workspace === 'mail' ? 'active' : ''}`} type="button" onClick={() => onWorkspace('mail')} aria-pressed={workspace === 'mail'} disabled={deleting}>
          <span aria-hidden="true">✉</span><span>Mail</span>
        </button>
        <button className={`folder-item ${workspace === 'doctor' ? 'active' : ''}`} type="button" onClick={() => onWorkspace('doctor')} aria-pressed={workspace === 'doctor'} disabled={deleting}>
          <span aria-hidden="true">◎</span><span>Inbox Doctor</span>
        </button>
        <button className={`folder-item ${workspace === 'metrics' ? 'active' : ''}`} type="button" onClick={() => onWorkspace('metrics')} aria-pressed={workspace === 'metrics'} disabled={deleting}>
          <span aria-hidden="true">▥</span><span>Email Metrics</span>
        </button>
        <button className="folder-item" type="button" onClick={onSettings} disabled={deleting}>Settings</button>
      </nav>

      <section className="sidebar-section">
        <h2>Accounts</h2>
        <ul className="account-list">
          {accounts.map((account) => (
            <li key={account.email}>
              <button
                type="button"
                className={`account-item ${account.email === selectedAccount ? 'active' : ''}`}
                disabled={deleting}
                onClick={() => onSelectAccount(account.email)}
                title={`${account.incoming_server}:${account.incoming_port}`}
              >
                <span className="account-email">{account.email}</span>
                {account.display_name && (
                  <span className="account-name">{account.display_name}</span>
                )}
                {isPop3Account(account) && (
                  <span className="account-name" title={POP3_COMPAT_NOTE}>POP3 · Inbox only</span>
                )}
              </button>
              <button type="button" className="icon-btn" aria-label={`Configure ${account.email}`} title="Account configuration" disabled={deleting} onClick={() => onConfigureAccount(account.email)}>
                ⚙
              </button>
              <button
                type="button"
                className="icon-btn"
                title="Lock account (forget password)"
                disabled={deleting}
                onClick={() => onLock(account.email)}
              >
                🔒
              </button>
            </li>
          ))}
        </ul>
        <button className="btn subtle block" type="button" onClick={onAddAccount} disabled={deleting}>
          + Add account
        </button>
      </section>

      {selectedAccount && (
        <section className="sidebar-section grow">
          <h2>Folders</h2>
          <ul className="folder-list">
            {folders
              .filter((f) => f.selectable)
              .map((folder) => (
                <li key={folder.name}>
                  <button
                    type="button"
                    className={`folder-item ${folder.name === selectedFolder ? 'active' : ''}`}
                    disabled={deleting}
                    onClick={() => onSelectFolder(folder.name)}
                  >
                    <span className="folder-icon">{FOLDER_ICONS[folder.special] ?? '📁'}</span>
                    <span className="folder-name">{folder.name}</span>
                  </button>
                </li>
              ))}
            {folders.length === 0 && <li className="muted">Loading folders…</li>}
          </ul>
        </section>
      )}

      <div className="sidebar-footer">
        <button className="btn subtle block" type="button" onClick={onAuditPaste}>
          🔍 Audit pasted .eml
        </button>
      </div>
    </aside>
  );
}
