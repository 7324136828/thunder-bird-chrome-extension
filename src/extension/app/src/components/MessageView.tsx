import { api, FullMessage, RetentionUpdate } from '../api';
import { backendDownloadClick } from '../platform/downloads';
import EmailHtml from './EmailHtml';
import MessageRetention from './MessageRetention';

interface Props {
  account: string;
  folder: string;
  message: FullMessage | null;
  loading: boolean;
  deleting: boolean;
  onAudit: () => void;
  onReply: (message: FullMessage) => void;
  onForward: (message: FullMessage) => void;
  onMailto: (url: string) => void;
  onDelete: (uid: number) => void;
  onToggleSeen: (uid: number, seen: boolean) => void;
  onToggleFlag: (uid: number, flagged: boolean) => void;
  retentionSaving: boolean;
  onRetentionUpdate: (update: RetentionUpdate) => void;
  classificationBusy: boolean;
  classifying: boolean;
  settingsLoaded: boolean;
  onClassify: () => void;
  senderRuleBusy: boolean;
  senderRuleSaving: boolean;
  onSaveSenderRule: () => void;
  onRemoveSenderRule: () => void;
  /**
   * Extension: POP3 compatibility account. Flag, read-state and delete
   * actions are hidden because the backend refuses them for POP3 (400).
   */
  pop3?: boolean;
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

export default function MessageView({
  account,
  folder,
  message,
  loading,
  deleting,
  onAudit,
  onReply,
  onForward,
  onMailto,
  onDelete,
  onToggleSeen,
  onToggleFlag,
  retentionSaving,
  onRetentionUpdate,
  classificationBusy,
  classifying,
  settingsLoaded,
  onClassify,
  senderRuleBusy,
  senderRuleSaving,
  onSaveSenderRule,
  onRemoveSenderRule,
  pop3 = false,
}: Props) {
  if (loading) {
    return (
      <section className="message-view">
        <p className="muted empty-state">Loading message…</p>
      </section>
    );
  }
  if (!message) {
    return (
      <section className="message-view">
        <p className="muted empty-state">Select a message to read it.</p>
      </section>
    );
  }

  const sender = message.from_name
    ? `${message.from_name} <${message.from_addr}>`
    : message.from_addr;
  const date = message.date ? new Date(message.date).toLocaleString() : '';

  return (
    <section className="message-view">
      <header className="message-header">
        <h2 className="message-subject">{message.subject || '(no subject)'}</h2>
        <div className="message-meta">
          <div>
            <span className="meta-label">From:</span> {sender}
          </div>
          <div>
            <span className="meta-label">To:</span> {message.to}
          </div>
          {message.cc && (
            <div>
              <span className="meta-label">Cc:</span> {message.cc}
            </div>
          )}
          <div>
            <span className="meta-label">Date:</span> {date}
            {message.message_id && (
              <span className="muted mono"> · {message.message_id}</span>
            )}
          </div>
        </div>
        <div className="message-actions">
          <button className="btn subtle" type="button" disabled={deleting} onClick={() => onReply(message)}>
            ↩ Reply
          </button>
          <button className="btn subtle" type="button" disabled={deleting} onClick={() => onForward(message)}>
            ↪ Forward
          </button>
          <button className="btn subtle" type="button" disabled={deleting} onClick={onAudit}>
            🔍 Audit
          </button>
          <button
            className="btn subtle"
            type="button"
            disabled={deleting || classificationBusy || senderRuleBusy || !message.uid_validity || !settingsLoaded}
            onClick={onClassify}
            title="Classify this email using the local AI model configured in Settings. Replaces its category and keeps any individual expiration."
          >
            {classifying ? 'Classifying...' : 'Auto classification'}
          </button>
          {!pop3 && <button
            className="btn subtle"
            type="button"
            disabled={deleting}
            onClick={() => onToggleFlag(message.uid, !message.flagged)}
          >
            {message.flagged ? '★ Unflag' : '☆ Flag'}
          </button>}
          {!pop3 && <button
            className="btn subtle"
            type="button"
            disabled={deleting}
            onClick={() => onToggleSeen(message.uid, !message.seen)}
          >
            {message.seen ? 'Mark unread' : 'Mark read'}
          </button>}
          <a
            className="btn subtle"
            href={api.messageEmlUrl(account, folder, message.uid)}
            download
            onClick={backendDownloadClick({ fallbackName: `message-${message.uid}.eml` })}
          >
            ⬇ .eml
          </a>
          {!pop3 && <button
            className="btn danger"
            type="button"
            disabled={deleting || classificationBusy || senderRuleBusy}
            onClick={() => onDelete(message.uid)}
          >
            🗑 Delete
          </button>}
        </div>
        <MessageRetention key={JSON.stringify([account, folder, message.uid])} message={message} folder={folder} busy={deleting || retentionSaving || classificationBusy || senderRuleBusy} saving={retentionSaving} onUpdate={onRetentionUpdate} senderRuleSaving={senderRuleSaving} onSaveSenderRule={onSaveSenderRule} onRemoveSenderRule={onRemoveSenderRule} />
        {classifying && <p className="muted" role="status">Classifying this email with the local model. This may take a minute.</p>}
        {!settingsLoaded && <p className="muted">Load your saved settings before using AI classification.</p>}
      </header>

      <div className="message-body">
        {message.html_body ? (
          <EmailHtml
            key={JSON.stringify([account, folder, message.uid, message.html_body])}
            account={account}
            folder={folder}
            uid={message.uid}
            html={message.html_body}
            onMailto={onMailto}
          />
        ) : (
          <pre className="text-body">{message.text_body || '(empty message)'}</pre>
        )}
      </div>

      {message.attachments.length > 0 && (
        <footer className="message-attachments">
          <h3>Attachments ({message.attachments.length})</h3>
          <ul>
            {message.attachments.map((attachment) => (
              <li key={attachment.index}>
                <a
                  href={api.attachmentUrl(account, folder, message.uid, attachment.index)}
                  download
                  onClick={backendDownloadClick({ fallbackName: attachment.filename })}
                >
                  📎 {attachment.filename}
                </a>
                <span className="muted">
                  {attachment.content_type} · {formatSize(attachment.size)}
                </span>
              </li>
            ))}
          </ul>
        </footer>
      )}
    </section>
  );
}
