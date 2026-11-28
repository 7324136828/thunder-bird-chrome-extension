import { FormEvent, useState } from 'react';
import { api, ApiError, AuditReport } from '../api';

interface Props {
  onClose: () => void;
  onReport: (report: AuditReport) => void;
}

export default function PasteAudit({ onClose, onReport }: Props) {
  const [content, setContent] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!content.trim()) {
      setError('Paste the raw source of an email first.');
      return;
    }
    setBusy(true);
    setError('');
    try {
      const report = await api.auditEml(content);
      onReport(report);
      onClose();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-label="Audit pasted email">
      <form className="modal compose" onSubmit={submit}>
        <header className="modal-header">
          <h2>Audit a raw email</h2>
          <button className="icon-btn" type="button" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </header>
        <p className="muted">
          Paste the full RFC 822 source of a message (headers + body). No mailbox
          connection is needed.
        </p>
        <label className="field grow">
          <span>Raw message</span>
          <textarea
            value={content}
            onChange={(e) => setContent(e.target.value)}
            rows={16}
            placeholder={'Received: from …\nFrom: …\nSubject: …\n\n…'}
            spellCheck={false}
          />
        </label>
        {error && <div className="banner error">{error}</div>}
        <footer className="button-row">
          <button className="btn" type="button" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button className="btn primary" type="submit" disabled={busy}>
            {busy ? 'Auditing…' : 'Audit'}
          </button>
        </footer>
      </form>
    </div>
  );
}
