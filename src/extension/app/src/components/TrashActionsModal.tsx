import { useEffect, useRef, useState } from 'react';
import { api, ApiError, TrashEmptyResult, TrashPreparation } from '../api';
import { backendDownloadClick } from '../platform/downloads';

interface Props {
  account: string;
  folder: string;
  archive: boolean;
  onClose: () => void;
  onEmptied: (result: TrashEmptyResult) => void;
}

function errorMessage(failure: unknown): string {
  if (failure instanceof ApiError && typeof failure.detail === 'object' && failure.detail !== null) {
    const detail = failure.detail as Record<string, unknown>;
    if (failure.passwordRequired) return 'Your account is locked. Close this dialog and unlock the account, then try again.';
    const message = typeof detail.message === 'string' ? detail.message :
      typeof detail.detail === 'string' ? detail.detail : failure.message;
    if (typeof detail.deleted === 'number' && typeof detail.remaining === 'number') {
      return `${message} ${detail.deleted} emails deleted; ${detail.remaining} remain in Trash.`;
    }
    return message;
  }
  return failure instanceof Error ? failure.message : String(failure);
}

export default function TrashActionsModal({ account, folder, archive, onClose, onEmptied }: Props) {
  const [operation, setOperation] = useState<TrashPreparation | null>(null);
  const [preparing, setPreparing] = useState(true);
  const [emptying, setEmptying] = useState(false);
  const [downloadStarted, setDownloadStarted] = useState(false);
  const [savedArchive, setSavedArchive] = useState(false);
  const [result, setResult] = useState<TrashEmptyResult | null>(null);
  const [error, setError] = useState('');
  const [preparationAttempt, setPreparationAttempt] = useState(0);
  const dialogRef = useRef<HTMLElement>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const onCloseRef = useRef(onClose);
  const emptyingRef = useRef(false);
  onCloseRef.current = onClose;
  emptyingRef.current = emptying;

  useEffect(() => {
    let active = true;
    let operationId: string | null = null;
    setPreparing(true);
    setError('');
    void (async () => {
      // Avoid preparing a duplicate archive during React's development effect check.
      await Promise.resolve();
      if (!active) return;
      try {
        const prepared = await api.prepareTrash(account, folder, archive);
        operationId = prepared.operation_id;
        if (!active) {
          void api.discardTrash(account, prepared.operation_id).catch(() => undefined);
          return;
        }
        setOperation(prepared);
      } catch (failure) {
        if (active) setError(errorMessage(failure));
      } finally {
        if (active) setPreparing(false);
      }
    })();
    return () => {
      active = false;
      if (operationId) void api.discardTrash(account, operationId).catch(() => undefined);
    };
  }, [account, folder, archive, preparationAttempt]);

  useEffect(() => {
    const previousFocus = document.activeElement;
    headingRef.current?.focus();
    const keydown = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !emptyingRef.current) {
        event.preventDefault();
        onCloseRef.current();
      }
      if (event.key !== 'Tab' || !dialogRef.current) return;
      const controls = Array.from(dialogRef.current.querySelectorAll<HTMLElement>(
        'button:not([disabled]), a[href]:not([aria-disabled="true"]), input:not([disabled])',
      ));
      const first = controls[0];
      const last = controls[controls.length - 1];
      if (!first || !last) {
        event.preventDefault();
      } else if (event.shiftKey && (document.activeElement === first || document.activeElement === headingRef.current)) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener('keydown', keydown);
    return () => {
      document.removeEventListener('keydown', keydown);
      if (previousFocus instanceof HTMLElement && previousFocus.isConnected) previousFocus.focus();
    };
  }, []);

  const empty = async () => {
    if (!operation || preparing || emptyingRef.current || result || operation.count === 0 || (archive && !savedArchive)) return;
    emptyingRef.current = true;
    setEmptying(true);
    setError('');
    try {
      const emptied = await api.emptyTrash(account, operation.operation_id);
      setResult(emptied);
      onEmptied(emptied);
    } catch (failure) {
      setError(errorMessage(failure));
    } finally {
      emptyingRef.current = false;
      setEmptying(false);
    }
  };

  const title = archive ? 'Archive and empty' : 'Empty trash bin';
  const hasArchive = archive && operation !== null && operation.count > 0 && operation.filename !== null;

  return <div className="modal-backdrop">
    <section ref={dialogRef} className="modal trash-modal" role="dialog" aria-modal="true" aria-labelledby="trash-actions-title" aria-describedby="trash-actions-description">
      <div className="modal-header">
        <h2 ref={headingRef} id="trash-actions-title" tabIndex={-1}>{title}</h2>
        <button className="icon-btn" type="button" aria-label="Close trash actions" disabled={emptying} onClick={onClose}>×</button>
      </div>
      <p className="muted trash-account">{account}</p>
      <p id="trash-actions-description">This permanently deletes emails from the mail server. It cannot be undone.</p>
      {preparing && <p role="status">{archive ? 'Preparing ZIP archive of all emails in Trash…' : 'Checking all emails in Trash…'}</p>}
      {operation && <p className="trash-count">
        <strong>{operation.count} {operation.count === 1 ? 'email' : 'emails'} in {folder}.</strong>{' '}
        This includes all pages and ignores search filters and selections.
      </p>}
      {operation && operation.count > 0 && <p className="muted">
        Emails that arrive after this check stay in Trash.
      </p>}
      {hasArchive && <div className="trash-archive-step">
        <p>The ZIP contains one original .eml file per email. Save it before permanently deleting these emails. If the download fails or is canceled, retry it before confirming.</p>
        <a
          className={`btn primary${emptying ? ' disabled' : ''}`}
          href={api.trashArchiveUrl(account, operation.operation_id)}
          download={operation.filename ?? undefined}
          aria-disabled={emptying}
          tabIndex={emptying ? -1 : 0}
          onClick={(event) => {
            if (emptying) event.preventDefault();
            else {
              setDownloadStarted(true);
              backendDownloadClick({ fallbackName: operation.filename ?? 'trash.zip', onError: setError })(event);
            }
          }}
        >Download ZIP</a>
        {!result && <label className="trash-archive-confirmation">
          <input type="checkbox" checked={savedArchive} disabled={!downloadStarted || emptying} onChange={(event) => setSavedArchive(event.target.checked)} />
          <span>I have saved the ZIP file</span>
        </label>}
      </div>}
      {operation?.count === 0 && <p role="status">Trash is already empty. There are no emails to archive or delete.</p>}
      {error && <div className="banner error" role="alert">{error}</div>}
      {error && operation && <p className="muted">Retry to finish deleting these emails.{hasArchive ? ' Your ZIP remains available above.' : ''}</p>}
      {result && <div className="banner success" role="status">
        Permanently deleted {result.deleted} {result.deleted === 1 ? 'email' : 'emails'}.{result.remaining > 0 ? ` ${result.remaining} emails remain in Trash, including any new arrivals.` : ' Trash is empty.'}
      </div>}
      <div className="trash-modal-actions">
        <button className="btn subtle" type="button" disabled={emptying} onClick={onClose}>{result || operation?.count === 0 ? 'Done' : 'Cancel'}</button>
        {!preparing && !operation && <button className="btn primary" type="button" onClick={() => setPreparationAttempt((attempt) => attempt + 1)}>Retry preparation</button>}
        {operation && operation.count > 0 && !result && <button
          className="btn danger"
          type="button"
          disabled={preparing || emptying || (archive && (!hasArchive || !savedArchive))}
          onClick={() => void empty()}
        >{emptying ? 'Permanently deleting…' : archive ? 'Permanently empty archived trash' : 'Permanently empty trash'}</button>}
      </div>
    </section>
  </div>;
}
