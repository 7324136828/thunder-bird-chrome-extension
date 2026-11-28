import { FormEvent, useEffect, useRef, useState } from 'react';
import { api, ApiError, FullMessage, RichSignature, SendResult, SendUpload } from '../api';
import { MailtoDraft } from '../mailto';
import { buildComposeMessage, hasSignature, localRasterImage, MAX_COMPOSE_FILE_BYTES, MAX_COMPOSE_FILES, MAX_COMPOSE_TOTAL_BYTES, ORIGINAL_MAIL_MARKER, placeSignatureMarker, plainToEditorHtml, SIGNATURE_MARKER, validateComposeUploads } from '../composeMessage';
import { loadAccountSignature } from '../signatures';
import RichTextEditor, { RichTextEditorHandle } from './RichTextEditor';

interface Props {
  account: string;
  displayName?: string;
  replyTo?: FullMessage | null;
  forwardOf?: FullMessage | null;
  initialDraft?: MailtoDraft;
  onClose: () => void;
  onSent: (result: SendResult) => void;
}

interface DraftUpload extends SendUpload { id: string; previewUrl?: string; }

function splitAddresses(value: string): string[] {
  return value.split(/[,;]/).map((item) => item.trim()).filter(Boolean);
}

function fileSize(bytes: number): string {
  return bytes >= 1024 * 1024 ? `${(bytes / (1024 * 1024)).toFixed(1)} MB` : `${Math.max(1, Math.round(bytes / 1024))} KB`;
}

function uploadId(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function sendError(exception: unknown): string {
  if (exception instanceof ApiError && exception.status === 422 && Array.isArray(exception.detail)) {
    const issues = exception.detail.slice(0, 3).map((item: unknown) => {
      if (!item || typeof item !== 'object') return '';
      const issue = item as { loc?: unknown[]; msg?: unknown };
      const field = issue.loc?.find((part) => typeof part === 'string' && part !== 'body');
      return typeof issue.msg === 'string' ? `${typeof field === 'string' ? `${field}: ` : ''}${issue.msg.replace(/^Value error, /, '')}` : '';
    }).filter(Boolean);
    return issues.length ? issues.join(' ') : 'Check the recipient addresses, message, and attachments, then try again.';
  }
  return exception instanceof Error ? exception.message : String(exception);
}

export default function ComposeModal({ account, displayName, replyTo, forwardOf, initialDraft, onClose, onSent }: Props) {
  const original = replyTo ?? forwardOf;
  const [draftSignature, setDraftSignature] = useState<RichSignature | null>(null);
  const draftSignatureRef = useRef<RichSignature | null>(null);
  const [signatureLoading, setSignatureLoading] = useState(true);
  const signatureLoadingRef = useRef(true);
  const [signatureError, setSignatureError] = useState('');
  const signatureRequest = useRef(0);
  const signatureMarkerPending = useRef(false);
  const [editorVersion, setEditorVersion] = useState(0);
  const [to, setTo] = useState(initialDraft?.to ?? replyTo?.from_addr ?? '');
  const [cc, setCc] = useState(initialDraft?.cc ?? '');
  const [bcc, setBcc] = useState(initialDraft?.bcc ?? '');
  const [subject, setSubject] = useState(() => {
    if (initialDraft) return initialDraft.subject;
    const base = original?.subject ?? '';
    if (replyTo) return /^re:/i.test(base) ? base : `Re: ${base}`;
    if (forwardOf) return /^fwd:/i.test(base) ? base : `Fwd: ${base}`;
    return '';
  });
  const [initialHtml, setInitialHtml] = useState(() => plainToEditorHtml(initialDraft?.body ?? (original ? `\n\n${ORIGINAL_MAIL_MARKER}` : '')));
  const [editorHtml, setEditorHtml] = useState(initialHtml);
  const [uploads, setUploads] = useState<DraftUpload[]>([]);
  const uploadsRef = useRef<DraftUpload[]>([]);
  const [busy, setBusy] = useState(false);
  const busyRef = useRef(false);
  const [addingFiles, setAddingFiles] = useState(false);
  const addingRef = useRef(false);
  const [error, setError] = useState('');
  const form = useRef<HTMLFormElement>(null);
  const editor = useRef<RichTextEditorHandle>(null);
  const imageInput = useRef<HTMLInputElement>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  const mounted = useRef(true);

  function updateUploads(next: DraftUpload[]) { uploadsRef.current = next; setUploads(next); }

  useEffect(() => {
    mounted.current = true;
    form.current?.querySelector<HTMLInputElement>('input')?.focus();
    return () => {
      mounted.current = false;
      uploadsRef.current.forEach((upload) => { if (upload.previewUrl) URL.revokeObjectURL(upload.previewUrl); });
    };
  }, []);

  async function readSignature() {
    const request = ++signatureRequest.current;
    signatureMarkerPending.current = false;
    draftSignatureRef.current = null;
    setDraftSignature(null);
    signatureLoadingRef.current = true;
    setSignatureLoading(true);
    setSignatureError('');
    try {
      const signature = await loadAccountSignature(account);
      if (!mounted.current || request !== signatureRequest.current) return;
      draftSignatureRef.current = signature;
      setDraftSignature(signature);
      signatureMarkerPending.current = hasSignature(signature);
      finishLoadedSignature();
    } catch (exception) {
      if (mounted.current && request === signatureRequest.current) {
        signatureMarkerPending.current = false;
        draftSignatureRef.current = null;
        setDraftSignature(null);
        setSignatureError(sendError(exception));
      }
    } finally {
      if (mounted.current && request === signatureRequest.current && !signatureMarkerPending.current) {
        signatureLoadingRef.current = false;
        setSignatureLoading(false);
      }
    }
  }

  function finishLoadedSignature() {
    if (!mounted.current || !draftSignatureRef.current || addingRef.current) return;
    if (signatureMarkerPending.current) {
      // Wait for image preparation before remounting so its just-inserted nodes are preserved.
      const nextHtml = placeSignatureMarker(editor.current?.getHtml() ?? editorHtml);
      setInitialHtml(nextHtml);
      setEditorHtml(nextHtml);
      setEditorVersion((version) => version + 1);
      signatureMarkerPending.current = false;
    }
    signatureLoadingRef.current = false;
    setSignatureLoading(false);
  }

  useEffect(() => {
    void readSignature();
    return () => { signatureRequest.current++; };
  }, [account]);

  useEffect(() => {
    if (signatureMarkerPending.current) finishLoadedSignature();
  }, [draftSignature, addingFiles]);

  function selectedSignatureUploads(html: string, current: DraftUpload[]): SendUpload[] {
    const signature = draftSignatureRef.current;
    if (!signature) return [];
    // An original is only used to count files here; it does not affect signature images.
    try { return buildComposeMessage(html, original, current, signature).uploads.filter((item) => !current.includes(item as DraftUpload)); }
    catch { return hasSignature(signature) && html.includes(SIGNATURE_MARKER) ? signature.uploads : []; }
  }

  async function addFiles(files: File[], inline: boolean) {
    if (busyRef.current || addingRef.current || !files.length) return;
    setError(''); addingRef.current = true; setAddingFiles(true);
    const prepared: DraftUpload[] = [];
    try {
      const current = uploadsRef.current;
      const signatureFiles = selectedSignatureUploads(editor.current?.getHtml() ?? editorHtml, current);
      if (current.length + signatureFiles.length + files.length > MAX_COMPOSE_FILES) throw new Error('Attach up to 20 files, including inline images and signature images.');
      if (files.some((file) => file.size > MAX_COMPOSE_FILE_BYTES)) throw new Error('Each file must be no larger than 10 MB.');
      if ([...current.map((item) => item.file), ...signatureFiles.map((item) => item.file), ...files].reduce((sum, file) => sum + file.size, 0) > MAX_COMPOSE_TOTAL_BYTES) throw new Error('The combined files, inline images, and signature images must be no larger than 20 MB.');
      for (const file of files) {
        const id = uploadId();
        if (inline) {
          const image = await localRasterImage(file);
          prepared.push({ id, file: image.file, inline: true, contentId: `${id}@inline.local`, previewUrl: image.url });
        } else prepared.push({ id, file, inline: false });
      }
      if (!mounted.current) { prepared.forEach((item) => { if (item.previewUrl) URL.revokeObjectURL(item.previewUrl); }); return; }
      updateUploads([...uploadsRef.current, ...prepared]);
      prepared.forEach((item) => { if (item.previewUrl && item.contentId) editor.current?.insertImage(item.previewUrl, item.contentId, item.file.name); });
    } catch (exception) {
      prepared.forEach((item) => { if (item.previewUrl) URL.revokeObjectURL(item.previewUrl); });
      if (mounted.current) setError(exception instanceof Error ? exception.message : String(exception));
    } finally {
      addingRef.current = false;
      if (mounted.current) setAddingFiles(false);
    }
  }

  function removeUpload(upload: DraftUpload) {
    if (busyRef.current || addingRef.current) return;
    if (upload.contentId) editor.current?.removeImage(upload.contentId);
    if (upload.previewUrl) URL.revokeObjectURL(upload.previewUrl);
    updateUploads(uploadsRef.current.filter((item) => item.id !== upload.id));
  }

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (busyRef.current || addingRef.current || signatureLoadingRef.current || !draftSignatureRef.current) return;
    setError(''); busyRef.current = true; setBusy(true);
    try {
      const message = buildComposeMessage(editor.current?.getHtml() ?? editorHtml, original, uploadsRef.current, draftSignatureRef.current);
      validateComposeUploads(message.uploads);
      const recipients = { to: splitAddresses(to), cc: splitAddresses(cc), bcc: splitAddresses(bcc) };
      if (!recipients.to.length && !recipients.cc.length && !recipients.bcc.length) throw new Error('Add at least one recipient in To, Cc, or Bcc.');
      if (new TextEncoder().encode(message.text).length + new TextEncoder().encode(message.html).length > 1024 * 1024) throw new Error('The message is too large. Keep the text and formatting under 1 MB.');
      const result = await api.send({
        account, ...recipients, subject,
        text: message.text, html: message.html,
        in_reply_to: replyTo?.message_id ?? '', references: replyTo?.message_id ?? '',
      }, message.uploads);
      onSent(result); onClose();
    } catch (exception) {
      if (mounted.current) setError(sendError(exception));
    } finally {
      busyRef.current = false;
      if (mounted.current) setBusy(false);
    }
  };

  const signatureConfigured = draftSignature ? hasSignature(draftSignature) : false;
  const signatureAssets = selectedSignatureUploads(editorHtml, uploads);
  const totalFileBytes = [...uploads, ...signatureAssets].reduce((sum, upload) => sum + upload.file.size, 0);

  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-label="Compose message" onKeyDown={(event) => {
      if (event.key === 'Escape' && !busyRef.current && !addingRef.current) { event.preventDefault(); onClose(); }
      if (event.key !== 'Tab') return;
      const focusable = Array.from(form.current?.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled):not([type="file"]), [contenteditable="true"], [tabindex="0"]') ?? []).filter((item) => item.getClientRects().length);
      if (!focusable.length) { event.preventDefault(); return; }
      const first = focusable[0]; const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
    }}>
      <form ref={form} className="modal compose" onSubmit={submit}>
        <header className="modal-header">
          <h2>{replyTo ? 'Reply' : forwardOf ? 'Forward' : 'New message'}</h2>
          <span className="muted">From: {displayName?.trim() ? `${displayName.trim()} <${account}>` : account}</span>
          <button className="icon-btn" type="button" onClick={onClose} disabled={busy || addingFiles} aria-label="Close">✕</button>
        </header>
        <label className="field"><span>To</span><input value={to} onChange={(event) => setTo(event.target.value)} disabled={busy} placeholder="a@example.com, b@example.com" /></label>
        <label className="field"><span>Cc</span><input value={cc} onChange={(event) => setCc(event.target.value)} disabled={busy} /></label>
        <label className="field"><span>Bcc</span><input value={bcc} onChange={(event) => setBcc(event.target.value)} disabled={busy} /></label>
        <label className="field"><span>Subject</span><input value={subject} onChange={(event) => setSubject(event.target.value)} disabled={busy} /></label>
        <div className="field grow compose-editor-field">
          <span>Message</span>
          <RichTextEditor key={editorVersion} ref={editor} initialHtml={initialHtml} disabled={busy} fileBusy={addingFiles} onChange={setEditorHtml} onInsertImages={() => imageInput.current?.click()} onAttachFiles={() => fileInput.current?.click()} />
          <p id="compose-editor-help" className="compose-help muted">{signatureConfigured ? `The ${SIGNATURE_MARKER} placeholder becomes your saved signature when sent. Move it to place your signature, or remove it to omit your signature. ` : ''}{original ? `The ${ORIGINAL_MAIL_MARKER} placeholder becomes the quoted original when sent. Move or remove it as needed. ` : ''}Paste inserts plain text. Images are embedded in the message.</p>
        </div>
        <input className="compose-file-input" ref={imageInput} type="file" aria-label="Insert images" accept="image/png,image/jpeg,image/gif,image/webp,image/bmp" multiple disabled={busy || addingFiles} onChange={(event) => { const files = Array.from(event.target.files ?? []); event.target.value = ''; void addFiles(files, true); }} />
        <input className="compose-file-input" ref={fileInput} type="file" aria-label="Attach files" multiple disabled={busy || addingFiles} onChange={(event) => { const files = Array.from(event.target.files ?? []); event.target.value = ''; void addFiles(files, false); }} />
        {addingFiles && <p className="compose-help muted" role="status">Preparing files…</p>}
        {uploads.length > 0 && <ul className="compose-uploads" aria-label="Message files">
          {uploads.map((upload) => <li key={upload.id}>
            <span><strong>{upload.file.name}</strong><small>{upload.inline ? 'Inline image' : 'Attachment'} · {fileSize(upload.file.size)}</small></span>
            <button className="icon-btn" type="button" aria-label={`Remove ${upload.file.name}`} disabled={busy || addingFiles} onClick={() => removeUpload(upload)}>✕</button>
          </li>)}
        </ul>}
        {signatureAssets.length > 0 && <p className="compose-help muted">Signature images: {signatureAssets.length}. Files including signature images: {uploads.length + signatureAssets.length} · {fileSize(totalFileBytes)} total. Remove the signature placeholder to omit its images.</p>}
        {signatureLoading && <p className="compose-help muted" role="status">Loading saved signature…</p>}
        {signatureError && <div className="banner error" role="alert">Could not load your saved signature: {signatureError} <button className="btn" type="button" onClick={() => void readSignature()} disabled={signatureLoading}>Retry signature</button></div>}
        {error && <div className="banner error" role="alert">{error}</div>}
        <footer className="button-row">
          <span className="compose-upload-limit muted">Up to 20 files · 10 MB each · 20 MB total</span>
          <button className="btn" type="button" onClick={onClose} disabled={busy || addingFiles}>Cancel</button>
          <button className="btn primary" type="submit" disabled={busy || addingFiles || signatureLoading || !draftSignature}>{busy ? 'Sending…' : 'Send'}</button>
        </footer>
      </form>
    </div>
  );
}
