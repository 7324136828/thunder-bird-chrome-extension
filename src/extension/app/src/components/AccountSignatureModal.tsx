import { FormEvent, useEffect, useRef, useState } from 'react';
import { api, ApiError, SendUpload } from '../api';
import { buildSignature, localRasterImage, MAX_COMPOSE_FILE_BYTES, MAX_COMPOSE_FILES, MAX_COMPOSE_TOTAL_BYTES, SIGNATURE_MARKER } from '../composeMessage';
import { loadAccountSignature } from '../signatures';
import RichTextEditor, { RichTextEditorHandle } from './RichTextEditor';

interface Props {
  account: string;
  onClose: () => void;
  onSaved: () => void;
}

interface SignatureUpload extends SendUpload {
  id: string;
  previewUrl?: string;
}

function fileSize(bytes: number): string {
  return bytes >= 1024 * 1024 ? `${(bytes / (1024 * 1024)).toFixed(1)} MB` : `${Math.max(1, Math.round(bytes / 1024))} KB`;
}

function failureMessage(failure: unknown): string {
  if (failure instanceof ApiError && failure.status === 422 && Array.isArray(failure.detail)) {
    const messages = failure.detail.slice(0, 3).map((issue: unknown) => {
      if (!issue || typeof issue !== 'object') return '';
      const message = (issue as { msg?: unknown }).msg;
      return typeof message === 'string' ? message.replace(/^Value error, /, '') : '';
    }).filter(Boolean);
    if (messages.length) return messages.join(' ');
  }
  return failure instanceof Error ? failure.message : String(failure);
}

export default function AccountSignatureModal({ account, onClose, onSaved }: Props) {
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [loadVersion, setLoadVersion] = useState(0);
  const [editorHtml, setEditorHtml] = useState('');
  const [initialHtml, setInitialHtml] = useState('');
  const [uploads, setUploads] = useState<SignatureUpload[]>([]);
  const uploadsRef = useRef<SignatureUpload[]>([]);
  const [saving, setSaving] = useState(false);
  const savingRef = useRef(false);
  const [addingImages, setAddingImages] = useState(false);
  const addingRef = useRef(false);
  const [error, setError] = useState('');
  const mounted = useRef(true);
  const form = useRef<HTMLFormElement>(null);
  const editor = useRef<RichTextEditorHandle>(null);
  const imageInput = useRef<HTMLInputElement>(null);

  function updateUploads(next: SignatureUpload[]) {
    uploadsRef.current = next;
    setUploads(next);
  }

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      uploadsRef.current.forEach((upload) => { if (upload.previewUrl) URL.revokeObjectURL(upload.previewUrl); });
    };
  }, []);

  useEffect(() => {
    let current = true;
    setLoading(true);
    setLoadError('');
    void loadAccountSignature(account).then((signature) => {
      if (!current || !mounted.current) return;
      const next = signature.uploads.map((upload, index) => ({ ...upload, id: upload.contentId ?? `loaded-${index}` }));
      uploadsRef.current.forEach((upload) => { if (upload.previewUrl) URL.revokeObjectURL(upload.previewUrl); });
      updateUploads(next);
      setInitialHtml(signature.html);
      setEditorHtml(signature.html);
      setLoading(false);
    }).catch((failure: unknown) => {
      if (!current || !mounted.current) return;
      setLoadError(failureMessage(failure));
      setLoading(false);
    });
    return () => { current = false; };
  }, [account, loadVersion]);

  useEffect(() => {
    form.current?.querySelector<HTMLElement>(!loading && !loadError ? '[contenteditable="true"]' : 'button:not(:disabled)')?.focus();
  }, [loading, loadError]);

  async function addImages(files: File[]) {
    if (loading || loadError || savingRef.current || addingRef.current || !files.length) return;
    setError('');
    addingRef.current = true;
    setAddingImages(true);
    const prepared: SignatureUpload[] = [];
    try {
      const current = uploadsRef.current;
      if (current.length + files.length > MAX_COMPOSE_FILES) throw new Error('Add up to 20 signature images.');
      if (files.some((file) => file.size > MAX_COMPOSE_FILE_BYTES)) throw new Error('Each image must be no larger than 10 MB.');
      if ([...current.map((item) => item.file), ...files].reduce((sum, file) => sum + file.size, 0) > MAX_COMPOSE_TOTAL_BYTES) throw new Error('The combined signature images must be no larger than 20 MB.');
      const ids = new Set(current.map((upload) => upload.contentId));
      for (const file of files) {
        let ordinal = 1;
        while (ids.has(`attach${ordinal}`)) ordinal += 1;
        const id = `attach${ordinal}`;
        ids.add(id);
        const image = await localRasterImage(file);
        prepared.push({ id, contentId: id, file: image.file, inline: true, previewUrl: image.url });
      }
      if (!mounted.current) {
        prepared.forEach((upload) => { if (upload.previewUrl) URL.revokeObjectURL(upload.previewUrl); });
        return;
      }
      updateUploads([...uploadsRef.current, ...prepared]);
      prepared.forEach((upload) => { if (upload.previewUrl && upload.contentId) editor.current?.insertImage(upload.previewUrl, upload.contentId, upload.file.name); });
    } catch (failure) {
      prepared.forEach((upload) => { if (upload.previewUrl) URL.revokeObjectURL(upload.previewUrl); });
      if (mounted.current) setError(failureMessage(failure));
    } finally {
      addingRef.current = false;
      if (mounted.current) setAddingImages(false);
    }
  }

  function removeImage(upload: SignatureUpload) {
    if (savingRef.current || addingRef.current) return;
    if (upload.contentId) editor.current?.removeImage(upload.contentId);
    if (upload.previewUrl) URL.revokeObjectURL(upload.previewUrl);
    updateUploads(uploadsRef.current.filter((item) => item.id !== upload.id));
  }

  async function save(event: FormEvent) {
    event.preventDefault();
    if (loading || loadError || savingRef.current || addingRef.current) return;
    setError('');
    savingRef.current = true;
    setSaving(true);
    try {
      const signature = buildSignature(editor.current?.getHtml() ?? editorHtml, uploadsRef.current);
      if (new TextEncoder().encode(signature.html).length > 256 * 1024) throw new Error('The signature is too large. Keep its text and formatting under 256 KB.');
      await api.saveSignature(account, signature.html, signature.uploads);
      if (!mounted.current) return;
      onSaved();
      onClose();
    } catch (failure) {
      if (mounted.current) setError(failureMessage(failure));
    } finally {
      savingRef.current = false;
      if (mounted.current) setSaving(false);
    }
  }

  const busy = saving || addingImages;
  return <div className="modal-backdrop" role="dialog" aria-modal="true" aria-labelledby="account-configuration-title" onKeyDown={(event) => {
    if (event.key === 'Escape' && !savingRef.current && !addingRef.current) { event.preventDefault(); onClose(); }
    if (event.key !== 'Tab') return;
    const focusable = Array.from(form.current?.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled):not([type="file"]), [contenteditable="true"], [tabindex="0"]') ?? []).filter((item) => item.getClientRects().length);
    if (!focusable.length) { event.preventDefault(); return; }
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
  }}>
    <form className="modal account-signature-modal" ref={form} onSubmit={(event) => void save(event)}>
      <header className="modal-header">
        <h2 id="account-configuration-title">Account configuration</h2>
        <button className="icon-btn" type="button" aria-label="Close account configuration" disabled={busy} onClick={onClose}>×</button>
      </header>
      <p className="signature-account">{account}</p>
      {loading && <p className="muted" role="status">Loading signature…</p>}
      {loadError && <div className="banner error" role="alert">
        <p>Could not load this account’s signature: {loadError}</p>
        <button className="btn" type="button" onClick={() => setLoadVersion((version) => version + 1)}>Retry loading signature</button>
      </div>}
      {!loading && !loadError && <>
        <div className="field compose-editor-field signature-editor-field">
          <span>Signature</span>
          <RichTextEditor ref={editor} initialHtml={initialHtml} label="Signature" helpId="signature-editor-help" disabled={saving} fileBusy={addingImages} onChange={setEditorHtml} onInsertImages={() => imageInput.current?.click()} />
          <p id="signature-editor-help" className="compose-help muted">Format your signature, insert images, and add emojis. It is saved on disk for {account} and restored when you sign in again. Leave it blank to disable it.</p>
          <p className="compose-help muted">When configured, every new draft includes {SIGNATURE_MARKER}. Move the placeholder to choose the signature’s position, or remove it to omit the signature.</p>
        </div>
        <input className="compose-file-input" ref={imageInput} type="file" aria-label="Insert signature images" accept="image/png,image/jpeg,image/gif,image/webp,image/bmp" multiple disabled={busy} onChange={(event) => {
          const files = Array.from(event.target.files ?? []);
          event.target.value = '';
          void addImages(files);
        }} />
        {addingImages && <p className="compose-help muted" role="status">Preparing images…</p>}
        {uploads.length > 0 && <ul className="compose-uploads" aria-label="Signature images">
          {uploads.map((upload) => <li key={upload.id}>
            <span><strong>{upload.file.name}</strong><small>Embedded image · {fileSize(upload.file.size)}</small></span>
            <button className="icon-btn" type="button" aria-label={`Remove ${upload.file.name}`} disabled={busy} onClick={() => removeImage(upload)}>×</button>
          </li>)}
        </ul>}
        {error && <div className="banner error" role="alert">{error}</div>}
      </>}
      <footer className="button-row">
        <span className="compose-upload-limit muted">Up to 20 images · 10 MB each · 20 MB total</span>
        <button className="btn" type="button" disabled={busy} onClick={onClose}>Cancel</button>
        <button className="btn primary" type="submit" disabled={loading || Boolean(loadError) || busy}>{saving ? 'Saving…' : 'Save signature'}</button>
      </footer>
    </form>
  </div>;
}
