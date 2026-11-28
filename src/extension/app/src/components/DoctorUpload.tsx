import { useRef, useState } from 'react';
import { DoctorJob, doctorApi, doctorError } from '../doctorApi';

const extensions = ['.eml', '.zip', '.mbox', '.json'];
const extension = (name: string) => name.slice(name.lastIndexOf('.')).toLowerCase();
const sizeLabel = (bytes: number) => bytes >= 1048576 ? `${(bytes / 1048576).toFixed(1)} MB` : `${(bytes / 1024).toFixed(1)} KB`;

export default function DoctorUpload({ onCreated }: { onCreated: (job: DoctorJob) => void }) {
  const [files, setFiles] = useState<File[]>([]);
  const [source, setSource] = useState('');
  const [filename, setFilename] = useState('pasted_email.eml');
  const [mode, setMode] = useState<'files' | 'source'>('files');
  const [dragging, setDragging] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const input = useRef<HTMLInputElement>(null);

  const addFiles = (incoming: FileList | File[]) => {
    const items = Array.from(incoming);
    const rejected = items.filter((file) => !extensions.includes(extension(file.name)));
    setError(rejected.length ? `Unsupported files: ${rejected.map((file) => file.name).join(', ')}. Choose .eml, .zip, .mbox or optional JSON.` : '');
    setFiles((current) => {
      const seen = new Set(current.map((file) => `${file.name}:${file.size}:${file.lastModified}`));
      return [...current, ...items.filter((file) => {
        const key = `${file.name}:${file.size}:${file.lastModified}`;
        if (!extensions.includes(extension(file.name)) || seen.has(key)) return false;
        seen.add(key);
        return true;
      })];
    });
    setMode('files');
  };

  const submit = async () => {
    setError('');
    setBusy(true);
    try {
      if (mode === 'files') {
        if (!files.some((file) => ['.eml', '.zip', '.mbox'].includes(extension(file.name)))) {
          throw new Error('Add an .eml, .zip or .mbox export. aliases.json and annotations.json accompany message files.');
        }
        onCreated(await doctorApi.upload(files));
        setFiles([]);
      } else {
        if (!source.trim()) throw new Error('Paste the complete raw email source, including headers.');
        onCreated(await doctorApi.paste(source, filename.trim() || 'pasted_email.eml'));
        setSource('');
      }
    } catch (failure) {
      setError(doctorError(failure));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="doctor-card" aria-labelledby="export-title" onPaste={(event) => {
      const pasted = Array.from(event.clipboardData.files);
      if (pasted.length) {
        event.preventDefault();
        addFiles(pasted);
      } else if (!(event.target instanceof HTMLInputElement) && !(event.target instanceof HTMLTextAreaElement)) {
        const text = event.clipboardData.getData('text/plain');
        if (text.trim()) { event.preventDefault(); setSource(text); setMode('source'); }
      }
    }}>
      <div className="doctor-card-heading"><span className="doctor-step">01</span><div><h2 id="export-title">Audit an inbox export</h2><p className="muted">Turn email archives into a sender inventory and a practical cleanup plan.</p></div></div>
      <div className="doctor-segmented" aria-label="Audit input">
        <button type="button" className={mode === 'files' ? 'active' : ''} aria-pressed={mode === 'files'} onClick={() => setMode('files')}>Upload files</button>
        <button type="button" className={mode === 'source' ? 'active' : ''} aria-pressed={mode === 'source'} onClick={() => setMode('source')}>Paste email source</button>
      </div>
      {mode === 'files' ? <>
        <button type="button" className={`doctor-dropzone ${dragging ? 'dragging' : ''}`} onClick={() => input.current?.click()}
          onDragOver={(event) => { event.preventDefault(); setDragging(true); }}
          onDragLeave={() => setDragging(false)} onDrop={(event) => { event.preventDefault(); setDragging(false); addFiles(event.dataTransfer.files); }}>
          <span className="doctor-drop-icon" aria-hidden="true">↑</span><strong>Drop your email exports here</strong><span>Choose files or paste files from your clipboard</span><small>.eml · .zip · .mbox</small>
        </button>
        <input ref={input} type="file" multiple hidden accept=".eml,.zip,.mbox,.json" aria-label="Choose email export files" onChange={(event) => {
          if (event.target.files) addFiles(event.target.files);
          event.target.value = '';
        }} />
        <p className="doctor-small muted">Add <code>aliases.json</code> to combine sender identities, or <code>annotations.json</code> for your own cleanup decisions.</p>
        {files.length > 0 && <ul className="doctor-staged-files">{files.map((file, index) => <li key={`${file.name}:${file.size}:${file.lastModified}`}><span>{file.name}<small className="muted">{sizeLabel(file.size)}</small></span><button type="button" className="icon-btn" aria-label={`Remove ${file.name}`} disabled={busy} onClick={() => setFiles((current) => current.filter((_, item) => item !== index))}>×</button></li>)}</ul>}
      </> : <div className="doctor-source-fields">
        <label className="field"><span>Raw email source</span><textarea className="mono" rows={10} placeholder={'From: sender@example.com\nTo: you@example.com\nSubject: Your message\nDate: ...\n\nMessage body'} value={source} onChange={(event) => setSource(event.target.value)} spellCheck={false} /></label>
        <label className="field"><span>Source filename</span><input value={filename} onChange={(event) => setFilename(event.target.value)} placeholder="pasted_email.eml" /></label>
      </div>}
      {error && <div className="banner error" role="alert">{error}</div>}
      <div className="doctor-card-footer"><span className="muted doctor-small">{mode === 'files' && files.length ? `${files.length} files · ${sizeLabel(files.reduce((sum, file) => sum + file.size, 0))}` : 'Your audit runs locally.'}</span><button type="button" className="btn primary" disabled={busy || (mode === 'files' ? !files.length : !source.trim())} onClick={() => void submit()}>{busy ? 'Starting audit…' : 'Start export audit'}</button></div>
    </section>
  );
}
