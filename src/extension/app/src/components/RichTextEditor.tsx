import { forwardRef, useEffect, useId, useImperativeHandle, useRef, useState } from 'react';
import { safeComposeLink } from '../composeMessage';

export interface RichTextEditorHandle {
  getHtml: () => string;
  insertImage: (url: string, contentId: string, filename: string) => void;
  removeImage: (contentId: string) => void;
}

interface Props {
  initialHtml: string;
  disabled: boolean;
  fileBusy: boolean;
  onChange: (html: string) => void;
  onInsertImages: () => void;
  onAttachFiles?: () => void;
  label?: string;
  helpId?: string;
}

const RichTextEditor = forwardRef<RichTextEditorHandle, Props>(function RichTextEditor({ initialHtml, disabled, fileBusy, onChange, onInsertImages, onAttachFiles, label = 'Message', helpId = 'compose-editor-help' }, forwardedRef) {
  const editor = useRef<HTMLDivElement>(null);
  const range = useRef<Range | null>(null);
  const initialized = useRef(false);
  const [linkOpen, setLinkOpen] = useState(false);
  const [linkUrl, setLinkUrl] = useState('https://');
  const [linkError, setLinkError] = useState('');
  const linkInput = useRef<HTMLInputElement>(null);
  const [active, setActive] = useState<Record<string, boolean>>({});
  const [emojiOpen, setEmojiOpen] = useState(false);
  const controlId = useId();
  const emojis = [['😀', 'Grinning face'], ['😊', 'Smiling face'], ['👋', 'Waving hand'], ['👍', 'Thumbs up'], ['❤️', 'Heart'], ['✨', 'Sparkles'], ['🎉', 'Celebration'], ['✅', 'Check mark'], ['📧', 'Email'], ['📞', 'Telephone'], ['💼', 'Briefcase'], ['🌍', 'Globe'], ['🤝', 'Handshake'], ['🙏', 'Folded hands'], ['🚀', 'Rocket'], ['🌟', 'Star']];

  useEffect(() => {
    if (editor.current && !initialized.current) {
      editor.current.innerHTML = initialHtml;
      initialized.current = true;
    }
  }, [initialHtml]);

  function rememberSelection() {
    const selection = window.getSelection();
    if (selection?.rangeCount && editor.current?.contains(selection.anchorNode) && editor.current.contains(selection.focusNode)) {
      range.current = selection.getRangeAt(0).cloneRange();
      setActive(Object.fromEntries(['bold', 'italic', 'underline', 'insertUnorderedList', 'insertOrderedList'].map((command) => [command, document.queryCommandState(command)])));
    }
  }

  function restoreSelection() {
    const element = editor.current;
    if (!element) return;
    element.focus();
    const selection = window.getSelection();
    if (!selection) return;
    const saved = range.current;
    const restored = saved && element.contains(saved.startContainer) && element.contains(saved.endContainer) ? saved : document.createRange();
    if (restored !== saved) {
      restored.selectNodeContents(element);
      restored.collapse(false);
    }
    selection.removeAllRanges();
    selection.addRange(restored);
  }

  function changed() {
    if (editor.current) onChange(editor.current.innerHTML);
    rememberSelection();
  }

  function command(name: string, value?: string) {
    if (disabled) return;
    rememberSelection();
    restoreSelection();
    document.execCommand(name, false, value);
    changed();
  }

  useImperativeHandle(forwardedRef, () => ({
    getHtml: () => editor.current?.innerHTML ?? initialHtml,
    insertImage: (url, contentId, filename) => {
      if (disabled) return;
      const image = document.createElement('img');
      image.src = url;
      image.alt = filename;
      image.setAttribute('data-compose-cid', contentId);
      image.style.maxWidth = '100%';
      command('insertHTML', `${image.outerHTML}<br>`);
    },
    removeImage: (contentId) => {
      editor.current?.querySelectorAll('img[data-compose-cid]').forEach((image) => {
        if (image.getAttribute('data-compose-cid') === contentId) image.remove();
      });
      changed();
    },
  }));

  useEffect(() => {
    if (linkOpen) linkInput.current?.focus();
  }, [linkOpen]);

  const formats = [
    ['bold', 'Bold', 'B'],
    ['italic', 'Italic', 'I'],
    ['underline', 'Underline', 'U'],
    ['insertUnorderedList', 'Bulleted list', '• List'],
    ['insertOrderedList', 'Numbered list', '1. List'],
  ];

  return (
    <div className="rich-editor">
      <div className="compose-toolbar" role="toolbar" aria-label={`${label} formatting`}>
        {formats.map(([name, label, text]) => (
          <button key={name} type="button" className={`editor-tool editor-tool-${name}`} aria-label={label} title={label} aria-pressed={Boolean(active[name])} disabled={disabled}
            onMouseDown={(event) => event.preventDefault()} onClick={() => command(name)}>{text}</button>
        ))}
        <button type="button" className="editor-tool" aria-label="Add link" disabled={disabled} onMouseDown={(event) => event.preventDefault()} onClick={() => {
          rememberSelection(); setEmojiOpen(false); setLinkError(''); setLinkOpen((open) => !open);
        }}>Link</button>
        <button type="button" className="editor-tool" aria-label="Remove link" disabled={disabled} onMouseDown={(event) => event.preventDefault()} onClick={() => command('unlink')}>Unlink</button>
        <button type="button" className="editor-tool" aria-label="Undo" disabled={disabled} onMouseDown={(event) => event.preventDefault()} onClick={() => command('undo')}>↶</button>
        <button type="button" className="editor-tool" aria-label="Redo" disabled={disabled} onMouseDown={(event) => event.preventDefault()} onClick={() => command('redo')}>↷</button>
        <span className="editor-toolbar-divider" />
        <button type="button" className="editor-tool" aria-label="Insert emoji" aria-expanded={emojiOpen} aria-controls={`${controlId}-emoji-picker`} disabled={disabled}
          onMouseDown={(event) => event.preventDefault()} onClick={() => { rememberSelection(); setLinkOpen(false); setEmojiOpen((open) => !open); }}>Emoji</button>
        <button type="button" className="editor-tool" disabled={disabled || fileBusy} onMouseDown={(event) => event.preventDefault()} onClick={() => { rememberSelection(); onInsertImages(); }}>Insert image</button>
        {onAttachFiles && <button type="button" className="editor-tool" disabled={disabled || fileBusy} onClick={onAttachFiles}>Attach files</button>}
      </div>
      {emojiOpen && <div id={`${controlId}-emoji-picker`} className="compose-emoji-controls" role="group" aria-label="Emoji picker" onKeyDown={(event) => {
        if (event.key === 'Escape') { event.stopPropagation(); setEmojiOpen(false); restoreSelection(); }
      }}>
        {emojis.map(([emoji, name]) => <button key={emoji} className="editor-tool emoji-choice" type="button" aria-label={`Insert ${name} emoji`} title={name} disabled={disabled}
          onMouseDown={(event) => event.preventDefault()} onClick={() => { command('insertText', emoji); setEmojiOpen(false); }}>{emoji}</button>)}
        <button className="editor-tool" type="button" disabled={disabled} aria-label="Close emoji picker" onClick={() => { setEmojiOpen(false); restoreSelection(); }}>Close</button>
      </div>}
      {linkOpen && (
        <div className="compose-link-controls">
          <label htmlFor={`${controlId}-link-url`}>Link URL</label>
          <input id={`${controlId}-link-url`} ref={linkInput} value={linkUrl} disabled={disabled} onChange={(event) => setLinkUrl(event.target.value)} onKeyDown={(event) => {
            if (event.key === 'Escape') { event.stopPropagation(); setLinkOpen(false); restoreSelection(); }
            if (event.key === 'Enter') event.preventDefault();
          }} />
          <button className="btn" type="button" disabled={disabled} onClick={() => {
            const url = safeComposeLink(linkUrl.trim());
            if (!url) { setLinkError('Use an https://, http://, or mailto: URL.'); return; }
            restoreSelection();
            if (window.getSelection()?.isCollapsed) {
              const anchor = document.createElement('a'); anchor.href = url; anchor.textContent = url;
              command('insertHTML', anchor.outerHTML);
            } else command('createLink', url);
            setLinkOpen(false); setLinkError('');
          }}>Insert link</button>
          <button className="btn" type="button" disabled={disabled} onClick={() => { setLinkOpen(false); restoreSelection(); }}>Cancel link</button>
          {linkError && <span className="error" role="alert">{linkError}</span>}
        </div>
      )}
      <div ref={editor} className="compose-message-editor" role="textbox" aria-label={label} aria-multiline="true" aria-disabled={disabled} aria-describedby={helpId}
        contentEditable={!disabled} suppressContentEditableWarning onInput={changed} onKeyUp={rememberSelection} onMouseUp={rememberSelection} onBlur={rememberSelection}
        onClick={(event) => { if ((event.target as Element).closest('a')) event.preventDefault(); }}
        onAuxClick={(event) => { if ((event.target as Element).closest('a')) event.preventDefault(); }}
        onPaste={(event) => { event.preventDefault(); command('insertText', event.clipboardData.getData('text/plain')); }}
        onDrop={(event) => event.preventDefault()} />
    </div>
  );
});

export default RichTextEditor;
