import { useEffect, useRef } from 'react';

interface Props {
  destination: string;
  onCancel: () => void;
  onContinue: () => void;
  onRestoreFocus: () => void;
}

export default function ExternalLinkModal({ destination, onCancel, onContinue, onRestoreFocus }: Props) {
  const dialogRef = useRef<HTMLDialogElement>(null);
  const cancelRef = useRef<HTMLButtonElement>(null);
  const restoreFocusRef = useRef(onRestoreFocus);
  restoreFocusRef.current = onRestoreFocus;
  const url = new URL(destination);
  const externalApp = url.protocol === 'tel:';

  useEffect(() => {
    const dialog = dialogRef.current;
    dialog?.showModal();
    cancelRef.current?.focus();
    return () => {
      dialog?.close();
      // Image downloads may have replaced the frame that opened the dialog.
      restoreFocusRef.current();
    };
  }, []);

  return <dialog
    ref={dialogRef}
    className="external-link-dialog"
    aria-labelledby="external-link-title"
    aria-describedby="external-link-description"
    onCancel={(event) => {
      event.preventDefault();
      onCancel();
    }}
  >
    <h2 id="external-link-title">Leave this site?</h2>
    <p id="external-link-description">
      {externalApp
        ? 'This email link will open an external application. Continue only if you trust the destination.'
        : 'You are about to leave this site and open an external link. Continue only if you trust the destination.'}
    </p>
    {url.hostname && <p className="external-link-host"><strong>{url.hostname}</strong></p>}
    <p className="external-link-destination" dir="ltr">{destination}</p>
    <div className="external-link-actions">
      <button ref={cancelRef} className="btn subtle" type="button" onClick={onCancel}>Cancel</button>
      <button className="btn primary" type="button" onClick={onContinue}>Continue</button>
    </div>
  </dialog>;
}
