import { api, RichSignature, SendUpload } from './api';
import { MAX_COMPOSE_FILE_BYTES, MAX_COMPOSE_FILES, MAX_COMPOSE_TOTAL_BYTES, signatureEditorHtml } from './composeMessage';

function imagePreview(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => typeof reader.result === 'string' ? resolve(reader.result) : reject(new Error('Could not read a signature image.'));
    reader.onerror = () => reject(new Error('Could not read a signature image.'));
    reader.readAsDataURL(file);
  });
}

export async function loadAccountSignature(account: string): Promise<RichSignature> {
  const saved = await api.signature(account);
  if (saved.images.length > MAX_COMPOSE_FILES) throw new Error('The saved signature has too many images. Edit the account signature before sending.');
  const uploads: SendUpload[] = await Promise.all(saved.images.map(async (image) => {
    const revision = new URL(image.url, window.location.href).searchParams.get('revision') ?? undefined;
    if (revision && !/^[a-f0-9]{32}$/i.test(revision)) throw new Error('The saved signature has an invalid image reference.');
    const blob = await api.signatureImage(account, image.content_id, revision);
    if (blob.size > MAX_COMPOSE_FILE_BYTES) throw new Error('A saved signature image exceeds 10 MB. Edit the account signature before sending.');
    return { file: new File([blob], image.filename, { type: blob.type }), contentId: image.content_id, inline: true };
  }));
  if (uploads.reduce((total, upload) => total + upload.file.size, 0) > MAX_COMPOSE_TOTAL_BYTES) {
    throw new Error('Saved signature images exceed 20 MB. Edit the account signature before sending.');
  }
  const previews = new Map(await Promise.all(uploads.map(async (upload) => [upload.contentId!, await imagePreview(upload.file)] as const)));
  const template = document.createElement('template');
  template.innerHTML = signatureEditorHtml(saved.text, uploads);
  template.content.querySelectorAll('img[data-compose-cid]').forEach((image) => {
    const preview = previews.get(image.getAttribute('data-compose-cid') ?? '');
    if (preview) image.setAttribute('src', preview);
  });
  return { html: template.innerHTML, uploads };
}
