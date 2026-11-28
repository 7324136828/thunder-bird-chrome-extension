/** Email HTML is parsed inside a template, whose contents never load resources. */
export interface PreparedEmailHtml {
  html: string;
  imageUrls: string[];
  linkUrls: string[];
}

export interface EmailImageState {
  state: 'loading' | 'blocked' | 'ready';
  dataUrl?: string;
}

interface RenderedEmailHtml {
  srcDoc: string;
  hasRenderBlocked: boolean;
  linkToken: string | null;
}

const SAFE_TAGS = new Set(
  'a abbr address b bdi bdo blockquote br caption center cite code col colgroup dd del details dfn div dl dt em figcaption figure font h1 h2 h3 h4 h5 h6 hr i img ins kbd li main mark ol p pre q s samp section small span strong sub summary sup table tbody td th thead tfoot time tr tt u ul var wbr'.split(' '),
);
const REMOVE_CONTENT = new Set(
  'script style iframe frame frameset object embed applet svg math template noscript audio video canvas textarea select input button link meta base source'.split(' '),
);
const SAFE_ATTRIBUTES = new Set(
  'alt title lang dir align valign width height cellpadding cellspacing border colspan rowspan scope start color bgcolor face size'.split(' '),
);
const SAFE_STYLES = new Set(
  'background-color background-position background-repeat background-size background-origin background-clip color border border-color border-style border-width border-top border-right border-bottom border-left border-top-color border-right-color border-bottom-color border-left-color border-top-style border-right-style border-bottom-style border-left-style border-top-width border-right-width border-bottom-width border-left-width border-radius border-collapse border-spacing box-sizing caption-side clear display float font font-family font-size font-style font-variant font-weight height width max-height max-width min-height min-width letter-spacing line-height list-style-type margin margin-top margin-right margin-bottom margin-left opacity overflow overflow-wrap padding padding-top padding-right padding-bottom padding-left table-layout text-align text-decoration text-decoration-color text-decoration-line text-decoration-style text-indent text-transform vertical-align white-space word-break word-spacing word-wrap'.split(' '),
);
const RASTER_DATA = /^data:image\/(?:png|jpeg|gif|webp|bmp);base64,[a-z\d+/=\s]+$/i;
const CSP = "default-src 'none'; img-src data:; style-src 'unsafe-inline'; script-src 'none'; connect-src 'none'; frame-src 'none'; media-src 'none'; object-src 'none'; font-src 'none'; base-uri 'none'; form-action 'none'";
const MAX_RENDERED_IMAGE_BYTES = 32 * 1024 * 1024;

function externalLinkUrl(value: string | undefined): string | null {
  if (!value || value.length > 8192 || /[\u0000-\u001f\u007f]/.test(value)) return null;
  try {
    const url = new URL(value.startsWith('//') ? `https:${value}` : value);
    if (!['http:', 'https:', 'mailto:', 'tel:'].includes(url.protocol)) return null;
    if (url.username || url.password) return null;
    return url.href;
  } catch {
    return null;
  }
}

function linkBridge(token: string): string {
  // Only app-owned code enters this script. Sender URLs remain in the parent.
  return `(() => {
    const token = ${JSON.stringify(token)};
    const activate = (event) => {
      if (event.type === 'keydown' && (event.key !== 'Enter' || event.repeat)) return;
      if (event.type === 'click' && event.button !== 0) return;
      if (event.type === 'auxclick' && event.button !== 1) return;
      const link = event.target instanceof Element ? event.target.closest('a[data-email-link]') : null;
      if (!link) return;
      event.preventDefault();
      event.stopImmediatePropagation();
      if (!event.isTrusted) return;
      parent.postMessage({ type: 'email-external-link', token, index: Number(link.dataset.emailLink) }, '*');
    };
    document.addEventListener('click', activate, true);
    document.addEventListener('auxclick', activate, true);
    document.addEventListener('keydown', activate, true);
  })();`;
}

function remoteImageUrl(value: string | null): string | null {
  const source = value?.trim() || '';
  try {
    const url = new URL(source.startsWith('//') ? `https:${source}` : source);
    if (!['http:', 'https:'].includes(url.protocol)) return null;
    url.hash = '';
    return url.href;
  } catch {
    return null;
  }
}

function firstImageSource(value: string | null): string | null {
  if (!value) return null;
  // Image sets normally contain URL + width/density pairs. The first supported
  // remote candidate is enough; never let the browser resolve a srcset itself.
  for (const candidate of value.split(',')) {
    const url = remoteImageUrl(candidate.trim().split(/\s+/)[0]);
    if (url) return url;
  }
  return null;
}

function safeStyle(source: HTMLElement): string {
  const clean = source.ownerDocument.createElement('span').style;
  for (let index = 0; index < source.style.length; index += 1) {
    const property = source.style[index];
    const value = source.style.getPropertyValue(property);
    // Backslashes/comments could hide resource functions. A property allowlist
    // also excludes background images, masks, cursors, and generated content.
    if (
      SAFE_STYLES.has(property) &&
      !/[\\@]|\/\*|url\s*\(|expression\s*\(|(?:var|attr|image|image-set)\s*\(/i.test(value)
    ) {
      clean.setProperty(property, value, source.style.getPropertyPriority(property));
    }
  }
  return clean.cssText;
}

export function prepareEmailHtml(html: string): PreparedEmailHtml {
  const template = document.createElement('template');
  template.innerHTML = html;
  const contentRoot = template.content.ownerDocument.createElement('div');
  contentRoot.setAttribute('data-email-root', '');
  // Template fragment parsing ignores <body> itself. Retain the body's basic
  // presentation attributes in an inert container before sanitizing them.
  const bodyTag = /<body\b(?:[^"'<>]|"[^"]*"|'[^']*')*>/i.exec(html)?.[0];
  if (bodyTag) {
    const bodyTemplate = document.createElement('template');
    bodyTemplate.innerHTML = `${bodyTag.replace(/^<body/i, '<div')}</div>`;
    const body = bodyTemplate.content.firstElementChild;
    for (const name of ['style', 'background', 'bgcolor', 'color', 'dir', 'lang']) {
      const value = body?.getAttribute(name);
      if (value) contentRoot.setAttribute(name, value);
    }
  }
  while (template.content.firstChild) contentRoot.append(template.content.firstChild);
  template.content.append(contentRoot);
  const inlineStyles = new WeakMap<HTMLElement, CSSStyleDeclaration>();
  for (const element of template.content.querySelectorAll<HTMLElement>('*')) {
    if (!('style' in element)) continue;
    const original = element.ownerDocument.createElement('span').style;
    original.cssText = element.style.cssText;
    inlineStyles.set(element, original);
  }

  // Constructed sheets do not fetch @imports and are never adopted into a
  // document. Keep simple matching rules as inline declarations; the normal
  // sanitizer below will retain safe styles and proxy background images.
  for (const source of template.content.querySelectorAll('style')) {
    try {
      const sheet = new CSSStyleSheet();
      sheet.replaceSync(source.textContent || '');
      for (const rule of Array.from(sheet.cssRules)) {
        if (!(rule instanceof CSSStyleRule)) continue;
        let matches: HTMLElement[] = [];
        for (const selector of rule.selectorText.split(',')) {
          const trimmed = selector.trim();
          if (['html', 'body', ':root'].includes(trimmed)) matches.push(contentRoot);
          else {
            try {
              matches.push(...template.content.querySelectorAll<HTMLElement>(trimmed));
            } catch {
              // One invalid selector must not prevent later valid rules.
            }
          }
        }
        for (const element of matches) {
          if (!('style' in element)) continue;
          for (let index = 0; index < rule.style.length; index += 1) {
            const property = rule.style[index];
            if (!inlineStyles.get(element)?.getPropertyValue(property)) {
              element.style.setProperty(property, rule.style.getPropertyValue(property), rule.style.getPropertyPriority(property));
            }
          }
        }
      }
    } catch {
      // Unsupported selectors or stylesheet syntax cannot expose resources.
    }
  }
  const imageUrls: string[] = [];
  const linkUrls: string[] = [];
  const linkIndexes = new Map<string, number>();
  const sourceIndexes = new Map<string, number>();
  const registerSource = (url: string) => {
    let index = sourceIndexes.get(url);
    if (index === undefined) {
      index = imageUrls.length;
      imageUrls.push(url);
      sourceIndexes.set(url, index);
    }
    return index;
  };

  const sanitize = (parent: DocumentFragment | Element) => {
    for (const child of Array.from(parent.childNodes)) {
      if (child.nodeType === Node.COMMENT_NODE) {
        child.remove();
        continue;
      }
      if (child.nodeType !== Node.ELEMENT_NODE) continue;
      const element = child as HTMLElement;
      const tag = element.localName;
      if (REMOVE_CONTENT.has(tag) || element.namespaceURI !== 'http://www.w3.org/1999/xhtml') {
        element.remove();
        continue;
      }
      if (!SAFE_TAGS.has(tag)) {
        // Keep text/basic formatting from unknown containers, but never copy
        // their potentially active attributes or custom element names.
        sanitize(element);
        element.replaceWith(...Array.from(element.childNodes));
        continue;
      }

      const style = safeStyle(element);
      const background = element.style.getPropertyValue('background-image');
      const backgroundMatch = !background.includes('\\')
        ? /^url\(\s*(['"]?)(.*?)\1\s*\)$/i.exec(background)
        : null;
      const backgroundSource = remoteImageUrl(element.getAttribute('background')) || remoteImageUrl(backgroundMatch?.[2] || null);
      const href = element.getAttribute('href')?.trim();
      const originalSource = element.getAttribute('src')?.trim();
      const pictureSource = tag === 'img' && element.parentElement?.localName === 'picture'
        ? Array.from(element.parentElement.querySelectorAll('source')).map((source) => source.getAttribute('srcset')).find(Boolean) || null
        : null;
      const remoteSource = tag === 'img'
        ? remoteImageUrl(originalSource || null) || (!originalSource
          ? firstImageSource(element.getAttribute('srcset')) || firstImageSource(pictureSource)
          : null)
        : null;

      for (const attribute of Array.from(element.attributes)) {
        if (!SAFE_ATTRIBUTES.has(attribute.name)) element.removeAttribute(attribute.name);
      }
      if (style) element.setAttribute('style', style);
      if (backgroundSource) {
        element.setAttribute('data-email-background', String(registerSource(backgroundSource)));
      }
      const linkUrl = tag === 'a' ? externalLinkUrl(href) : null;
      if (linkUrl) {
        let index = linkIndexes.get(linkUrl);
        if (index === undefined) {
          index = linkUrls.length;
          linkUrls.push(linkUrl);
          linkIndexes.set(linkUrl, index);
        }
        // No navigable href survives, including browser context-menu actions.
        element.setAttribute('data-email-link', String(index));
        element.setAttribute('role', 'link');
        element.setAttribute('tabindex', '0');
      }
      if (tag === 'img') {
        element.setAttribute('referrerpolicy', 'no-referrer');
        if (originalSource && RASTER_DATA.test(originalSource)) {
          element.setAttribute('src', originalSource);
        } else if (remoteSource) {
          const index = registerSource(remoteSource);
          element.setAttribute('data-email-image', String(index));
          element.setAttribute('data-email-alt', element.getAttribute('alt') || '');
        }
      }
      sanitize(element);
    }
  };

  // Record picture alternatives before source tags are removed by traversal.
  for (const picture of template.content.querySelectorAll('picture')) {
    const image = picture.querySelector('img');
    if (image && !image.getAttribute('src') && !image.getAttribute('srcset')) {
      const source = Array.from(picture.querySelectorAll('source')).map((entry) => entry.getAttribute('srcset')).find(Boolean);
      if (source) image.setAttribute('srcset', source);
    }
  }
  sanitize(template.content);
  return { html: template.innerHTML, imageUrls, linkUrls };
}

export function renderEmailHtml(
  prepared: PreparedEmailHtml,
  images: ReadonlyMap<string, EmailImageState>,
): RenderedEmailHtml {
  const template = document.createElement('template');
  template.innerHTML = prepared.html;
  let renderedBytes = 0;
  let hasRenderBlocked = false;
  const canRender = (dataUrl: string) => {
    if (renderedBytes + dataUrl.length > MAX_RENDERED_IMAGE_BYTES) {
      hasRenderBlocked = true;
      return false;
    }
    renderedBytes += dataUrl.length;
    return true;
  };
  for (const image of template.content.querySelectorAll('img')) {
    const marker = image.getAttribute('data-email-image');
    const state = marker === null ? undefined : images.get(prepared.imageUrls[Number(marker)]);
    const alt = image.getAttribute('data-email-alt') ?? image.getAttribute('alt') ?? '';
    image.removeAttribute('data-email-alt');
    const dataUrl = state?.state === 'ready' ? state.dataUrl : image.getAttribute('src');
    if (dataUrl && canRender(dataUrl)) {
      image.setAttribute('src', dataUrl);
      image.setAttribute('alt', alt);
    } else {
      image.removeAttribute('src');
      const label = state?.state === 'loading' ? 'Downloading remote image…' : 'Remote image blocked';
      image.setAttribute('alt', alt ? `${alt} (${label})` : label);
      image.setAttribute('title', label);
    }
  }
  for (const element of template.content.querySelectorAll<HTMLElement>('[data-email-background]')) {
    const index = Number(element.getAttribute('data-email-background'));
    const state = images.get(prepared.imageUrls[index]);
    if (state?.state === 'ready' && state.dataUrl && canRender(state.dataUrl)) {
      element.style.backgroundImage = `url("${state.dataUrl}")`;
    }
  }
  const linkToken = prepared.linkUrls.length
    ? Array.from(crypto.getRandomValues(new Uint8Array(16)), (byte) => byte.toString(16).padStart(2, '0')).join('')
    : null;
  const policy = linkToken ? CSP.replace("script-src 'none'", `script-src 'nonce-${linkToken}'`) : CSP;
  const bridge = linkToken ? `<script nonce="${linkToken}">${linkBridge(linkToken)}</script>` : '';
  return {
    srcDoc: `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="${policy}"><meta name="referrer" content="no-referrer"><style>body{margin:0;padding:20px;font-family:Arial,sans-serif;line-height:1.5;overflow-wrap:anywhere}img{max-width:100%}img:not([src]){display:inline-block;min-height:24px;color:#596775;background:#edf1f4;border:1px solid #d3dce5}table{max-width:100%}pre{white-space:pre-wrap}a[data-email-link]{color:#1758aa;text-decoration:underline;cursor:pointer}a[data-email-link]:focus-visible{outline:2px solid #1758aa;outline-offset:3px}</style>${bridge}</head><body>${template.innerHTML}</body></html>`,
    hasRenderBlocked,
    linkToken,
  };
}
