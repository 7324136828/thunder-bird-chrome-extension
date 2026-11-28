import { FormEvent, useEffect, useState } from 'react';
import { CategoryFilter, EMAIL_CATEGORIES, MessageReadStatus, MessageSummary } from '../api';
import { categoryLabel, expirationLabel } from '../retention';
import { POP3_COMPAT_NOTE } from '../platform/mailProtocol';

interface Props {
  account: string;
  folder: string;
  messages: MessageSummary[];
  total: number;
  offset: number;
  limit: number;
  loading: boolean;
  deleting: boolean;
  mutationBusy?: boolean;
  checkedUids: number[];
  trashFolder: string;
  isTrash: boolean;
  trashBusy: boolean;
  onTrashAction: (archive: boolean) => void;
  onCheck: (uid: number) => void;
  onCheckPage: () => void;
  onDeleteSelected: () => void;
  selectedUid: number | null;
  onSelect: (uid: number) => void;
  onPage: (offset: number) => void;
  onSearch: (query: string) => void;
  onRefresh: () => void;
  senderDomains: string[];
  onClearDomain: () => void;
  searchQuery: string;
  readStatus: MessageReadStatus;
  onReadStatusChange: (status: MessageReadStatus) => void;
  categoryFilter: CategoryFilter;
  expiredOnly: boolean;
  onCategoryFilterChange: (category: CategoryFilter) => void;
  onExpiredOnlyChange: (expiredOnly: boolean) => void;
  /**
   * Extension: POP3 compatibility account. Selection, Move to Trash, Trash
   * actions and the read-status filter are hidden (the backend refuses the
   * mutations with 400 and POP3 has no server read state).
   */
  pop3?: boolean;
}

function formatDate(iso: string | null): string {
  if (!iso) return '';
  const date = new Date(iso);
  const today = new Date();
  const sameDay = date.toDateString() === today.toDateString();
  return sameDay
    ? date.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
    : date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

export default function MessageList({
  account,
  folder,
  messages,
  total,
  offset,
  limit,
  loading,
  deleting,
  mutationBusy = false,
  checkedUids,
  trashFolder,
  isTrash,
  trashBusy,
  onTrashAction,
  onCheck,
  onCheckPage,
  onDeleteSelected,
  selectedUid,
  onSelect,
  onPage,
  onSearch,
  onRefresh,
  senderDomains,
  onClearDomain,
  searchQuery,
  readStatus,
  onReadStatusChange,
  categoryFilter,
  expiredOnly,
  onCategoryFilterChange,
  onExpiredOnlyChange,
  pop3 = false,
}: Props) {
  const [query, setQuery] = useState(searchQuery);
  useEffect(() => setQuery(searchQuery), [searchQuery]);
  const busy = loading || deleting || trashBusy;
  const allChecked = messages.length > 0 && messages.every((message) => checkedUids.includes(message.uid));
  const trashUnavailable = !trashFolder || trashFolder === folder;
  const pageStart = total === 0 ? 0 : offset + 1;
  const pageEnd = Math.min(offset + limit, total);

  const submitSearch = (event: FormEvent) => {
    event.preventDefault();
    onSearch(query);
  };

  return (
    <section className="message-list">
      {senderDomains.length > 0 && <div className="domain-filter-banner">
        <span>Sender domain: {senderDomains.join(', ')}</span>
        <small>Includes subdomains. Select page selects only visible emails.</small>
        <button className="btn subtle" type="button" onClick={onClearDomain} disabled={busy}>Clear domain filter</button>
      </div>}
      <div className="message-list-toolbar">
        <form onSubmit={submitSearch} className="search-form">
          <input
            type="search"
            aria-label={`Search ${folder}`}
            disabled={busy}
            placeholder={`Search ${folder}…`}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <button className="btn subtle" type="submit" disabled={busy}>
            Search
          </button>
        </form>
        <button className="btn subtle" type="button" onClick={onRefresh} disabled={busy} aria-label="Refresh messages">
          ⟳
        </button>
      </div>

      <div className="message-status-toolbar">
        {!pop3 && <label className="field">
          <span>Message status</span>
          <select value={readStatus} onChange={(event) => onReadStatusChange(event.target.value as MessageReadStatus)} disabled={busy}>
            <option value="all">All messages</option>
            <option value="unread">Unread</option>
            <option value="read">Read</option>
          </select>
        </label>}
        <label className="field">
          <span>Email category</span>
          <select value={categoryFilter} onChange={(event) => onCategoryFilterChange(event.target.value as CategoryFilter)} disabled={busy}>
            <option value="all">All categories</option>
            {EMAIL_CATEGORIES.map((category) => <option key={category} value={category}>{categoryLabel(category)}</option>)}
          </select>
        </label>
        <label className="expired-only-filter">
          <input type="checkbox" checked={expiredOnly} onChange={(event) => onExpiredOnlyChange(event.target.checked)} disabled={busy} />
          <span>Expired only</span>
        </label>
        {expiredOnly && !pop3 && <small className="muted">Select expired emails on this page and move them to Trash.</small>}
      </div>

      {isTrash && !pop3 && <div className="trash-actions-toolbar">
        <div className="trash-action-buttons">
          <button className="btn subtle" type="button" onClick={() => onTrashAction(true)} disabled={busy || mutationBusy}>
            Archive and empty
          </button>
          <button className="btn danger" type="button" onClick={() => onTrashAction(false)} disabled={busy || mutationBusy}>
            Empty trash bin
          </button>
        </div>
        <small className="muted">Applies to all emails in server Trash, across every page and search filter.</small>
      </div>}

      {pop3 ? <div className="message-selection-toolbar pop3-note">
        <p className="muted selection-help" role="note">{POP3_COMPAT_NOTE}</p>
      </div> : <div className="message-selection-toolbar">
        <button className="btn subtle" type="button" onClick={onCheckPage} disabled={busy || messages.length === 0}>
          {allChecked ? 'Clear selection' : 'Select page'}
        </button>
        <span className="muted selection-count" aria-live="polite">{checkedUids.length} selected</span>
        <button
          className="btn danger"
          type="button"
          onClick={onDeleteSelected}
          disabled={busy || mutationBusy || checkedUids.length === 0 || trashUnavailable}
          title="Move selected messages to Trash on the mail server"
        >
          {deleting ? 'Moving to Trash…' : `Move to Trash${checkedUids.length ? ` (${checkedUids.length})` : ''}`}
        </button>
        {trashUnavailable && (
          <p className="muted selection-help">
            {trashFolder ? 'These messages are already in server Trash.' : 'No server Trash folder was found. Bulk removal is unavailable.'}
          </p>
        )}
      </div>}

      <div className="message-rows" role="list" aria-label={`Messages in ${folder}`} aria-busy={busy}>
        {messages.map((message) => (
          <div key={message.uid} role="listitem" className={`message-row-container ${checkedUids.includes(message.uid) ? 'checked' : ''}`}>
            {!pop3 && <input
              type="checkbox"
              className="message-checkbox"
              aria-label={`Select message: ${message.subject || '(no subject)'}`}
              checked={checkedUids.includes(message.uid)}
              onChange={() => onCheck(message.uid)}
              disabled={busy}
            />}
            <button
              type="button"
              aria-pressed={message.uid === selectedUid}
              disabled={busy}
              className={`message-row ${message.uid === selectedUid ? 'active' : ''} ${
                message.seen ? '' : 'unread'
              }`}
              onClick={() => onSelect(message.uid)}
            >
              <span className="row-from">
                {message.flagged && <span className="flag">★</span>}
                {message.from || '(unknown sender)'}
              </span>
              <span className="row-subject">{message.subject || '(no subject)'}</span>
              <span className="row-date">{formatDate(message.date)}</span>
              {message.category && <span className="row-retention">
                <span className={`category-badge category-${message.category}`}>{categoryLabel(message.category)}</span>
                <span className={message.expired ? 'expiration-status expired' : 'expiration-status'}>{expirationLabel(message, true)}</span>
              </span>}
            </button>
          </div>
        ))}
        {!loading && messages.length === 0 && (
          <p className="muted empty-state">
            {account ? 'No messages found in this folder.' : ''}
          </p>
        )}
        {loading && <p className="muted empty-state">Loading…</p>}
      </div>

      <div className="message-list-footer">
        <span className="muted">
          {pageStart}–{pageEnd} of {total}
        </span>
        <span className="pager">
          <button
            className="btn subtle"
            type="button"
            disabled={offset === 0 || busy}
            onClick={() => onPage(Math.max(0, offset - limit))}
          >
            ‹ Newer
          </button>
          <button
            className="btn subtle"
            type="button"
            disabled={offset + limit >= total || busy}
            onClick={() => onPage(offset + limit)}
          >
            Older ›
          </button>
        </span>
      </div>
    </section>
  );
}
