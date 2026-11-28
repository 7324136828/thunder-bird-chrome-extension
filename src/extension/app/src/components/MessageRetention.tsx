import { useEffect, useState } from 'react';
import { EMAIL_CATEGORIES, EmailCategory, FullMessage, RetentionUpdate } from '../api';
import { categoryLabel, expirationLabel, MAX_EXPIRATION_DAYS, parseExpirationDays } from '../retention';

interface Props {
  message: FullMessage;
  busy: boolean;
  saving: boolean;
  onUpdate: (update: RetentionUpdate) => void;
  folder: string;
  senderRuleSaving: boolean;
  onSaveSenderRule: () => void;
  onRemoveSenderRule: () => void;
}

export default function MessageRetention({ message, busy, saving, onUpdate, folder, senderRuleSaving, onSaveSenderRule, onRemoveSenderRule }: Props) {
  const [category, setCategory] = useState<EmailCategory>(message.category ?? 'uncategorized');
  const [expirationDays, setExpirationDays] = useState(String(message.expiration_days ?? -1));
  const [error, setError] = useState('');
  const cannotEdit = busy || !message.uid_validity;
  const senderRuleMatches = message.sender_rule?.category === message.category;
  const hasSender = Boolean(message.from_addr && message.from_addr.includes('@'));

  useEffect(() => setCategory(message.category ?? 'uncategorized'), [message.category, message.category_source]);
  useEffect(() => { setExpirationDays(String(message.expiration_days ?? -1)); setError(''); }, [message.expiration_days, message.expiration_source]);

  const saveExpiration = () => {
    const days = parseExpirationDays(expirationDays);
    if (days === null) {
      setError(`Enter whole days up to ${MAX_EXPIRATION_DAYS}, or a negative number to never expire.`);
      return;
    }
    setError('');
    onUpdate({ expiration_days: days });
  };

  return <details className="message-retention">
    <summary>Category and expiration</summary>
    <div className="retention-summary">
      <span className={`category-badge category-${message.category ?? 'uncategorized'}`}>{categoryLabel(message.category ?? 'uncategorized')}</span>
      <span>{message.category_source === 'sender_rule' ? 'Rule categorized' : message.category_source === 'ai' ? 'AI categorized' : message.category_source === 'manual' ? 'Manually categorized' : 'Automatically categorized'}</span>
      {message.category_source === 'ai' && message.category_model && <span className="muted">{message.category_model}</span>}
      <span className={message.expired ? 'expiration-status expired' : 'expiration-status'}>{expirationLabel(message)}</span>
      <span className="muted">{message.expiration_source === 'manual' ? 'Individual expiration' : 'Category expiration'}</span>
    </div>
    {message.category_reason && <p className="muted category-reason">{message.category_reason}</p>}
    <div className="retention-edit-row">
      <label className="field">
        <span>Message category</span>
        <select value={category} disabled={cannotEdit} onChange={(event) => setCategory(event.target.value as EmailCategory)}>
          {EMAIL_CATEGORIES.map((item) => <option key={item} value={item}>{categoryLabel(item)}</option>)}
        </select>
      </label>
      <button className="btn subtle" type="button" disabled={cannotEdit} onClick={() => onUpdate({ category })}>Save category</button>
      <button className="btn subtle" type="button" disabled={cannotEdit || (message.category_source !== 'manual' && message.category_source !== 'ai')} onClick={() => onUpdate({ category: null })}>{message.category_source === 'ai' ? 'Use rule-based category' : 'Use automatic category'}</button>
    </div>
    <div className="retention-edit-row sender-rule-actions">
      <button className="btn subtle" type="button" disabled={cannotEdit || !hasSender || !message.category || senderRuleMatches} onClick={onSaveSenderRule} title={`Use this email's saved category for future emails from ${message.from_addr} in ${folder}.`}>
        Categorize the same from the same mail inbox
      </button>
      {message.sender_rule && <button className="btn subtle" type="button" disabled={busy} onClick={onRemoveSenderRule}>Remove sender rule</button>}
    </div>
    {message.sender_rule ? <p className="muted sender-rule-status" role="status">Future emails from {message.sender_rule.sender} in {folder} will use {categoryLabel(message.sender_rule.category)}. {senderRuleMatches && 'Saved for future emails.'}</p> : hasSender && message.category ? <p className="muted sender-rule-status">Future emails from {message.from_addr} in {folder} will use {categoryLabel(message.category)} when you save this rule.</p> : <p className="muted sender-rule-status">A sender address is required to categorize future emails.</p>}
    {category !== message.category && <p className="muted">Save the selected category first to use it for future emails.</p>}
    {senderRuleSaving && <p className="muted" role="status">Saving sender rule...</p>}
    <div className="retention-edit-row">
      <label className="field">
        <span>Message expiration days</span>
        <input type="number" step="1" max={MAX_EXPIRATION_DAYS} value={expirationDays} disabled={cannotEdit} onChange={(event) => setExpirationDays(event.target.value)} />
      </label>
      <button className="btn subtle" type="button" disabled={cannotEdit} onClick={saveExpiration}>Save expiration</button>
      <button className="btn subtle" type="button" disabled={cannotEdit || message.expiration_source !== 'manual'} onClick={() => onUpdate({ expiration_days: null })}>Use category expiration</button>
    </div>
    <p className="muted retention-help">Expiration is measured from the server received date. Any negative number means never expire (-1). Expired emails can be selected and moved to Trash.</p>
    {!message.uid_validity && <p className="muted">Server message identity is unavailable. Refresh the message before changing its category or expiration.</p>}
    {error && <p className="banner error" role="alert">{error}</p>}
    {saving && <p className="muted" role="status">Saving email settings...</p>}
  </details>;
}
