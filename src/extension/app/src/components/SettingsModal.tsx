import { FormEvent, useEffect, useState } from 'react';
import { api, CategoryExpirationDays, DEFAULT_LOCAL_AI_MODEL, EMAIL_CATEGORIES, LocalClassifierStatus, MailSettings } from '../api';
import { categoryLabel, DEFAULT_CATEGORY_EXPIRATION_DAYS, MAX_EXPIRATION_DAYS, parseExpirationDays } from '../retention';

interface Props {
  messagesPerPage: number;
  categoryExpirationDays: CategoryExpirationDays;
  localAiModel: string;
  settingsLoaded: boolean;
  account?: string;
  onConfigureAccount?: () => void;
  onSaved: (settings: MailSettings) => void;
  onClose: () => void;
}

export default function SettingsModal({ messagesPerPage, categoryExpirationDays, localAiModel, settingsLoaded, account, onConfigureAccount, onSaved, onClose }: Props) {
  const [value, setValue] = useState(String(messagesPerPage));
  const [expirationValues, setExpirationValues] = useState(() => Object.fromEntries(EMAIL_CATEGORIES.map((category) => [category, String(categoryExpirationDays[category])])) as Record<typeof EMAIL_CATEGORIES[number], string>);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [settingsReady, setSettingsReady] = useState(settingsLoaded);
  const [loading, setLoading] = useState(false);
  const [initialExpirationDays, setInitialExpirationDays] = useState(categoryExpirationDays);
  const [model, setModel] = useState(localAiModel);
  const [initialModel, setInitialModel] = useState(localAiModel);
  const [checkingModel, setCheckingModel] = useState(false);
  const [modelStatus, setModelStatus] = useState<LocalClassifierStatus | null>(null);

  const changeModel = (next: string) => {
    setModel(next);
    setModelStatus(null);
  };

  const checkModel = async () => {
    if (checkingModel) return;
    setCheckingModel(true);
    setModelStatus(null);
    try {
      setModelStatus(await api.classifierStatus(model.trim()));
    } catch (failure) {
      setModelStatus({ available: false, model: model.trim(), installed_models: [], error: failure instanceof Error ? failure.message : String(failure) });
    } finally {
      setCheckingModel(false);
    }
  };

  const loadSettings = async () => {
    setLoading(true);
    setError('');
    try {
      const settings = await api.settings();
      const days = { ...DEFAULT_CATEGORY_EXPIRATION_DAYS, ...settings.category_expiration_days };
      setValue(String(settings.messages_per_page));
      const savedModel = settings.local_ai_model ?? DEFAULT_LOCAL_AI_MODEL;
      setInitialModel(savedModel);
      changeModel(savedModel);
      setInitialExpirationDays(days);
      setExpirationValues(Object.fromEntries(EMAIL_CATEGORIES.map((category) => [category, String(days[category])])) as Record<typeof EMAIL_CATEGORIES[number], string>);
      setSettingsReady(true);
    } catch (failure) {
      setError(`Could not load settings. ${failure instanceof Error ? failure.message : String(failure)}`);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    const keydown = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !saving) onClose();
    };
    document.addEventListener('keydown', keydown);
    return () => document.removeEventListener('keydown', keydown);
  }, [onClose, saving]);

  const save = async (event: FormEvent) => {
    event.preventDefault();
    if (saving || !settingsReady) return;
    const size = Number(value);
    if (!Number.isInteger(size) || size < 1 || size > 200) {
      setError('Enter a whole number from 1 to 200.');
      return;
    }
    const expirationDays = {} as CategoryExpirationDays;
    for (const category of EMAIL_CATEGORIES) {
      const days = parseExpirationDays(expirationValues[category]);
      if (days === null) {
        setError(`Enter whole days for ${categoryLabel(category)}, up to ${MAX_EXPIRATION_DAYS}. Use a negative number to never expire.`);
        return;
      }
      expirationDays[category] = days;
    }
    const retentionChanged = EMAIL_CATEGORIES.some((category) => expirationDays[category] !== initialExpirationDays[category]);
    const selectedModel = model.trim();
    if (!/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$/.test(selectedModel) || selectedModel.includes('..') || selectedModel.includes('://')) {
      setError('Enter a local Ollama model name up to 200 characters, such as llama3.2:latest.');
      return;
    }
    setSaving(true);
    setError('');
    try {
      const result = await api.saveSettings(size, undefined, retentionChanged ? expirationDays : undefined, selectedModel !== initialModel ? selectedModel : undefined);
      onSaved(result);
      onClose();
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : String(failure));
    } finally {
      setSaving(false);
    }
  };

  return <div className="modal-backdrop settings-backdrop">
    <section className="settings-modal" role="dialog" aria-modal="true" aria-labelledby="settings-title">
      <div className="settings-heading">
        <h2 id="settings-title">Settings</h2>
        <button className="icon-btn" type="button" onClick={onClose} disabled={saving} aria-label="Close settings">×</button>
      </div>
      <form onSubmit={(event) => void save(event)}>
        <label className="field">
          <span>Messages per page</span>
          <input type="number" aria-label="Messages per page" min="1" max="200" step="1" required autoFocus value={value} disabled={saving || !settingsReady} onChange={(event) => setValue(event.target.value)} />
          <small className="muted">Choose 1–200 emails per page. The default is 5.</small>
        </label>
        <p className="muted">Selections apply only to emails on the current page.</p>
        <fieldset className="retention-settings" disabled={saving || !settingsReady}>
          <legend>Email expiration</legend>
          <p className="muted">Days from the server received date. Any negative number means never expire (-1). Expired emails stay in your mailbox until you select them and move them to Trash.</p>
          <div className="retention-settings-fields">
            {EMAIL_CATEGORIES.map((category) => <label className="field" key={category}>
              <span>{categoryLabel(category)} expiration days</span>
              <input type="number" max={MAX_EXPIRATION_DAYS} step="1" required value={expirationValues[category]} onChange={(event) => setExpirationValues((values) => ({ ...values, [category]: event.target.value }))} />
            </label>)}
          </div>
          <small className="muted">Category settings also apply to existing emails. Individual expiration overrides are kept.</small>
        </fieldset>
        <fieldset className="retention-settings" disabled={saving || !settingsReady}>
          <legend>Local AI classification</legend>
          <p className="muted">Use Auto classification on an open email to classify it with Ollama running on the backend computer. Its sender, subject, and body are sent to the local model; attachments are excluded.</p>
          <label className="field">
            <span>Local AI model</span>
            <input type="text" maxLength={200} required value={model} disabled={checkingModel} onChange={(event) => changeModel(event.target.value)} />
          </label>
          <button className="btn subtle" type="button" disabled={checkingModel || !model.trim()} onClick={() => void checkModel()}>{checkingModel ? 'Checking local model...' : 'Check local model'}</button>
          {modelStatus && <div className="local-model-status" role="status">
            <p className={modelStatus.available ? 'muted' : 'banner error'}>{modelStatus.available ? `${modelStatus.model} is ready for local classification.` : modelStatus.error || `${modelStatus.model} is not available locally.`}</p>
            {modelStatus.installed_models.length > 0 && <label className="field">
              <span>Installed local models</span>
              <select value={modelStatus.installed_models.includes(model.trim()) ? model.trim() : ''} onChange={(event) => changeModel(event.target.value)}>
                <option value="" disabled>Select an installed model</option>
                {modelStatus.installed_models.map((installed) => <option key={installed} value={installed}>{installed}</option>)}
              </select>
            </label>}
          </div>}
          <p className="muted">Install and start Ollama, then download a model manually, for example <code>ollama pull llama3.2</code>. The service must run at <code>127.0.0.1:11434</code>. Save your selected model to use it. Classification replaces this email's category and preserves individual expiration overrides.</p>
        </fieldset>
        {!settingsReady && <div>
          <p className="muted">Load your saved settings before editing expiration periods.</p>
          <button className="btn" type="button" disabled={loading} onClick={() => void loadSettings()}>{loading ? 'Loading settings...' : 'Retry loading settings'}</button>
        </div>}
        <div className="settings-signature-shortcut">
          <p className="muted">Rich signatures, images, and emojis are saved separately for each email account under its configuration.</p>
          {account && onConfigureAccount && <button className="btn" type="button" disabled={saving} onClick={onConfigureAccount}>Configure {account}</button>}
        </div>
        {error && <div className="banner error" role="alert">{error}</div>}
        <div className="settings-actions">
          <button className="btn subtle" type="button" onClick={onClose} disabled={saving}>Cancel</button>
          <button className="btn primary" type="submit" disabled={saving || !settingsReady}>{saving ? 'Saving…' : 'Save settings'}</button>
        </div>
      </form>
    </section>
  </div>;
}
