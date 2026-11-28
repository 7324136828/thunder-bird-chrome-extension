import { useCallback, useEffect, useRef, useState } from 'react';
import {
  api,
  Account,
  ApiError,
  AuditReport,
  CategoryExpirationDays,
  CategoryFilter,
  DEFAULT_LOCAL_AI_MODEL,
  Folder,
  FullMessage,
  MailSettings,
  MessageReadStatus,
  MessageSummary,
  RetentionUpdate,
  TrashEmptyResult,
} from './api';
import AuditPanel from './components/AuditPanel';
import ComposeModal from './components/ComposeModal';
import ConnectScreen from './components/ConnectScreen';
import MessageList from './components/MessageList';
import MessageView from './components/MessageView';
import PasteAudit from './components/PasteAudit';
import Sidebar from './components/Sidebar';
import InboxDoctor from './components/InboxDoctor';
import EmailMetrics from './components/EmailMetrics';
import SettingsModal from './components/SettingsModal';
import TrashActionsModal from './components/TrashActionsModal';
import AccountSignatureModal from './components/AccountSignatureModal';
import { MailtoDraft, parseMailto } from './mailto';
import { onMailtoRequest, takeLaunchMailto } from './platform/launch';
import { isPop3Account, POP3_IMAP_ONLY_DETAIL } from './platform/mailProtocol';
import { DEFAULT_CATEGORY_EXPIRATION_DAYS } from './retention';

const DEFAULT_PAGE_SIZE = 5;

const mailViewKey = (account: string, folder: string, offset: number, query: string, domains: string[], readStatus: MessageReadStatus, limit: number, category: CategoryFilter, expiredOnly: boolean) =>
  JSON.stringify([account, folder, offset, query, domains, readStatus, limit, category, expiredOnly]);

interface ComposeState {
  id: number;
  account: string;
  replyTo?: FullMessage;
  forwardOf?: FullMessage;
  initialDraft?: MailtoDraft;
}

interface TrashAction {
  account: string;
  folder: string;
  archive: boolean;
}

export default function App() {
  const [workspace, setWorkspace] = useState<'mail' | 'doctor' | 'metrics'>(() => window.location.hash === '#doctor' ? 'doctor' : window.location.hash === '#metrics' ? 'metrics' : 'mail');
  const [accounts, setAccounts] = useState<Account[]>([]);
  const [ready, setReady] = useState(false);
  const [showConnect, setShowConnect] = useState(false);
  const [relockEmail, setRelockEmail] = useState<string | null>(null);
  const [showSettings, setShowSettings] = useState(false);
  const [messagesPerPage, setMessagesPerPage] = useState(DEFAULT_PAGE_SIZE);
  const [categoryExpirationDays, setCategoryExpirationDays] = useState<CategoryExpirationDays>(DEFAULT_CATEGORY_EXPIRATION_DAYS);
  const [localAiModel, setLocalAiModel] = useState(DEFAULT_LOCAL_AI_MODEL);
  const [settingsLoaded, setSettingsLoaded] = useState(false);
  const [configurationAccount, setConfigurationAccount] = useState<string | null>(null);

  const [selectedAccount, setSelectedAccount] = useState('');
  const [folders, setFolders] = useState<Folder[]>([]);
  const [selectedFolder, setSelectedFolder] = useState('INBOX');

  const [messages, setMessages] = useState<MessageSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [query, setQuery] = useState('');
  const [senderDomains, setSenderDomains] = useState<string[]>([]);
  const [readStatus, setReadStatus] = useState<MessageReadStatus>('all');
  const [categoryFilter, setCategoryFilter] = useState<CategoryFilter>('all');
  const [expiredOnly, setExpiredOnly] = useState(false);
  const mailFilters = useRef<{ category: CategoryFilter; expiredOnly: boolean }>({ category: 'all', expiredOnly: false });
  const [listLoading, setListLoading] = useState(false);
  const [checkedUids, setCheckedUids] = useState<number[]>([]);
  const [deleting, setDeleting] = useState(false);
  const [trashAction, setTrashAction] = useState<TrashAction | null>(null);
  const trashChanged = useRef(false);

  const [selectedUid, setSelectedUid] = useState<number | null>(null);
  const [message, setMessage] = useState<FullMessage | null>(null);
  const [messageLoading, setMessageLoading] = useState(false);

  const [compose, setCompose] = useState<ComposeState | null>(null);
  const composeSequence = useRef(0);
  const [audit, setAudit] = useState<{ report: AuditReport | null; loading: boolean } | null>(null);
  const [pasteAudit, setPasteAudit] = useState(false);
  const [notice, setNotice] = useState('');
  // Extension: a mailto: link from the "Compose with Webmail" context menu.
  const [pendingMailto, setPendingMailto] = useState<string | null>(() => takeLaunchMailto());

  const pendingAfterUnlock = useRef<{
    retry: () => void;
    isCurrent: () => boolean;
    priority: number;
  }[]>([]);
  const listRequest = useRef(0);
  const folderRequest = useRef(0);
  const messageRequest = useRef(0);
  const activeView = useRef('');
  const readerUid = useRef<number | null>(null);
  const deletingRef = useRef(false);
  const retentionSavingRef = useRef(false);
  const [retentionSaving, setRetentionSaving] = useState(false);
  const classificationBusyRef = useRef(false);
  const [classificationTarget, setClassificationTarget] = useState<{ account: string; folder: string; uid: number; uidValidity: string } | null>(null);
  const senderRuleBusyRef = useRef(false);
  const [senderRuleTarget, setSenderRuleTarget] = useState<{ account: string; folder: string; uid: number } | null>(null);
  const credentialVersion = useRef(0);
  const pageSize = useRef(DEFAULT_PAGE_SIZE);

  useEffect(() => {
    const changed = () => setWorkspace(window.location.hash === '#doctor' ? 'doctor' : window.location.hash === '#metrics' ? 'metrics' : 'mail');
    window.addEventListener('hashchange', changed);
    return () => window.removeEventListener('hashchange', changed);
  }, []);

  const openWorkspace = (next: 'mail' | 'doctor' | 'metrics') => {
    setWorkspace(next);
    window.location.hash = next;
  };

  /**
   * Run a request; on password_required prompt to re-unlock, then re-run the
   * whole UI-level operation given as ``retry``.
   */
  const guarded = useCallback(
    async <T,>(
      fn: () => Promise<T>,
      retry?: () => void,
      isCurrent: () => boolean = () => true,
      priority = 0,
    ): Promise<T | null> => {
      const version = credentialVersion.current;
      try {
        return await fn();
      } catch (error) {
        const needed = error instanceof ApiError ? error.passwordRequired : null;
        if (!needed) throw error;
        if (!isCurrent()) return null;
        // An older request can finish after the password was already restored.
        if (version !== credentialVersion.current) return guarded(fn, retry, isCurrent, priority);
        if (retry) pendingAfterUnlock.current.push({ retry, isCurrent, priority });
        setRelockEmail(needed.email);
        return null;
      }
    },
    [],
  );

  const refreshAccounts = useCallback(async () => {
    const data = await api.accounts();
    setAccounts(data.accounts);
    return data.accounts;
  }, []);

  const loadFolders = useCallback(
    async (email: string, reportErrors = true): Promise<void> => {
      const requestId = ++folderRequest.current;
      try {
        const data = await guarded(
          () => api.folders(email),
          () => { if (requestId === folderRequest.current) void loadFolders(email, reportErrors); },
          () => requestId === folderRequest.current,
        );
        if (data && requestId === folderRequest.current) setFolders(data.folders);
      } catch (error) {
        if (reportErrors && requestId === folderRequest.current) setNotice(error instanceof ApiError ? error.message : String(error));
      }
    },
    [guarded],
  );

  const loadMessages = useCallback(
    async (
      email: string, folder: string, newOffset: number, search: string,
      domains: string[] = [], status: MessageReadStatus = 'all', limit = pageSize.current, selectVisible = false, reportErrors = true,
      preserveReader = false,
      category = mailFilters.current.category, expired = mailFilters.current.expiredOnly,
    ): Promise<void> => {
      const requestId = ++listRequest.current;
      const view = mailViewKey(email, folder, newOffset, search, domains, status, limit, category, expired);
      if (activeView.current !== view) {
        setCheckedUids([]);
        setMessages([]);
        if (!preserveReader) {
          readerUid.current = null;
          ++messageRequest.current;
          setSelectedUid(null);
          setMessage(null);
          setMessageLoading(false);
        }
      }
      activeView.current = view;
      setListLoading(true);
      try {
        const data = await guarded(
          () => api.messages(email, folder, newOffset, limit, search, domains, status, category, expired),
          () => { if (requestId === listRequest.current) void loadMessages(email, folder, newOffset, search, domains, status, limit, selectVisible, reportErrors, preserveReader, category, expired); },
          () => requestId === listRequest.current,
        );
        if (data && requestId === listRequest.current) {
          const lastOffset = Math.max(0, Math.floor((data.total - 1) / limit) * limit);
          if (newOffset > lastOffset) {
            // Correct the page after membership changes without closing the email being read.
            await loadMessages(email, folder, lastOffset, search, domains, status, limit, selectVisible, reportErrors, true, category, expired);
            return;
          }
          setMessages(data.messages);
          setTotal(data.total);
          setOffset(data.offset);
          setCheckedUids((uids) => selectVisible
            ? data.messages.map((item) => item.uid)
            : uids.filter((uid) => data.messages.some((item) => item.uid === uid)));
        }
      } catch (error) {
        if (reportErrors && requestId === listRequest.current) setNotice(error instanceof ApiError ? error.message : String(error));
      } finally {
        if (requestId === listRequest.current) setListLoading(false);
      }
    },
    [guarded],
  );

  const selectAccount = useCallback(
    (email: string, folder = 'INBOX', domains: string[] = [], selectVisible = false) => {
      setSelectedAccount(email);
      setFolders([]);
      setSelectedFolder(folder);
      setMessages([]);
      setTotal(0);
      setOffset(0);
      setQuery('');
      setSenderDomains(domains);
      setReadStatus('all');
      setCategoryFilter('all');
      setExpiredOnly(false);
      mailFilters.current = { category: 'all', expiredOnly: false };
      setSelectedUid(null);
      readerUid.current = null;
      ++messageRequest.current;
      setMessageLoading(false);
      setCheckedUids([]);
      setMessage(null);
      void loadFolders(email);
      void loadMessages(email, folder, 0, '', domains, 'all', pageSize.current, selectVisible);
    },
    [loadFolders, loadMessages],
  );

  const selectFolder = useCallback(
    (name: string) => {
      setSelectedFolder(name);
      setCheckedUids([]);
      setOffset(0);
      setTotal(0);
      setSelectedUid(null);
      readerUid.current = null;
      ++messageRequest.current;
      setMessageLoading(false);
      setMessage(null);
      setQuery('');
      setSenderDomains([]);
      setReadStatus('all');
      setCategoryFilter('all');
      setExpiredOnly(false);
      mailFilters.current = { category: 'all', expiredOnly: false };
      void loadMessages(selectedAccount, name, 0, '');
    },
    [loadMessages, selectedAccount],
  );

  const openMessage = useCallback(
    async (uid: number, markSeen = true) => {
      if (deletingRef.current || retentionSavingRef.current || trashAction) return;
      const requestId = ++messageRequest.current;
      readerUid.current = uid;
      setSelectedUid(uid);
      setMessageLoading(true);
      try {
        const data = await guarded(
          () => api.message(selectedAccount, selectedFolder, uid, markSeen),
          () => { if (requestId === messageRequest.current) void openMessage(uid, markSeen); },
          () => requestId === messageRequest.current,
        );
        if (data && requestId === messageRequest.current) {
          setMessage(data);
          setMessages((items) =>
            items.map((item) =>
              item.uid === uid ? { ...item, seen: data.seen, flags: data.flags } : item,
            ),
          );
          if ((readStatus === 'unread' && data.seen) || (readStatus === 'read' && !data.seen)) {
            await loadMessages(selectedAccount, selectedFolder, offset, query, senderDomains, readStatus, messagesPerPage);
          }
        }
      } catch (error) {
        if (requestId === messageRequest.current) setNotice(error instanceof ApiError ? error.message : String(error));
      } finally {
        if (requestId === messageRequest.current) setMessageLoading(false);
      }
    },
    [guarded, loadMessages, selectedAccount, selectedFolder, offset, query, senderDomains, readStatus, messagesPerPage, trashAction],
  );

  useEffect(() => {
    let active = true;
    void Promise.allSettled([api.accounts(), api.settings()]).then(([accountResult, settingsResult]) => {
      if (!active) return;
      if (settingsResult.status === 'fulfilled') {
        pageSize.current = settingsResult.value.messages_per_page;
        setMessagesPerPage(pageSize.current);
        setCategoryExpirationDays({ ...DEFAULT_CATEGORY_EXPIRATION_DAYS, ...settingsResult.value.category_expiration_days });
        setLocalAiModel(settingsResult.value.local_ai_model ?? DEFAULT_LOCAL_AI_MODEL);
        setSettingsLoaded(true);
      } else {
        setNotice('Could not load mail settings. Using 5 messages per page.');
      }
      if (accountResult.status === 'fulfilled') {
        setAccounts(accountResult.value.accounts);
        if (accountResult.value.accounts.length > 0) selectAccount(accountResult.value.accounts[0].email);
      } else {
        setNotice(accountResult.reason instanceof ApiError ? accountResult.reason.message : String(accountResult.reason));
      }
      setReady(true);
    });
    return () => { active = false; };
  }, [selectAccount]);

  const unlocked = useCallback(async () => {
    const wasRelock = relockEmail !== null;
    ++credentialVersion.current;
    let list = accounts;
    try {
      list = await refreshAccounts();
    } catch (error) {
      setNotice(error instanceof ApiError ? error.message : String(error));
    }
    setRelockEmail(null);
    setShowConnect(false);
    if (wasRelock) {
      const pending = pendingAfterUnlock.current;
      pendingAfterUnlock.current = [];
      const current = pending.filter((operation) => operation.isCurrent());
      if (current.length > 0) {
        // Start read/list retries before the mutation locks the controls.
        current.sort((a, b) => a.priority - b.priority).forEach((operation) => {
          if (operation.isCurrent()) operation.retry();
        });
        return;
      }
    }
    const email = relockEmail ?? list[list.length - 1]?.email;
    if (email) selectAccount(email);
  }, [accounts, refreshAccounts, relockEmail, selectAccount]);

  const lockAccount = async (email: string) => {
    await api.lock(email).catch(() => {});
    const list = await refreshAccounts();
    if (selectedAccount === email) {
      setSelectedAccount('');
      setFolders([]);
      setMessages([]);
      setMessage(null);
      setSelectedUid(null);
      readerUid.current = null;
      ++messageRequest.current;
      ++listRequest.current;
      ++folderRequest.current;
      activeView.current = '';
      setCheckedUids([]);
      setSenderDomains([]);
      setReadStatus('all');
      setCategoryFilter('all');
      setExpiredOnly(false);
      mailFilters.current = { category: 'all', expiredOnly: false };
      setMessageLoading(false);
      setListLoading(false);
    }
    if (list.length > 0 && selectedAccount === email) selectAccount(list[0].email);
  };

  const trashFolder = folders.find((f) => f.special === 'trash' && f.selectable)?.name ?? '';
  // Extension: POP3 compatibility accounts can only list and read the INBOX;
  // the IMAP-only actions below are hidden and refused here as well.
  const selectedIsPop3 = isPop3Account(accounts.find((item) => item.email.toLowerCase() === selectedAccount.toLowerCase()));

  const removeMessages = async (uids: number[], bulk: boolean) => {
    if (selectedIsPop3) { setNotice(POP3_IMAP_ONLY_DETAIL); return; }
    if (bulk) uids = uids.filter((uid) => messages.some((item) => item.uid === uid));
    if (deletingRef.current || retentionSavingRef.current || classificationBusyRef.current || senderRuleBusyRef.current || trashAction || listLoading || uids.length === 0) return;
    if (bulk && (!trashFolder || trashFolder === selectedFolder)) return;
    let identityConflict = false;
    const identities = uids.map((uid) => {
      const summary = messages.find((item) => item.uid === uid);
      if (message?.uid === uid) {
        if (summary && (summary.uid_validity ?? null) !== (message.uid_validity ?? null)) identityConflict = true;
        return message.uid_validity;
      }
      return summary?.uid_validity;
    });
    const knownIdentities = identities.filter((identity): identity is string => Boolean(identity));
    if (identityConflict || (knownIdentities.length > 0 && knownIdentities.length !== identities.length) || new Set(knownIdentities).size > 1 || (expiredOnly && knownIdentities.length !== identities.length)) {
      setNotice('Server message identity changed or is unavailable. Refresh messages before moving them to Trash.');
      return;
    }
    const uidValidity = knownIdentities[0];
    const view = mailViewKey(selectedAccount, selectedFolder, offset, query, senderDomains, readStatus, messagesPerPage, categoryFilter, expiredOnly);
    if (activeView.current !== view) return;
    deletingRef.current = true;
    setDeleting(true);
    try {
      const result = await guarded<{ deleted: number | number[] }>(
        () => bulk
          ? api.deleteMessages(selectedAccount, selectedFolder, uids, trashFolder, uidValidity)
          : api.deleteMessage(selectedAccount, selectedFolder, uids[0], trashFolder, uidValidity),
        () => { if (activeView.current === view) void removeMessages(uids, bulk); },
        () => activeView.current === view,
        1,
      );
      if (!result) return;
      if (activeView.current === view) {
        setCheckedUids((checked) => checked.filter((uid) => !uids.includes(uid)));
        if (readerUid.current !== null && uids.includes(readerUid.current)) {
          ++messageRequest.current;
          readerUid.current = null;
          setMessageLoading(false);
          setMessage(null);
          setSelectedUid(null);
        }
        setNotice(trashFolder && trashFolder !== selectedFolder
          ? `${uids.length} ${uids.length === 1 ? 'message' : 'messages'} moved to server Trash.`
          : `${uids.length} ${uids.length === 1 ? 'message' : 'messages'} deleted from the server.`);
        await loadMessages(selectedAccount, selectedFolder, offset, query, senderDomains, readStatus, messagesPerPage);
      }
    } catch (error) {
      setNotice(error instanceof ApiError ? error.message : String(error));
      // A rejected request may still have moved some messages on the server.
      if (activeView.current === view) {
        if (readerUid.current !== null && uids.includes(readerUid.current)) {
          ++messageRequest.current;
          readerUid.current = null;
          setMessageLoading(false);
          setMessage(null);
          setSelectedUid(null);
        }
        await loadMessages(selectedAccount, selectedFolder, offset, query, senderDomains, readStatus, messagesPerPage);
      }
    } finally {
      deletingRef.current = false;
      setDeleting(false);
    }
  };

  const toggleFlag = async (uid: number, flagged: boolean) => {
    if (selectedIsPop3) { setNotice(POP3_IMAP_ONLY_DETAIL); return; }
    try {
      const result = await api.setFlags(selectedAccount, selectedFolder, uid, { flagged });
      setMessage((m) => (m && m.uid === uid ? { ...m, flagged: result.flagged, flags: result.flags } : m));
      setMessages((items) =>
        items.map((item) => (item.uid === uid ? { ...item, flagged: result.flagged, flags: result.flags } : item)),
      );
    } catch (error) {
      setNotice(error instanceof ApiError ? error.message : String(error));
    }
  };

  const toggleSeen = async (uid: number, seen: boolean) => {
    if (selectedIsPop3) { setNotice(POP3_IMAP_ONLY_DETAIL); return; }
    const view = mailViewKey(selectedAccount, selectedFolder, offset, query, senderDomains, readStatus, messagesPerPage, categoryFilter, expiredOnly);
    try {
      const result = await api.setFlags(selectedAccount, selectedFolder, uid, { seen });
      if (activeView.current !== view) return;
      setMessage((m) => (m && m.uid === uid ? { ...m, seen: result.seen, flags: result.flags } : m));
      setMessages((items) =>
        items.map((item) => (item.uid === uid ? { ...item, seen: result.seen, flags: result.flags } : item)),
      );
      if (readStatus !== 'all') {
        await loadMessages(selectedAccount, selectedFolder, offset, query, senderDomains, readStatus, messagesPerPage);
      }
    } catch (error) {
      setNotice(error instanceof ApiError ? error.message : String(error));
    }
  };

  const updateRetention = async (update: RetentionUpdate) => {
    if (!message || !message.uid_validity || retentionSavingRef.current || classificationBusyRef.current || senderRuleBusyRef.current || deletingRef.current || listLoading || trashAction) return;
    const uid = message.uid;
    const requestId = messageRequest.current;
    const view = activeView.current;
    const isCurrent = () => activeView.current === view && readerUid.current === uid && messageRequest.current === requestId;
    retentionSavingRef.current = true;
    setRetentionSaving(true);
    try {
      const result = await guarded(
        () => api.updateRetention(selectedAccount, selectedFolder, uid, message.uid_validity, update),
        () => { if (isCurrent()) void updateRetention(update); },
        isCurrent,
        1,
      );
      if (!result || !isCurrent()) return;
      setMessage((item) => item && item.uid === uid ? { ...item, ...result } : item);
      setMessages((items) => items.map((item) => item.uid === uid ? { ...item, ...result } : item));
      setNotice('Email category and expiration saved.');
      await loadMessages(selectedAccount, selectedFolder, offset, query, senderDomains, readStatus, messagesPerPage, false, true, true);
    } catch (error) {
      if (isCurrent()) setNotice(error instanceof ApiError ? error.message : String(error));
    } finally {
      retentionSavingRef.current = false;
      setRetentionSaving(false);
    }
  };

  const classifyMessage = async () => {
    if (!message || !message.uid_validity || !settingsLoaded || classificationBusyRef.current || senderRuleBusyRef.current || retentionSavingRef.current || deletingRef.current || listLoading || trashAction) return;
    const uid = message.uid;
    const requestId = messageRequest.current;
    const view = activeView.current;
    const isCurrent = () => activeView.current === view && readerUid.current === uid && messageRequest.current === requestId;
    classificationBusyRef.current = true;
    setClassificationTarget({ account: selectedAccount, folder: selectedFolder, uid, uidValidity: message.uid_validity });
    try {
      const result = await guarded(
        () => api.classifyMessage(selectedAccount, selectedFolder, uid, message.uid_validity!),
        () => { if (isCurrent()) void classifyMessage(); },
        isCurrent,
        1,
      );
      if (!result || !isCurrent()) return;
      setMessage((item) => item && item.uid === uid ? { ...item, ...result } : item);
      setMessages((items) => items.map((item) => item.uid === uid ? { ...item, ...result } : item));
      setNotice('Email categorized with the local AI model.');
      await loadMessages(selectedAccount, selectedFolder, offset, query, senderDomains, readStatus, messagesPerPage, false, true, true);
    } catch (error) {
      if (isCurrent()) setNotice(error instanceof ApiError ? error.message : String(error));
    } finally {
      classificationBusyRef.current = false;
      setClassificationTarget(null);
    }
  };

  const mutateSenderRule = async (remove = false) => {
    if (!message || senderRuleBusyRef.current || retentionSavingRef.current || classificationBusyRef.current || deletingRef.current || listLoading || trashAction) return;
    if (remove ? !message.sender_rule : !message.uid_validity || !message.from_addr || !message.category || message.sender_rule?.category === message.category) return;
    const uid = message.uid;
    const requestId = messageRequest.current;
    const view = activeView.current;
    const isCurrent = () => activeView.current === view && readerUid.current === uid && messageRequest.current === requestId;
    senderRuleBusyRef.current = true;
    setSenderRuleTarget({ account: selectedAccount, folder: selectedFolder, uid });
    try {
      if (remove) {
        const result = await guarded(
          () => api.deleteSenderRule(selectedAccount, selectedFolder, message.sender_rule!.sender, message.sender_rule!.revision),
          () => { if (isCurrent()) void mutateSenderRule(true); },
          isCurrent,
          1,
        );
        if (!result || !isCurrent()) return;
        setMessage((item) => item && item.uid === uid ? { ...item, sender_rule: null } : item);
        // Re-read current metadata while keeping categories assigned by earlier rules.
        const updated = await guarded(
          () => api.message(selectedAccount, selectedFolder, uid, false),
          () => { if (isCurrent()) void openMessage(uid, false); },
          isCurrent,
        );
        if (!isCurrent()) return;
        if (updated) setMessage(updated);
        else setMessage((item) => item && item.uid === uid ? { ...item, sender_rule: null } : item);
        setNotice('Sender rule removed for future emails.');
      } else {
        const result = await guarded(
          () => api.saveSenderRule(selectedAccount, selectedFolder, uid, message.uid_validity!, message.category!),
          () => { if (isCurrent()) void mutateSenderRule(); },
          isCurrent,
          1,
        );
        if (!result || !isCurrent()) return;
        const { rule, ...retention } = result;
        const updated = { ...retention, sender_rule: rule };
        setMessage((item) => item && item.uid === uid ? { ...item, ...updated } : item);
        setMessages((items) => items.map((item) => item.uid === uid ? { ...item, ...updated } : item));
        setNotice(`Sender rule saved for future emails from ${rule.sender}.`);
      }
      await loadMessages(selectedAccount, selectedFolder, offset, query, senderDomains, readStatus, messagesPerPage, false, true, true);
    } catch (error) {
      if (isCurrent()) setNotice(error instanceof ApiError ? error.message : String(error));
    } finally {
      senderRuleBusyRef.current = false;
      setSenderRuleTarget(null);
    }
  };

  const runAudit = async () => {
    if (selectedUid === null) return;
    setAudit({ report: null, loading: true });
    try {
      const report = await api.audit(selectedAccount, selectedFolder, selectedUid);
      setAudit({ report, loading: false });
    } catch (error) {
      setNotice(error instanceof ApiError ? error.message : String(error));
      setAudit(null);
    }
  };

  const openDomainInbox = (email: string, domains: string[]) => {
    const account = accounts.find((item) => item.email.toLowerCase() === email.toLowerCase());
    if (!account || domains.length === 0) {
      setNotice('Connect the audit mailbox before opening its matching emails.');
      return;
    }
    openWorkspace('mail');
    selectAccount(account.email, 'INBOX', [...new Set(domains.map((domain) => domain.trim().toLowerCase()))], true);
  };

  const savedSettings = (settings: MailSettings) => {
    const limit = settings.messages_per_page;
    const pageSizeChanged = limit !== messagesPerPage;
    setSettingsLoaded(true);
    const retentionChanged = Boolean(settings.category_expiration_days) && JSON.stringify(settings.category_expiration_days) !== JSON.stringify(categoryExpirationDays);
    pageSize.current = limit;
    setMessagesPerPage(limit);
    if (settings.category_expiration_days) setCategoryExpirationDays({ ...DEFAULT_CATEGORY_EXPIRATION_DAYS, ...settings.category_expiration_days });
    if (settings.local_ai_model !== undefined) setLocalAiModel(settings.local_ai_model);
    if (pageSizeChanged || retentionChanged) {
      setCheckedUids([]);
      const nextOffset = pageSizeChanged ? 0 : offset;
      setOffset(nextOffset);
      if (selectedAccount) {
        const uid = readerUid.current;
        void loadMessages(selectedAccount, selectedFolder, nextOffset, query, senderDomains, readStatus, limit, false, true, true).then(() => {
          if (uid !== null && readerUid.current === uid) void openMessage(uid, false);
        });
      }
    }
    setNotice('Settings saved.');
  };

  const clearDomainFilter = () => {
    setSenderDomains([]);
    setCheckedUids([]);
    setOffset(0);
    void loadMessages(selectedAccount, selectedFolder, 0, query, [], readStatus, messagesPerPage);
  };

  const changeReadStatus = (status: MessageReadStatus) => {
    setReadStatus(status);
    setCheckedUids([]);
    setOffset(0);
    void loadMessages(selectedAccount, selectedFolder, 0, query, senderDomains, status, messagesPerPage);
  };

  const changeRetentionFilter = (category: CategoryFilter, expired: boolean) => {
    setCategoryFilter(category);
    setExpiredOnly(expired);
    mailFilters.current = { category, expiredOnly: expired };
    setCheckedUids([]);
    setOffset(0);
    void loadMessages(selectedAccount, selectedFolder, 0, query, senderDomains, readStatus, messagesPerPage);
  };

  const openTrashAction = (archive: boolean) => {
    if (selectedIsPop3) { setNotice(POP3_IMAP_ONLY_DETAIL); return; }
    if (selectedFolder !== trashFolder || !trashFolder || deletingRef.current || retentionSavingRef.current || classificationBusyRef.current || senderRuleBusyRef.current || listLoading || trashAction) return;
    setTrashAction({ account: selectedAccount, folder: selectedFolder, archive });
    trashChanged.current = false;
  };

  const trashEmptied = (result: TrashEmptyResult) => {
    if (!trashAction) return;
    trashChanged.current = true;
    setNotice(`${result.deleted} ${result.deleted === 1 ? 'message' : 'messages'} permanently deleted.${result.remaining > 0 ? ` ${result.remaining} ${result.remaining === 1 ? 'message remains' : 'messages remain'} in Trash.` : ''}`);
    if (selectedAccount === trashAction.account && selectedFolder === trashAction.folder) {
      ++messageRequest.current;
      readerUid.current = null;
      setSelectedUid(null);
      setMessage(null);
      setMessageLoading(false);
      setCheckedUids([]);
      setOffset(0);
      setQuery('');
      setSenderDomains([]);
      setReadStatus('all');
      setCategoryFilter('all');
      setExpiredOnly(false);
      mailFilters.current = { category: 'all', expiredOnly: false };
      void loadMessages(trashAction.account, trashAction.folder, 0, '', [], 'all', pageSize.current);
    }
  };

  const closeTrashAction = () => {
    if (trashAction && !trashChanged.current && selectedAccount === trashAction.account && selectedFolder === trashAction.folder) {
      // A failed commit may have removed messages even without a success response.
      ++messageRequest.current;
      readerUid.current = null;
      setSelectedUid(null);
      setMessage(null);
      setMessageLoading(false);
      void loadMessages(selectedAccount, selectedFolder, offset, query, senderDomains, readStatus, messagesPerPage);
    }
    setTrashAction(null);
  };

  const openComposer = (draft: Pick<ComposeState, 'replyTo' | 'forwardOf' | 'initialDraft'> = {}) => {
    if (!selectedAccount || compose) return;
    setCompose({ id: ++composeSequence.current, account: selectedAccount, ...draft });
  };

  const composeMailto = (url: string) => {
    const draft = parseMailto(url);
    if (!draft) {
      setNotice('The email link contains invalid or unsafe draft fields.');
      return;
    }
    openComposer({ initialDraft: draft });
  };

  useEffect(() => onMailtoRequest(setPendingMailto), []);

  useEffect(() => {
    if (!pendingMailto || !ready || compose) return;
    if (!selectedAccount) {
      setNotice('Unlock a mail account to compose the email link.');
      return;
    }
    setPendingMailto(null);
    composeMailto(pendingMailto);
    // composeMailto/openComposer read the current render's state.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pendingMailto, ready, selectedAccount, compose]);

  if (!ready) {
    return (
      <main className="page-shell">
        <p className="muted">Starting…</p>
      </main>
    );
  }

  return (
    <main className={`app-shell ${workspace !== 'mail' || accounts.length === 0 ? 'workspace-shell' : ''}`}>
      <Sidebar
        accounts={accounts}
        selectedAccount={selectedAccount}
        folders={folders}
        selectedFolder={selectedFolder}
        onSelectAccount={(email) => { openWorkspace('mail'); selectAccount(email); }}
        onSelectFolder={(name) => { openWorkspace('mail'); selectFolder(name); }}
        onCompose={() => openComposer()}
        onAddAccount={() => setShowConnect(true)}
        onLock={lockAccount}
        onAuditPaste={() => setPasteAudit(true)}
        workspace={workspace}
        onWorkspace={openWorkspace}
        onSettings={() => setShowSettings(true)}
        onConfigureAccount={(email) => setConfigurationAccount(email)}
        deleting={deleting || retentionSaving || Boolean(trashAction)}
      />

      {workspace === 'doctor' ? <InboxDoctor accounts={accounts} selectedAccount={selectedAccount} onUnlock={() => setShowConnect(true)} onOpenDomain={openDomainInbox} /> : workspace === 'metrics' ? <EmailMetrics accounts={accounts} onUnlock={() => setShowConnect(true)} onOpenDoctor={() => openWorkspace('doctor')} /> : accounts.length === 0 ? <div className="connect-workspace"><ConnectScreen onUnlocked={unlocked} /></div> : <><MessageList
        key={JSON.stringify([selectedAccount, selectedFolder, senderDomains])}
        account={selectedAccount}
        folder={selectedFolder}
        messages={messages}
        total={total}
        offset={offset}
        limit={messagesPerPage}
        loading={listLoading}
        deleting={deleting || retentionSaving || Boolean(trashAction)}
        isTrash={Boolean(trashFolder) && selectedFolder === trashFolder}
        mutationBusy={Boolean(classificationTarget || senderRuleTarget)}
        trashBusy={Boolean(trashAction)}
        onTrashAction={openTrashAction}
        checkedUids={checkedUids}
        trashFolder={trashFolder}
        senderDomains={senderDomains}
        searchQuery={query}
        readStatus={readStatus}
        onReadStatusChange={changeReadStatus}
        categoryFilter={categoryFilter}
        expiredOnly={expiredOnly}
        onCategoryFilterChange={(category) => changeRetentionFilter(category, expiredOnly)}
        onExpiredOnlyChange={(expired) => changeRetentionFilter(categoryFilter, expired)}
        onClearDomain={clearDomainFilter}
        onCheck={(uid) => setCheckedUids((checked) => checked.includes(uid)
          ? checked.filter((item) => item !== uid) : [...checked, uid])}
        onCheckPage={() => setCheckedUids((checked) => messages.every((item) => checked.includes(item.uid))
          ? [] : messages.map((item) => item.uid))}
        onDeleteSelected={() => void removeMessages(checkedUids, true)}
        selectedUid={selectedUid}
        onSelect={openMessage}
        onPage={(next) => void loadMessages(selectedAccount, selectedFolder, next, query, senderDomains, readStatus, messagesPerPage)}
        onSearch={(text) => {
          setCheckedUids([]);
          setQuery(text);
          void loadMessages(selectedAccount, selectedFolder, 0, text, senderDomains, readStatus, messagesPerPage);
        }}
        onRefresh={() => void loadMessages(selectedAccount, selectedFolder, offset, query, senderDomains, readStatus, messagesPerPage)}
        pop3={selectedIsPop3}
      />

      <MessageView
        account={selectedAccount}
        folder={selectedFolder}
        message={message}
        loading={messageLoading}
        deleting={deleting || retentionSaving || listLoading || Boolean(trashAction)}
        onAudit={runAudit}
        onReply={(m) => openComposer({ replyTo: m })}
        onForward={(m) => openComposer({ forwardOf: m })}
        onMailto={composeMailto}
        onDelete={(uid) => void removeMessages([uid], false)}
        onToggleSeen={toggleSeen}
        onToggleFlag={toggleFlag}
        retentionSaving={retentionSaving}
        onRetentionUpdate={(update) => void updateRetention(update)}
        classificationBusy={Boolean(classificationTarget)}
        classifying={Boolean(classificationTarget && classificationTarget.account === selectedAccount && classificationTarget.folder === selectedFolder && classificationTarget.uid === message?.uid && classificationTarget.uidValidity === message.uid_validity)}
        settingsLoaded={settingsLoaded}
        onClassify={() => void classifyMessage()}
        senderRuleBusy={Boolean(senderRuleTarget)}
        senderRuleSaving={Boolean(senderRuleTarget && senderRuleTarget.account === selectedAccount && senderRuleTarget.folder === selectedFolder && senderRuleTarget.uid === message?.uid)}
        onSaveSenderRule={() => void mutateSenderRule()}
        onRemoveSenderRule={() => void mutateSenderRule(true)}
        pop3={selectedIsPop3}
      />
      </>}

      {notice && (
        <div className="toast" role="status">
          {notice}
          <button className="icon-btn" type="button" onClick={() => setNotice('')} aria-label="Dismiss">
            ✕
          </button>
        </div>
      )}

      {showSettings && <SettingsModal messagesPerPage={messagesPerPage} categoryExpirationDays={categoryExpirationDays} localAiModel={localAiModel} settingsLoaded={settingsLoaded} account={selectedAccount} onConfigureAccount={() => { setShowSettings(false); setConfigurationAccount(selectedAccount); }} onSaved={savedSettings} onClose={() => setShowSettings(false)} />}

      {configurationAccount && <AccountSignatureModal
        key={configurationAccount}
        account={configurationAccount}
        onClose={() => setConfigurationAccount(null)}
        onSaved={() => setNotice(`Signature saved for ${configurationAccount}.`)}
      />}

      {trashAction && <TrashActionsModal
        account={trashAction.account}
        folder={trashAction.folder}
        archive={trashAction.archive}
        onClose={closeTrashAction}
        onEmptied={trashEmptied}
      />}

      {showConnect && (accounts.length > 0 || workspace !== 'mail') && (
        <div className="modal-backdrop">
          <ConnectScreen onUnlocked={unlocked} onCancel={() => setShowConnect(false)} />
        </div>
      )}

      {relockEmail && (
        <div className="modal-backdrop">
          <ConnectScreen
            relockEmail={relockEmail}
            onUnlocked={unlocked}
            onCancel={() => { pendingAfterUnlock.current = []; setRelockEmail(null); }}
          />
        </div>
      )}

      {compose && (
        <ComposeModal
          key={compose.id}
          account={compose.account}
          displayName={accounts.find((account) => account.email.toLowerCase() === compose.account.toLowerCase())?.display_name}
          replyTo={compose.replyTo}
          forwardOf={compose.forwardOf}
          initialDraft={compose.initialDraft}
          onClose={() => setCompose(null)}
          onSent={(result) => {
            setNotice(result.warning || (result.sent_saved && result.sent_folder
              ? `Message sent and saved to ${result.sent_folder}.`
              : 'Message sent.'));
            if (selectedAccount) {
              void loadFolders(selectedAccount, false);
              const sentFolderOpen = compose.account === selectedAccount && selectedFolder === result.sent_folder;
              void loadMessages(selectedAccount, selectedFolder, sentFolderOpen ? 0 : offset, query, senderDomains, readStatus, messagesPerPage, false, false);
            }
          }}
        />
      )}

      {pasteAudit && (
        <PasteAudit
          onClose={() => setPasteAudit(false)}
          onReport={(report) => setAudit({ report, loading: false })}
        />
      )}

      {audit && (
        <AuditPanel report={audit.report} loading={audit.loading} onClose={() => setAudit(null)} />
      )}
    </main>
  );
}
