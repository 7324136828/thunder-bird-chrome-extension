import { AuditReport } from '../api';

interface Props {
  report: AuditReport | null;
  loading: boolean;
  onClose: () => void;
}

const SEVERITY_LABEL: Record<string, string> = {
  pass: 'PASS',
  info: 'INFO',
  warn: 'WARN',
  alert: 'ALERT',
};

const VERDICT_LABEL: Record<string, string> = {
  low: 'Low risk',
  medium: 'Medium risk',
  high: 'High risk',
};

function authBadge(value: string) {
  const cls =
    value === 'pass'
      ? 'auth-pass'
      : value === 'none' || value === 'neutral'
        ? 'auth-none'
        : 'auth-fail';
  return <span className={`auth-badge ${cls}`}>{value.toUpperCase()}</span>;
}

export default function AuditPanel({ report, loading, onClose }: Props) {
  return (
    <div className="modal-backdrop" role="dialog" aria-modal="true" aria-label="Email audit">
      <div className="modal audit">
        <header className="modal-header">
          <h2>Email audit</h2>
          <button className="icon-btn" type="button" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </header>

        {loading && <p className="muted">Analyzing headers and content…</p>}

        {report && (
          <div className="audit-body">
            <div className={`verdict verdict-${report.verdict}`}>
              <strong>{VERDICT_LABEL[report.verdict]}</strong>
              <span className="muted">risk score {report.risk_score}/100</span>
            </div>

            <section>
              <h3>Authentication</h3>
              <div className="auth-grid">
                <span>SPF</span> {authBadge(report.authentication.spf)}
                <span>DKIM</span> {authBadge(report.authentication.dkim)}
                <span>DMARC</span> {authBadge(report.authentication.dmarc)}
              </div>
            </section>

            <section>
              <h3>Sender</h3>
              <dl className="audit-facts">
                <dt>From</dt>
                <dd>
                  {report.from_name ? `${report.from_name} ` : ''}
                  &lt;{report.from_addr}&gt;
                </dd>
                <dt>Domain</dt>
                <dd>{report.sender.from_domain || '—'}</dd>
                {report.sender.reply_to && (
                  <>
                    <dt>Reply-To</dt>
                    <dd>{report.sender.reply_to}</dd>
                  </>
                )}
                {report.sender.return_path && (
                  <>
                    <dt>Return-Path</dt>
                    <dd>{report.sender.return_path}</dd>
                  </>
                )}
                <dt>Message-ID</dt>
                <dd className="mono">{report.message_id || '—'}</dd>
                {report.sender.x_mailer && (
                  <>
                    <dt>X-Mailer</dt>
                    <dd>{report.sender.x_mailer}</dd>
                  </>
                )}
              </dl>
            </section>

            <section>
              <h3>Routing</h3>
              <p className="muted">
                {report.routing.hop_count} hop(s)
                {report.routing.delivery_seconds != null &&
                  ` · ${Math.round(report.routing.delivery_seconds)}s in transit`}
              </p>
              {report.routing.hops.length > 0 && (
                <ol className="hop-list">
                  {report.routing.hops.map((hop) => (
                    <li key={hop.index}>
                      <span className="mono">
                        {hop.from || '?'} → {hop.by || '?'}
                      </span>
                      {hop.timestamp && (
                        <span className="muted"> {new Date(hop.timestamp).toLocaleString()}</span>
                      )}
                    </li>
                  ))}
                </ol>
              )}
            </section>

            <section>
              <h3>Findings ({report.findings.length})</h3>
              <ul className="finding-list">
                {report.findings.map((finding, index) => (
                  <li key={index} className={`finding finding-${finding.severity}`}>
                    <span className="finding-severity">
                      {SEVERITY_LABEL[finding.severity]}
                    </span>
                    <span>
                      <strong>{finding.title}</strong>
                      <br />
                      <span className="muted">{finding.detail}</span>
                    </span>
                  </li>
                ))}
              </ul>
            </section>

            {report.link_count > 0 && (
              <section>
                <h3>Links ({report.link_count})</h3>
                <ul className="link-list">
                  {report.links.slice(0, 25).map((link) => (
                    <li key={link.url}>
                      <span className="mono">{link.url}</span>
                      {link.label && <span className="muted"> “{link.label}”</span>}
                    </li>
                  ))}
                  {report.link_count > 25 && (
                    <li className="muted">…and {report.link_count - 25} more</li>
                  )}
                </ul>
              </section>
            )}

            {report.attachments.length > 0 && (
              <section>
                <h3>Attachments</h3>
                <ul className="link-list">
                  {report.attachments.map((a) => (
                    <li key={a.index}>
                      {a.filename} <span className="muted">({a.content_type}, {a.size} B)</span>
                    </li>
                  ))}
                </ul>
              </section>
            )}

            {report.unsubscribe.present && (
              <section>
                <h3>Unsubscribe</h3>
                <p className="mono">{report.unsubscribe.link}</p>
              </section>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
