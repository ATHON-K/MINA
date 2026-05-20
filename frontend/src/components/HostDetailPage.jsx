import { useState, useEffect } from 'react'
import { API_BASE } from '../api/config'

const RISK_COLORS = {
  critical: '#dc2626',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
  info: '#94a3b8',
}

function RiskBadge({ level }) {
  return (
    <span style={{
      background: RISK_COLORS[level] || '#94a3b8',
      color: '#fff',
      padding: '2px 6px',
      borderRadius: 4,
      fontSize: '0.7rem',
      fontWeight: 700,
      textTransform: 'uppercase',
    }}>
      {level}
    </span>
  )
}

function Section({ title, children }) {
  const [open, setOpen] = useState(true)
  return (
    <div style={{ borderBottom: '1px solid #1e293b', marginBottom: 16 }}>
      <div
        onClick={() => setOpen(o => !o)}
        style={{ cursor: 'pointer', color: '#60a5fa', fontWeight: 700, padding: '8px 0', display: 'flex', justifyContent: 'space-between' }}
      >
        <span>{title}</span>
        <span>{open ? '▼' : '▶'}</span>
      </div>
      {open && <div style={{ paddingBottom: 12 }}>{children}</div>}
    </div>
  )
}

export default function HostDetailPage({ host }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    if (!host) return
    setLoading(true)
    fetch(`${API_BASE}/api/host/${encodeURIComponent(host)}`)
      .then((r) => r.json())
      .then((d) => { setData(d); setLoading(false) })
      .catch((e) => { setError(e.message); setLoading(false) })
  }, [host])

  if (!host) return null
  if (loading) return <div style={{ color: '#6b7280', padding: 20, fontFamily: 'monospace' }}>Loading host data...</div>
  if (error) return <div style={{ color: '#ef4444', padding: 20, fontFamily: 'monospace' }}>Error: {error}</div>

  const d = data || {}

  return (
    <div style={{ fontFamily: 'monospace', fontSize: '0.8rem', color: '#e2e8f0', padding: 16 }}>
      <h2 style={{ color: '#93c5fd', marginBottom: 4 }}>{host}</h2>
      <div style={{ color: '#64748b', marginBottom: 20 }}>Host Intelligence Report</div>

      {/* 1. DNS Records */}
      <Section title="1. DNS Records">
        {d.dns ? (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead><tr style={{ background: '#1e293b' }}>
              <th style={{ padding: '4px 8px', textAlign: 'left' }}>Type</th>
              <th style={{ padding: '4px 8px', textAlign: 'left' }}>Value</th>
            </tr></thead>
            <tbody>
              {Object.entries(d.dns).map(([type, values]) =>
                (Array.isArray(values) ? values : [values]).map((v, i) => (
                  <tr key={`${type}-${i}`} style={{ borderBottom: '1px solid #1e293b' }}>
                    <td style={{ padding: '3px 8px', color: '#60a5fa' }}>{type}</td>
                    <td style={{ padding: '3px 8px' }}>{v}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        ) : <div style={{ color: '#6b7280' }}>No DNS records found</div>}
      </Section>

      {/* 2. IP & ASN */}
      <Section title="2. IP Address & ASN">
        <div><b>IP:</b> {d.ip || '—'}</div>
        <div><b>ASN:</b> {d.asn || '—'}</div>
        <div><b>Organization:</b> {d.org || '—'}</div>
        <div><b>Country:</b> {d.country || '—'}</div>
      </Section>

      {/* 3. TLS Certificate */}
      <Section title="3. TLS Certificate">
        {d.ssl ? (
          <>
            <div><b>Issuer:</b> {d.ssl.issuer || '—'}</div>
            <div><b>Subject:</b> {d.ssl.subject || '—'}</div>
            <div><b>Expiry:</b> {d.ssl.expiry || '—'}</div>
            <div><b>SANs:</b> {(d.ssl.san || []).join(', ') || '—'}</div>
          </>
        ) : <div style={{ color: '#6b7280' }}>No TLS data</div>}
      </Section>

      {/* 4. HTTP Fingerprint */}
      <Section title="4. HTTP Fingerprint">
        <div><b>Status:</b> {d.http?.status_code || '—'}</div>
        <div><b>Title:</b> {d.http?.title || '—'}</div>
        <div><b>Server:</b> {d.http?.server || '—'}</div>
        <div><b>Tech Stack:</b> {(d.http?.tech || []).join(', ') || '—'}</div>
        {d.http?.waf && <div><b>WAF:</b> {d.http.waf}</div>}
      </Section>

      {/* 5. Open Ports */}
      <Section title={`5. Open Ports & Services (${(d.ports || []).length})`}>
        {(d.ports || []).length === 0 ? (
          <div style={{ color: '#6b7280' }}>No open ports</div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead><tr style={{ background: '#1e293b' }}>
              <th style={{ padding: '4px 8px', textAlign: 'left' }}>Port</th>
              <th style={{ padding: '4px 8px', textAlign: 'left' }}>Service</th>
              <th style={{ padding: '4px 8px', textAlign: 'left' }}>Version</th>
              <th style={{ padding: '4px 8px', textAlign: 'left' }}>Risk</th>
            </tr></thead>
            <tbody>
              {(d.ports || []).map((p, i) => (
                <tr key={i} style={{ borderBottom: '1px solid #1e293b' }}>
                  <td style={{ padding: '3px 8px', color: '#60a5fa' }}>{p.port || p}</td>
                  <td style={{ padding: '3px 8px' }}>{p.service || '—'}</td>
                  <td style={{ padding: '3px 8px', color: '#94a3b8' }}>{p.version || '—'}</td>
                  <td style={{ padding: '3px 8px' }}><RiskBadge level={p.risk || 'info'} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>

      {/* 6. Endpoints */}
      <Section title={`6. Discovered Endpoints (${(d.endpoints || []).length})`}>
        {(d.endpoints || []).length === 0 ? (
          <div style={{ color: '#6b7280' }}>No endpoints</div>
        ) : (
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead><tr style={{ background: '#1e293b' }}>
              <th style={{ padding: '4px 8px', textAlign: 'left' }}>URL</th>
              <th style={{ padding: '4px 8px', textAlign: 'left' }}>Status</th>
              <th style={{ padding: '4px 8px', textAlign: 'left' }}>Score</th>
            </tr></thead>
            <tbody>
              {(d.endpoints || []).map((e, i) => (
                <tr key={i} style={{ borderBottom: '1px solid #1e293b' }}>
                  <td style={{ padding: '3px 8px', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    <a href={e.url} target="_blank" rel="noopener noreferrer" style={{ color: '#93c5fd' }}>{e.url}</a>
                  </td>
                  <td style={{ padding: '3px 8px', color: '#94a3b8' }}>{e.status_code || '—'}</td>
                  <td style={{ padding: '3px 8px' }}>
                    <span style={{ color: (e.interesting_score || 0) > 0.6 ? '#f97316' : '#22c55e' }}>
                      {(e.interesting_score || 0).toFixed(2)}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Section>

      {/* 7. Findings */}
      <Section title={`7. Related Findings (${(d.findings || []).length})`}>
        {(d.findings || []).length === 0 ? (
          <div style={{ color: '#6b7280' }}>No findings for this host</div>
        ) : (
          (d.findings || []).map((f, i) => (
            <div key={i} style={{ marginBottom: 8, padding: '8px', background: '#1e293b', borderRadius: 4 }}>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <RiskBadge level={f.risk_level} />
                <span style={{ fontWeight: 600 }}>{f.title}</span>
                <span style={{ color: '#64748b', marginLeft: 'auto' }}>{(f.priority_score || 0).toFixed(1)}/10</span>
              </div>
              <div style={{ color: '#94a3b8', marginTop: 4, fontSize: '0.75rem' }}>{f.description}</div>
            </div>
          ))
        )}
      </Section>

      {/* 8. Evidence Files */}
      <Section title="8. Evidence Files">
        {(d.evidence_refs || []).length === 0 ? (
          <div style={{ color: '#6b7280' }}>No evidence files</div>
        ) : (
          (d.evidence_refs || []).map((ref, i) => (
            <div key={i} style={{ color: '#64748b', fontSize: '0.75rem', marginBottom: 2 }}>{ref}</div>
          ))
        )}
      </Section>
    </div>
  )
}
