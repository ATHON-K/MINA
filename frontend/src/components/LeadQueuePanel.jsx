import { useState, useEffect } from 'react'

const LEAD_STATUS_COLORS = {
  pending:      '#FFB300',
  running:      '#3b82f6',
  exhausted:    '#6b7280',
  rejected:     '#ef4444',
  out_of_scope: '#ef4444',
  duplicate:    '#6b7280',
  approved:     '#22c55e',
  ttl_expired:  '#6b7280',
}

function StatusBadge({ status }) {
  return (
    <span style={{
      background: LEAD_STATUS_COLORS[status] || '#6b7280',
      color: '#fff',
      padding: '2px 8px',
      borderRadius: 4,
      fontSize: '0.75rem',
      fontWeight: 600,
      textTransform: 'uppercase',
    }}>
      {status}
    </span>
  )
}

function ConfidenceBar({ value }) {
  const pct = Math.round((value || 0) * 100)
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      <div style={{ width: 60, background: '#1e293b', borderRadius: 4, height: 8 }}>
        <div style={{ width: `${pct}%`, background: pct > 70 ? '#22c55e' : pct > 40 ? '#FFB300' : '#ef4444', height: '100%', borderRadius: 4 }} />
      </div>
      <span style={{ fontSize: '0.75rem', color: '#94a3b8' }}>{pct}%</span>
    </div>
  )
}

export default function LeadQueuePanel({ leads = [], onLeadClick }) {
  const [sortKey, setSortKey] = useState('priority')
  const [sortDir, setSortDir] = useState('desc')
  const [filterType, setFilterType] = useState('all')
  const [filterStatus, setFilterStatus] = useState('all')
  const [search, setSearch] = useState('')

  const types = ['all', ...new Set(leads.map((l) => l.type).filter(Boolean))]
  const statuses = ['all', ...new Set(leads.map((l) => l.status).filter(Boolean))]

  const pendingCount = leads.filter((l) => l.status === 'pending').length
  const processedCount = leads.filter((l) => l.status === 'exhausted').length
  const rejectedCount = leads.filter((l) => ['rejected', 'duplicate', 'out_of_scope'].includes(l.status)).length

  const sorted = [...leads]
    .filter((l) => filterType === 'all' || l.type === filterType)
    .filter((l) => filterStatus === 'all' || l.status === filterStatus)
    .filter((l) => !search || (l.value || '').toLowerCase().includes(search.toLowerCase()))
    .sort((a, b) => {
      const av = a[sortKey] ?? 0
      const bv = b[sortKey] ?? 0
      return sortDir === 'asc' ? (av > bv ? 1 : -1) : (av < bv ? 1 : -1)
    })

  function toggleSort(key) {
    if (sortKey === key) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortKey(key); setSortDir('desc') }
  }

  const SortHeader = ({ col, label }) => (
    <th
      onClick={() => toggleSort(col)}
      style={{ cursor: 'pointer', userSelect: 'none', whiteSpace: 'nowrap' }}
    >
      {label} {sortKey === col ? (sortDir === 'asc' ? '▲' : '▼') : ''}
    </th>
  )

  return (
    <div className="lead-queue-panel" style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>
      {/* Stats bar */}
      <div style={{ display: 'flex', gap: 16, padding: '8px 12px', background: '#0f172a', borderBottom: '1px solid #1e293b' }}>
        <span>Queue: <b style={{ color: '#FFB300' }}>{pendingCount}</b></span>
        <span>Processed: <b style={{ color: '#22c55e' }}>{processedCount}</b></span>
        <span>Rejected: <b style={{ color: '#ef4444' }}>{rejectedCount}</b></span>
        <span>Total: <b style={{ color: '#94a3b8' }}>{leads.length}</b></span>
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: 8, padding: '6px 12px', background: '#0f172a', borderBottom: '1px solid #1e293b', flexWrap: 'wrap' }}>
        <input
          placeholder="Search value..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{ background: '#1e293b', border: '1px solid #334155', color: '#e2e8f0', padding: '2px 8px', borderRadius: 4, fontSize: '0.75rem' }}
        />
        <select value={filterType} onChange={(e) => setFilterType(e.target.value)}
          style={{ background: '#1e293b', border: '1px solid #334155', color: '#e2e8f0', padding: '2px', borderRadius: 4, fontSize: '0.75rem' }}>
          {types.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        <select value={filterStatus} onChange={(e) => setFilterStatus(e.target.value)}
          style={{ background: '#1e293b', border: '1px solid #334155', color: '#e2e8f0', padding: '2px', borderRadius: 4, fontSize: '0.75rem' }}>
          {statuses.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
      </div>

      {/* Table */}
      <div style={{ overflowX: 'auto', overflowY: 'auto', maxHeight: '400px' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead style={{ background: '#1e293b', position: 'sticky', top: 0 }}>
            <tr>
              <th style={{ padding: '6px 10px', textAlign: 'left', whiteSpace: 'nowrap' }}>Value</th>
              <th style={{ padding: '6px 10px', textAlign: 'left' }}>Type</th>
              <SortHeader col="depth" label="Depth" />
              <SortHeader col="priority" label="Priority" />
              <th style={{ padding: '6px 10px', textAlign: 'left' }}>Confidence</th>
              <th style={{ padding: '6px 10px', textAlign: 'left' }}>Status</th>
              <th style={{ padding: '6px 10px', textAlign: 'left' }}>Source</th>
              <th style={{ padding: '6px 10px', textAlign: 'left' }}>Discovered By</th>
            </tr>
          </thead>
          <tbody>
            {sorted.length === 0 && (
              <tr><td colSpan={8} style={{ textAlign: 'center', padding: 20, color: '#6b7280' }}>No leads</td></tr>
            )}
            {sorted.map((lead, i) => (
              <tr
                key={lead.lead_id || i}
                onClick={() => onLeadClick && onLeadClick(lead)}
                style={{ cursor: onLeadClick ? 'pointer' : 'default', borderBottom: '1px solid #1e293b' }}
                onMouseEnter={(e) => e.currentTarget.style.background = '#1e293b'}
                onMouseLeave={(e) => e.currentTarget.style.background = 'transparent'}
              >
                <td style={{ padding: '4px 10px', maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: '#93c5fd' }}>
                  {lead.value}
                </td>
                <td style={{ padding: '4px 10px', color: '#94a3b8' }}>{lead.type}</td>
                <td style={{ padding: '4px 10px', textAlign: 'center' }}>{lead.depth ?? '—'}</td>
                <td style={{ padding: '4px 10px', textAlign: 'center' }}>{(lead.priority ?? 0).toFixed(2)}</td>
                <td style={{ padding: '4px 10px' }}><ConfidenceBar value={lead.confidence} /></td>
                <td style={{ padding: '4px 10px' }}><StatusBadge status={lead.status || 'pending'} /></td>
                <td style={{ padding: '4px 10px', color: '#64748b' }}>{lead.source}</td>
                <td style={{ padding: '4px 10px', color: '#64748b', fontSize: '0.7rem' }}>{lead.discovered_by}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
