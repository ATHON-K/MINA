import { useState, useEffect } from 'react'
import { API_BASE } from '../api/config'

const RISK_COLORS = {
  critical: '#dc2626',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
  info: '#94a3b8',
}

export default function EntityDetailPanel({ entityId, onClose }) {
  const [entity, setEntity] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    if (!entityId) return
    setLoading(true)
    fetch(`${API_BASE}/api/entity/${entityId}`)
      .then((r) => r.json())
      .then((data) => { setEntity(data); setLoading(false) })
      .catch((e) => { setError(e.message); setLoading(false) })
  }, [entityId])

  if (!entityId) return null

  return (
    <div style={{
      background: '#0f172a', border: '1px solid #334155', borderRadius: 8,
      padding: 16, fontFamily: 'monospace', fontSize: '0.8rem', color: '#e2e8f0',
      minWidth: 320, maxWidth: 480,
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 12 }}>
        <span style={{ fontWeight: 700, color: '#93c5fd' }}>Entity Inspector</span>
        {onClose && <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#6b7280', cursor: 'pointer', fontSize: '1rem' }}>✕</button>}
      </div>

      {loading && <div style={{ color: '#6b7280' }}>Loading...</div>}
      {error && <div style={{ color: '#ef4444' }}>Error: {error}</div>}

      {entity && (
        <>
          {/* Basic info */}
          <section style={{ marginBottom: 12 }}>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 8 }}>
              <Tag label="type" value={entity.type} />
              <Tag label="confidence" value={`${((entity.confidence || 0) * 100).toFixed(0)}%`} />
              <Tag label="status" value={entity.status || 'active'} />
              {entity.needs_review && (
                <span style={{ background: '#f97316', color: '#fff', padding: '2px 8px', borderRadius: 4, fontSize: '0.7rem', fontWeight: 700 }}>NEEDS REVIEW</span>
              )}
            </div>
            <div style={{ color: '#93c5fd', wordBreak: 'break-all' }}>
              <b>Canonical:</b> {entity.canonical_value || entity.value}
            </div>
            {entity.value !== entity.canonical_value && (
              <div style={{ color: '#64748b' }}><b>Raw:</b> {entity.value}</div>
            )}
          </section>

          {/* Attributes */}
          {entity.attributes && Object.keys(entity.attributes).length > 0 && (
            <section style={{ marginBottom: 12 }}>
              <div style={{ color: '#60a5fa', fontWeight: 700, marginBottom: 4 }}>Attributes</div>
              {Object.entries(entity.attributes).map(([k, v]) => (
                <div key={k} style={{ display: 'flex', gap: 8 }}>
                  <span style={{ color: '#94a3b8', minWidth: 120 }}>{k}</span>
                  <span style={{ color: '#e2e8f0', wordBreak: 'break-all' }}>{JSON.stringify(v)}</span>
                </div>
              ))}
            </section>
          )}

          {/* Sources */}
          {entity.sources?.length > 0 && (
            <section style={{ marginBottom: 12 }}>
              <div style={{ color: '#60a5fa', fontWeight: 700, marginBottom: 4 }}>Sources</div>
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                {entity.sources.map((s) => <Tag key={s} value={s} />)}
              </div>
            </section>
          )}

          {/* Observations */}
          {entity.observation_ids?.length > 0 && (
            <section style={{ marginBottom: 12 }}>
              <div style={{ color: '#60a5fa', fontWeight: 700, marginBottom: 4 }}>
                Observations ({entity.observation_ids.length})
              </div>
              {entity.observation_ids.slice(0, 5).map((id) => (
                <div key={id} style={{ color: '#64748b', fontSize: '0.7rem' }}>{id}</div>
              ))}
              {entity.observation_ids.length > 5 && (
                <div style={{ color: '#475569' }}>...+{entity.observation_ids.length - 5} more</div>
              )}
            </section>
          )}

          {/* Evidence refs */}
          {entity.evidence_refs?.length > 0 && (
            <section style={{ marginBottom: 12 }}>
              <div style={{ color: '#60a5fa', fontWeight: 700, marginBottom: 4 }}>Evidence</div>
              {entity.evidence_refs.slice(0, 5).map((ref) => (
                <div key={ref} style={{ color: '#64748b', fontSize: '0.7rem' }}>{ref}</div>
              ))}
            </section>
          )}

          {/* Linked relationships */}
          {entity.relationships?.length > 0 && (
            <section style={{ marginBottom: 12 }}>
              <div style={{ color: '#60a5fa', fontWeight: 700, marginBottom: 4 }}>
                Relationships ({entity.relationships.length})
              </div>
              {entity.relationships.slice(0, 10).map((rel, idx) => (
                <div key={idx} style={{ color: '#94a3b8', fontSize: '0.7rem', padding: '2px 0', borderBottom: '1px solid #1e293b' }}>
                  <span style={{ color: '#93c5fd' }}>{rel.type || rel.relation_type}</span>
                  {' → '}
                  <span style={{ color: '#e2e8f0' }}>{rel.target_value || rel.to_entity_id || rel.target_entity_id}</span>
                  {rel.confidence != null && (
                    <span style={{ color: '#475569', marginLeft: 8 }}>({(rel.confidence * 100).toFixed(0)}%)</span>
                  )}
                </div>
              ))}
              {entity.relationships.length > 10 && (
                <div style={{ color: '#475569' }}>...+{entity.relationships.length - 10} more</div>
              )}
            </section>
          )}

          {/* Timestamps */}
          <section>
            <div style={{ color: '#475569', fontSize: '0.7rem' }}>
              First seen: {entity.first_seen || '—'}<br />
              Last seen: {entity.last_seen || '—'}
            </div>
          </section>
        </>
      )}
    </div>
  )
}

function Tag({ label, value }) {
  return (
    <span style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 4, padding: '1px 6px', fontSize: '0.7rem' }}>
      {label && <span style={{ color: '#64748b' }}>{label}: </span>}
      <span style={{ color: '#e2e8f0' }}>{value}</span>
    </span>
  )
}
