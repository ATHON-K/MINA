import { useMemo } from 'react'

const COLORS = {
  success: '#22c55e',
  warning: '#FFB300',
  error: '#ef4444',
  info: '#3b82f6',
  muted: '#6b7280',
}

function MetricCard({ title, value, sub, color }) {
  return (
    <div style={{
      background: '#1e293b', borderRadius: 8, padding: '12px 16px',
      minWidth: 120, textAlign: 'center', border: '1px solid #334155',
    }}>
      <div style={{ fontSize: '1.5rem', fontWeight: 700, color: color || '#e2e8f0' }}>{value ?? '—'}</div>
      <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginTop: 2 }}>{title}</div>
      {sub && <div style={{ fontSize: '0.65rem', color: '#64748b', marginTop: 2 }}>{sub}</div>}
    </div>
  )
}

function CollectorRow({ tool, stats }) {
  const successRate = stats.runs > 0 ? (stats.success / stats.runs * 100).toFixed(0) : 0
  const barColor = successRate >= 70 ? COLORS.success : successRate >= 40 ? COLORS.warning : COLORS.error

  return (
    <tr style={{ borderBottom: '1px solid #1e293b' }}>
      <td style={{ padding: '4px 10px', color: '#93c5fd' }}>{tool}</td>
      <td style={{ padding: '4px 10px', textAlign: 'center' }}>{stats.runs}</td>
      <td style={{ padding: '4px 10px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <div style={{ width: 60, background: '#0f172a', borderRadius: 4, height: 8 }}>
            <div style={{ width: `${successRate}%`, background: barColor, height: '100%', borderRadius: 4 }} />
          </div>
          <span style={{ color: barColor, fontSize: '0.75rem' }}>{successRate}%</span>
        </div>
      </td>
      <td style={{ padding: '4px 10px', textAlign: 'center', color: '#94a3b8' }}>{stats.total_events || 0}</td>
      <td style={{ padding: '4px 10px', textAlign: 'center', color: '#94a3b8' }}>{stats.total_leads || 0}</td>
      <td style={{ padding: '4px 10px', textAlign: 'center', color: stats.failures > 0 ? COLORS.error : COLORS.muted }}>
        {stats.failures || 0}
      </td>
    </tr>
  )
}

function ConfidenceHistogram({ entities }) {
  const buckets = [0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
  const counts = buckets.slice(0, -1).map((low, i) => {
    const high = buckets[i + 1]
    return entities.filter((e) => e.confidence >= low && e.confidence < high).length
  })
  const maxCount = Math.max(...counts, 1)

  return (
    <div style={{ display: 'flex', alignItems: 'flex-end', gap: 2, height: 60, marginTop: 8 }}>
      {counts.map((c, i) => (
        <div key={i} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', flex: 1 }}>
          <div style={{
            width: '100%',
            height: `${(c / maxCount) * 50}px`,
            background: buckets[i] >= 0.7 ? COLORS.success : buckets[i] >= 0.4 ? COLORS.warning : COLORS.error,
            borderRadius: '2px 2px 0 0',
            minHeight: c > 0 ? 2 : 0,
          }} />
          <div style={{ fontSize: '0.55rem', color: '#475569', marginTop: 2 }}>{(buckets[i] * 100).toFixed(0)}</div>
        </div>
      ))}
    </div>
  )
}

export default function MetricsDashboard({
  collectorStats = {},
  entities = [],
  relationships = [],
  observations = [],
  findings = [],
  phaseLog = [],
  leadsQueued = 0,
  leadsProcessed = 0,
  activeBudgetUsed = 0,
  activeBudgetMax = 0,
  stopReason = '',
}) {
  const riskCounts = useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
    findings.forEach((f) => { if (counts[f.risk_level] !== undefined) counts[f.risk_level]++ })
    return counts
  }, [findings])

  const totalEvents = Object.values(collectorStats).reduce((s, c) => s + (c.total_events || 0), 0)
  const coverageRate = observations.length > 0
    ? ((entities.length / observations.length) * 100).toFixed(0)
    : 0

  return (
    <div style={{ fontFamily: 'monospace', fontSize: '0.8rem', color: '#e2e8f0', padding: 16 }}>
      <div style={{ color: '#60a5fa', fontWeight: 700, marginBottom: 16, fontSize: '0.9rem' }}>
        Collector Metrics Dashboard
      </div>

      {/* Top-level metrics */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10, marginBottom: 20 }}>
        <MetricCard title="Leads Queued" value={leadsQueued} color={COLORS.info} />
        <MetricCard title="Leads Processed" value={leadsProcessed} color={COLORS.success} />
        <MetricCard title="Raw Events" value={totalEvents} color={COLORS.info} />
        <MetricCard title="Observations" value={observations.length} color={COLORS.info} />
        <MetricCard title="Entities" value={entities.length} color={COLORS.success} sub={`${coverageRate}% coverage`} />
        <MetricCard title="Relationships" value={relationships.length} color={COLORS.success} />
        <MetricCard title="Findings" value={findings.length} color={findings.some(f => f.risk_level === 'critical') ? COLORS.error : COLORS.warning} />
        <MetricCard title="Active Budget" value={activeBudgetMax ? `${activeBudgetUsed}/${activeBudgetMax}` : activeBudgetUsed || '—'} color={activeBudgetUsed >= activeBudgetMax && activeBudgetMax > 0 ? COLORS.error : COLORS.muted} />
        <MetricCard title="Iterations" value={phaseLog.length} color={COLORS.muted} />
        {stopReason && <MetricCard title="Stop Reason" value={stopReason} color={COLORS.warning} />}
      </div>

      {/* Risk breakdown */}
      {findings.length > 0 && (
        <div style={{ marginBottom: 20 }}>
          <div style={{ color: '#60a5fa', fontWeight: 700, marginBottom: 8 }}>Risk Distribution</div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {Object.entries(riskCounts).filter(([, v]) => v > 0).map(([risk, count]) => (
              <div key={risk} style={{
                background: { critical: '#7f1d1d', high: '#7c2d12', medium: '#713f12', low: '#14532d', info: '#1e293b' }[risk] || '#1e293b',
                border: `1px solid ${COLORS[risk] || '#334155'}`,
                borderRadius: 6, padding: '4px 12px', textAlign: 'center',
              }}>
                <div style={{ fontWeight: 700, color: { critical: COLORS.error, high: '#f97316', medium: '#eab308', low: COLORS.success, info: COLORS.muted }[risk] }}>
                  {count}
                </div>
                <div style={{ fontSize: '0.7rem', color: '#94a3b8' }}>{risk}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Collector table */}
      {Object.keys(collectorStats).length > 0 && (
        <div style={{ marginBottom: 20 }}>
          <div style={{ color: '#60a5fa', fontWeight: 700, marginBottom: 8 }}>Per-Collector Stats</div>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead style={{ background: '#1e293b' }}>
                <tr>
                  <th style={{ padding: '6px 10px', textAlign: 'left' }}>Collector</th>
                  <th style={{ padding: '6px 10px', textAlign: 'center' }}>Runs</th>
                  <th style={{ padding: '6px 10px', textAlign: 'left' }}>Success Rate</th>
                  <th style={{ padding: '6px 10px', textAlign: 'center' }}>Events</th>
                  <th style={{ padding: '6px 10px', textAlign: 'center' }}>Leads</th>
                  <th style={{ padding: '6px 10px', textAlign: 'center' }}>Errors</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(collectorStats).map(([tool, stats]) => (
                  <CollectorRow key={tool} tool={tool} stats={stats} />
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Confidence distribution */}
      {entities.length > 0 && (
        <div style={{ marginBottom: 20 }}>
          <div style={{ color: '#60a5fa', fontWeight: 700, marginBottom: 4 }}>Confidence Distribution</div>
          <ConfidenceHistogram entities={entities} />
          <div style={{ fontSize: '0.65rem', color: '#475569', marginTop: 4 }}>Confidence % buckets (0–100)</div>
        </div>
      )}

      {/* Phase log */}
      {phaseLog.length > 0 && (
        <div>
          <div style={{ color: '#60a5fa', fontWeight: 700, marginBottom: 8 }}>Phase Log</div>
          <div style={{ maxHeight: 120, overflowY: 'auto' }}>
            {phaseLog.map((entry, i) => (
              <div key={i} style={{ borderBottom: '1px solid #1e293b', padding: '3px 0', color: '#94a3b8', fontSize: '0.75rem' }}>
                <span style={{ color: '#64748b', marginRight: 8 }}>#{i + 1}</span>
                {entry.stop_reason && <span style={{ color: '#f97316', marginRight: 8 }}>STOP: {entry.stop_reason}</span>}
                {entry.leads_popped !== undefined && <span>leads_popped={entry.leads_popped} </span>}
                {entry.timestamp && <span style={{ color: '#475569' }}>{entry.timestamp}</span>}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
