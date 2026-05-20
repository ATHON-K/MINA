import { useEffect, useRef, useState } from 'react'

//  Color maps 

const LEVEL_COLOR = {
  info:    '#00FF41',
  success: '#00FF41',
  warning: '#FFB300',
  alert:   '#E53935',
  error:   '#E53935',
}

const AGENT_COLOR = {
  'Director':    '#58A6FF',
  'PassiveRecon':'#D2A8FF',
  'OSINTAgent':  '#FF6B35',
  'KarmaV2':     '#FF3D00',
  'ActiveRecon': '#E07B54',
  'Normalizer':  '#79C0FF',
  'Reporter':    '#FFB300',
  'System':      '#8B949E',
}

const SEVERITY_TEXT = {
  critical: '#FF3333',
  high:     '#FF5722',
  medium:   '#FFB300',
  low:      '#00FF41',
  info:     '#58A6FF',
}

const SEVERITY_BG = {
  critical: 'rgba(229,57,53,0.15)',
  high:     'rgba(255,87,34,0.12)',
  medium:   'rgba(255,179,0,0.10)',
  low:      'rgba(0,255,65,0.06)',
  info:     'rgba(88,166,255,0.06)',
}

const ENTITY_TYPE_COLOR = {
  subdomain:    '#D2A8FF',
  ip_address:   '#FF6B35',
  email:        '#FFB300',
  service:      '#79C0FF',
  organization: '#58A6FF',
  certificate:  '#00FF41',
  webapp:       '#E07B54',
  open_port:    '#FF5722',
}

//  Terminal 

function Terminal({ logs }) {
  const ref = useRef(null)
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight
  }, [logs])

  return (
    <div ref={ref} style={S.termBody}>
      {logs.length === 0 ? (
        <div style={S.emptyState}>
          <span style={{ color: '#484F58', fontFamily: 'Fira Code, monospace', fontSize: 11 }}>
             AWAITING SIGNAL...
          </span>
        </div>
      ) : (
        logs.map((log, i) => {
          const agentColor = AGENT_COLOR[log.agent] || '#8B949E'
          const msgColor   = LEVEL_COLOR[log.level]  || '#C9D1D9'
          const ts = log.timestamp ? log.timestamp.substring(11, 19) : '--:--:--'
          return (
            <div key={i} style={S.termLine}>
              <span style={S.termTs}>{ts}</span>
              <span style={{ ...S.termAgent, color: agentColor }}>[{log.agent ?? 'SYS'}]</span>{' '}
              <span style={{ ...S.termMsg, color: msgColor }}>{log.message}</span>
            </div>
          )
        })
      )}
    </div>
  )
}

//  EventList 

function EventList({ events }) {
  const [expanded, setExpanded] = useState(null)
  const ref = useRef(null)
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight
  }, [events])

  if (!events || events.length === 0) {
    return (
      <div style={S.emptyState}>
        <span style={{ color: '#484F58', fontFamily: 'Fira Code, monospace', fontSize: 10 }}>
          -- NO INTEL EVENTS YET --
        </span>
      </div>
    )
  }

  return (
    <div ref={ref} style={S.feedBody}>
      {events.map((ev, i) => {
        const isOpen = expanded === i
        const ts = (ev.timestamp || '').substring(11, 19)
        const agentColor = AGENT_COLOR[ev.source_agent] || '#8B949E'
        return (
          <div key={i}>
            <div
              style={{ ...S.feedRow, cursor: 'pointer' }}
              onClick={() => setExpanded(isOpen ? null : i)}
            >
              <span style={S.termTs}>{ts}</span>
              <span style={{ ...S.termAgent, color: agentColor }}>{ev.source_agent || 'SYS'}</span>
              <span style={{ flex: 1, color: '#C9D1D9', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {ev.what}  {ev.value}
              </span>
              <span style={{ color: '#484F58', flexShrink: 0 }}>{isOpen ? '' : ''}</span>
            </div>
            {isOpen && (
              <div style={S.detailCard}>
                <div style={S.detailRow}><span style={S.detailKey}>TYPE</span><span>{ev.what}</span></div>
                <div style={S.detailRow}><span style={S.detailKey}>VALUE</span><span style={{ color: '#00FF41', wordBreak: 'break-all' }}>{ev.value}</span></div>
                <div style={S.detailRow}><span style={S.detailKey}>WHERE</span><span>{ev.where}</span></div>
                <div style={S.detailRow}><span style={S.detailKey}>HOW</span><span>{ev.how}</span></div>
                <div style={S.detailRow}><span style={S.detailKey}>CONF</span><span>{((ev.confidence || 1) * 100).toFixed(0)}%</span></div>
                {ev.evidence_ref && (
                  <div style={S.detailRow}><span style={S.detailKey}>REF</span><span style={{ color: '#484F58', wordBreak: 'break-all', fontSize: 9 }}>{ev.evidence_ref}</span></div>
                )}
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}

//  EntityList 

function EntityList({ entities }) {
  const [expanded, setExpanded] = useState(null)

  if (!entities || entities.length === 0) {
    return (
      <div style={S.emptyState}>
        <span style={{ color: '#484F58', fontFamily: 'Fira Code, monospace', fontSize: 10 }}>
          -- NO ENTITIES DISCOVERED --
        </span>
      </div>
    )
  }

  return (
    <div style={S.feedBody}>
      {entities.map((ent, i) => {
        const isOpen = expanded === i
        const typeColor = ENTITY_TYPE_COLOR[ent.type] || '#8B949E'
        const riskColor = SEVERITY_TEXT[(ent.risk_level || 'low').toLowerCase()] || '#8B949E'
        return (
          <div key={i}>
            <div
              style={{ ...S.feedRow, cursor: 'pointer' }}
              onClick={() => setExpanded(isOpen ? null : i)}
            >
              <span style={{ ...S.typePill, color: typeColor, borderColor: typeColor }}>
                {ent.type || 'unknown'}
              </span>
              <span style={{ flex: 1, color: '#C9D1D9', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {ent.canonical_value}
              </span>
              <span style={{ color: riskColor, flexShrink: 0, fontSize: 9, fontWeight: 700 }}>
                {(ent.risk_level || 'low').toUpperCase()}
              </span>
              <span style={{ color: '#484F58', flexShrink: 0, marginLeft: 4 }}>{isOpen ? '' : ''}</span>
            </div>
            {isOpen && (
              <div style={S.detailCard}>
                <div style={S.detailRow}><span style={S.detailKey}>ID</span><span style={{ color: '#D2A8FF', fontSize: 9, wordBreak: 'break-all' }}>{ent.entity_id}</span></div>
                <div style={S.detailRow}><span style={S.detailKey}>TYPE</span><span style={{ color: typeColor }}>{ent.type}</span></div>
                <div style={S.detailRow}><span style={S.detailKey}>VALUE</span><span style={{ color: '#00FF41', wordBreak: 'break-all' }}>{ent.canonical_value}</span></div>
                <div style={S.detailRow}><span style={S.detailKey}>RISK</span><span style={{ color: riskColor, fontWeight: 700 }}>{(ent.risk_level || 'low').toUpperCase()}</span></div>
                <div style={S.detailRow}><span style={S.detailKey}>CONF</span><span>{((ent.confidence || 1) * 100).toFixed(0)}%</span></div>
                {ent.sources && ent.sources.length > 0 && (
                  <div style={S.detailRow}><span style={S.detailKey}>SRC</span><span>{ent.sources.join(', ')}</span></div>
                )}
                {ent.attributes && Object.keys(ent.attributes).length > 0 && (
                  <div style={{ ...S.detailRow, flexDirection: 'column', gap: 2 }}>
                    <span style={S.detailKey}>ATTRS</span>
                    {Object.entries(ent.attributes).slice(0, 6).map(([k, v]) => (
                      <span key={k} style={{ color: '#8B949E', paddingLeft: 8, wordBreak: 'break-all' }}>
                        {k}: <span style={{ color: '#C9D1D9' }}>{String(v)}</span>
                      </span>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}

//  VulnList 

function VulnList({ vulns }) {
  const [expanded, setExpanded] = useState(null)

  if (!vulns || vulns.length === 0) {
    return (
      <div style={S.emptyState}>
        <span style={{ color: '#484F58', fontFamily: 'Fira Code, monospace', fontSize: 10 }}>
          -- NO VULNERABILITIES DETECTED --
        </span>
      </div>
    )
  }

  return (
    <div style={S.feedBody}>
      <div style={S.vulnHeader}>
        <span style={{ flex: '2 1 0' }}>ASSET</span>
        <span style={{ flex: '3 1 0' }}>VULNERABILITY</span>
        <span style={{ flex: '1 1 0', textAlign: 'right' }}>SEVERITY</span>
      </div>
      {vulns.map((v, i) => {
        const isOpen = expanded === i
        const sev = (v.severity || v.impact || 'low').toLowerCase()
        const sevText = SEVERITY_TEXT[sev]  || '#8B949E'
        const sevBg   = SEVERITY_BG[sev]    || 'transparent'
        const asset = v.asset || v.target || '-'
        const title = v.title || v.vulnerability || v.description || v.name || '-'
        return (
          <div key={i}>
            <div
              style={{
                ...S.feedRow,
                background: sevBg,
                borderLeft: `2px solid ${sevText}`,
                cursor: 'pointer',
              }}
              onClick={() => setExpanded(isOpen ? null : i)}
            >
              <span style={{ flex: '2 1 0', color: '#C9D1D9', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {asset}
              </span>
              <span style={{ flex: '3 1 0', color: '#C9D1D9', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {title}
              </span>
              <span style={{ flex: '1 1 0', textAlign: 'right', color: sevText, fontWeight: 700, flexShrink: 0 }}>
                {sev.toUpperCase()}
              </span>
              <span style={{ color: '#484F58', marginLeft: 4 }}>{isOpen ? '' : ''}</span>
            </div>
            {isOpen && (
              <div style={S.detailCard}>
                <div style={S.detailRow}><span style={S.detailKey}>TITLE</span><span style={{ color: '#C9D1D9', wordBreak: 'break-word' }}>{title}</span></div>
                <div style={S.detailRow}><span style={S.detailKey}>TARGET</span><span>{asset}</span></div>
                <div style={S.detailRow}><span style={S.detailKey}>SEVERITY</span><span style={{ color: sevText, fontWeight: 700 }}>{sev.toUpperCase()}</span></div>
                {(v.category || v.type) && (
                  <div style={S.detailRow}><span style={S.detailKey}>CATEGORY</span><span>{v.category || v.type}</span></div>
                )}
                {v.description && (
                  <div style={{ ...S.detailRow, flexDirection: 'column', gap: 2 }}>
                    <span style={S.detailKey}>DESCRIPTION</span>
                    <span style={{ color: '#8B949E', paddingLeft: 8, wordBreak: 'break-word', lineHeight: '1.5' }}>{v.description}</span>
                  </div>
                )}
                {v.recommendation && (
                  <div style={{ ...S.detailRow, flexDirection: 'column', gap: 2 }}>
                    <span style={S.detailKey}>RECOMMEND</span>
                    <span style={{ color: '#00FF41', paddingLeft: 8, wordBreak: 'break-word', lineHeight: '1.5' }}>{v.recommendation}</span>
                  </div>
                )}
                {v.source_agent && (
                  <div style={S.detailRow}><span style={S.detailKey}>AGENT</span><span style={{ color: AGENT_COLOR[v.source_agent] || '#8B949E' }}>{v.source_agent}</span></div>
                )}
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}

//  ToolCoverage 

function RelationshipList({ relationships }) {
  const [expanded, setExpanded] = useState(null)

  if (!relationships || relationships.length === 0) {
    return (
      <div style={S.emptyState}>
        <span style={{ color: '#484F58', fontFamily: 'Fira Code, monospace', fontSize: 10 }}>
          -- NO RELATIONSHIPS DISCOVERED --
        </span>
      </div>
    )
  }

  return (
    <div style={S.feedBody}>
      <div style={{
        display: 'flex', gap: 6, padding: '3px 8px', background: '#161B22',
        color: '#8B949E', fontSize: 9, letterSpacing: '0.1em',
        borderBottom: '1px solid #30363D', position: 'sticky', top: 0,
        fontFamily: 'Fira Code, monospace',
      }}>
        <span style={{ flex: '2 1 0' }}>SOURCE</span>
        <span style={{ flex: '1 1 0', textAlign: 'center' }}>RELATION</span>
        <span style={{ flex: '2 1 0' }}>TARGET</span>
      </div>
      {relationships.map((rel, i) => {
        const isOpen = expanded === i
        const src = rel.source_value || rel.source_entity_id || '-'
        const tgt = rel.target_value || rel.target_entity_id || '-'
        const relType = rel.rel_type || rel.relation_type || 'related'
        return (
          <div key={i}>
            <div
              style={{ ...S.feedRow, cursor: 'pointer' }}
              onClick={() => setExpanded(isOpen ? null : i)}
            >
              <span style={{ flex: '2 1 0', color: '#58A6FF', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {src}
              </span>
              <span style={{ flex: '1 1 0', textAlign: 'center', color: '#D2A8FF', fontSize: 9 }}>
                {relType}
              </span>
              <span style={{ flex: '2 1 0', color: '#00FF41', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {tgt}
              </span>
              <span style={{ color: '#484F58', marginLeft: 4 }}>{isOpen ? '▾' : '▸'}</span>
            </div>
            {isOpen && (
              <div style={S.detailCard}>
                <div style={S.detailRow}><span style={S.detailKey}>SOURCE</span><span style={{ color: '#58A6FF', wordBreak: 'break-all' }}>{src}</span></div>
                <div style={S.detailRow}><span style={S.detailKey}>REL</span><span style={{ color: '#D2A8FF' }}>{relType}</span></div>
                <div style={S.detailRow}><span style={S.detailKey}>TARGET</span><span style={{ color: '#00FF41', wordBreak: 'break-all' }}>{tgt}</span></div>
                {rel.confidence != null && (
                  <div style={S.detailRow}><span style={S.detailKey}>CONF</span><span>{((rel.confidence || 0) * 100).toFixed(0)}%</span></div>
                )}
                {rel.source_collectors && rel.source_collectors.length > 0 && (
                  <div style={S.detailRow}><span style={S.detailKey}>SRC</span><span>{rel.source_collectors.join(', ')}</span></div>
                )}
                {rel.reason && (
                  <div style={S.detailRow}><span style={S.detailKey}>WHY</span><span style={{ color: '#8B949E', wordBreak: 'break-word' }}>{rel.reason}</span></div>
                )}
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}

function EvidenceList({ observations }) {
  const [expanded, setExpanded] = useState(null)

  if (!observations || observations.length === 0) {
    return (
      <div style={S.emptyState}>
        <span style={{ color: '#484F58', fontFamily: 'Fira Code, monospace', fontSize: 10 }}>
          -- NO EVIDENCE COLLECTED --
        </span>
      </div>
    )
  }

  const OBS_TYPE_COLOR = {
    subdomain_found: '#D2A8FF', ip_found: '#FF6B35', port_open: '#FF5722',
    service_detected: '#79C0FF', vulnerability_found: '#E53935', cert_found: '#00FF41',
    webapp_alive: '#58A6FF', technology_found: '#FFB300', header_found: '#8B949E',
    email_found: '#FFB300', endpoint_found: '#E07B54', url_found: '#D2A8FF',
  }

  return (
    <div style={S.feedBody}>
      <div style={{
        display: 'flex', gap: 6, padding: '3px 8px', background: '#161B22',
        color: '#8B949E', fontSize: 9, letterSpacing: '0.1em',
        borderBottom: '1px solid #30363D', position: 'sticky', top: 0,
        fontFamily: 'Fira Code, monospace',
      }}>
        <span style={{ flex: '1 1 0' }}>TYPE</span>
        <span style={{ flex: '2 1 0' }}>VALUE</span>
        <span style={{ flex: '1 1 0' }}>COLLECTOR</span>
        <span style={{ flex: '0 0 40px', textAlign: 'right' }}>CONF</span>
      </div>
      {observations.map((obs, i) => {
        const isOpen = expanded === i
        const obsType = obs.obs_type || obs.type || 'unknown'
        const typeColor = OBS_TYPE_COLOR[obsType] || '#8B949E'
        const val = obs.value || obs.raw_value || '-'
        const collector = obs.collector || obs.source_collector || '-'
        const conf = obs.confidence != null ? ((obs.confidence * 100).toFixed(0) + '%') : '-'
        return (
          <div key={i}>
            <div
              style={{ ...S.feedRow, cursor: 'pointer' }}
              onClick={() => setExpanded(isOpen ? null : i)}
            >
              <span style={{ flex: '1 1 0', ...S.typePill, color: typeColor, borderColor: typeColor }}>
                {obsType.replace(/_/g, ' ')}
              </span>
              <span style={{ flex: '2 1 0', color: '#C9D1D9', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {val}
              </span>
              <span style={{ flex: '1 1 0', color: '#D2A8FF', fontSize: 9 }}>
                {collector}
              </span>
              <span style={{ flex: '0 0 40px', textAlign: 'right', color: '#8B949E' }}>
                {conf}
              </span>
            </div>
            {isOpen && (
              <div style={S.detailCard}>
                <div style={S.detailRow}><span style={S.detailKey}>TYPE</span><span style={{ color: typeColor }}>{obsType}</span></div>
                <div style={S.detailRow}><span style={S.detailKey}>VALUE</span><span style={{ color: '#00FF41', wordBreak: 'break-all' }}>{val}</span></div>
                <div style={S.detailRow}><span style={S.detailKey}>COLL</span><span>{collector}</span></div>
                <div style={S.detailRow}><span style={S.detailKey}>CONF</span><span>{conf}</span></div>
                {obs.target && (
                  <div style={S.detailRow}><span style={S.detailKey}>TGT</span><span style={{ wordBreak: 'break-all' }}>{obs.target}</span></div>
                )}
                {obs.evidence_ref && (
                  <div style={S.detailRow}><span style={S.detailKey}>REF</span><span style={{ color: '#484F58', wordBreak: 'break-all', fontSize: 9 }}>{obs.evidence_ref}</span></div>
                )}
                {obs.raw_data && (
                  <div style={{ ...S.detailRow, flexDirection: 'column', gap: 2 }}>
                    <span style={S.detailKey}>RAW</span>
                    <pre style={{ color: '#484F58', fontSize: 8, whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: 0, paddingLeft: 8 }}>
                      {typeof obs.raw_data === 'string' ? obs.raw_data.slice(0, 400) : JSON.stringify(obs.raw_data, null, 1).slice(0, 400)}
                    </pre>
                  </div>
                )}
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}

//  ToolCoverage (kept for metrics, no longer a main tab) 

function ToolCoverage({ stats }) {
  const entries = Object.entries(stats || {})
  if (entries.length === 0) {
    return (
      <div style={S.emptyState}>
        <span style={{ color: '#484F58', fontFamily: 'Fira Code, monospace', fontSize: 10 }}>
          -- NO TOOL DATA YET --
        </span>
      </div>
    )
  }

  return (
    <div style={S.feedBody}>
      <div style={{
        display: 'grid',
        gridTemplateColumns: '2fr 1fr 1fr 1fr',
        gap: 0,
        padding: '3px 8px',
        background: '#161B22',
        color: '#8B949E',
        fontSize: 9,
        letterSpacing: '0.1em',
        borderBottom: '1px solid #30363D',
        position: 'sticky',
        top: 0,
        fontFamily: 'Fira Code, monospace',
      }}>
        <span>COLLECTOR</span>
        <span style={{ textAlign: 'right' }}>RUNS</span>
        <span style={{ textAlign: 'right' }}>OK %</span>
        <span style={{ textAlign: 'right' }}>EVENTS</span>
      </div>
      {entries.map(([name, s]) => {
        const runs = (s.success || 0) + (s.fail || 0)
        const rate = runs > 0 ? ((s.success || 0) / runs * 100).toFixed(0) : '-'
        const rateColor = rate === '-' ? '#484F58' : (parseInt(rate) >= 80 ? '#00FF41' : parseInt(rate) >= 50 ? '#FFB300' : '#E53935')
        return (
          <div key={name} style={{
            display: 'grid',
            gridTemplateColumns: '2fr 1fr 1fr 1fr',
            gap: 0,
            padding: '3px 8px',
            borderBottom: '1px solid rgba(48,54,61,0.5)',
            fontFamily: 'Fira Code, monospace',
            fontSize: 10,
          }}>
            <span style={{ color: '#D2A8FF', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{name}</span>
            <span style={{ textAlign: 'right', color: '#C9D1D9' }}>{runs}</span>
            <span style={{ textAlign: 'right', color: rateColor }}>{rate}{rate !== '-' ? '%' : ''}</span>
            <span style={{ textAlign: 'right', color: '#C9D1D9' }}>{s.events || 0}</span>
          </div>
        )
      })}
    </div>
  )
}

//  ExportBtn 

function ExportBtn({ label, disabled, onClick, primary }) {
  return (
    <button
      disabled={disabled}
      onClick={onClick}
      style={{
        ...S.exportBtn,
        ...(primary ? S.exportBtnPrimary : {}),
        ...(disabled ? S.exportBtnDisabled : {}),
      }}
      onMouseEnter={e => {
        if (!disabled) {
          e.currentTarget.style.background = primary ? 'rgba(229,57,53,0.2)' : 'rgba(48,54,61,0.8)'
          e.currentTarget.style.borderColor = primary ? '#E53935' : '#58A6FF'
          e.currentTarget.style.color = primary ? '#E53935' : '#58A6FF'
        }
      }}
      onMouseLeave={e => {
        if (!disabled) {
          Object.assign(e.currentTarget.style, primary ? S.exportBtnPrimary : S.exportBtn)
        }
      }}
    >
      {label}
    </button>
  )
}

//  Main component 

export default function RightPanel({ logs, vulns, entities, intelEvents = [], report, scanStatus, onExport, collectorStats = {}, relationships = [], findings = [], observations = [] }) {
  const [feedView, setFeedView] = useState('events')
  const canExport = scanStatus === 'complete'

  const statsEntries = Object.entries(collectorStats)

  const tabs = [
    { key: 'events',        label: 'EVENTS',        count: intelEvents.length,   color: '#00FF41' },
    { key: 'entities',      label: 'ENTITIES',      count: entities.length,       color: '#58A6FF' },
    { key: 'relationships', label: 'RELS',          count: relationships.length,  color: '#D2A8FF' },
    { key: 'findings',      label: 'FINDINGS',      count: (findings.length || vulns.length), color: (vulns.length > 0 || findings.length > 0) ? '#E53935' : '#8B949E' },
    { key: 'evidence',      label: 'EVIDENCE',      count: observations.length,   color: '#FFB300' },
  ]

  return (
    <div className="panel panel-right" style={S.panel}>

      {/* PANEL HEADER */}
      <div className="panel-header">
        <span className="accent"></span>
        <span>INTELLIGENCE FEED</span>
        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6 }}>
          {scanStatus === 'running' && <span style={S.pulseDot} />}
          <span style={{
            color: scanStatus === 'running' ? '#FFB300'
                 : scanStatus === 'complete' ? '#00FF41'
                 : scanStatus === 'error' ? '#E53935'
                 : '#484F58',
            fontSize: 11,
          }}>{scanStatus.toUpperCase()}</span>
        </div>
      </div>

      {/* TAB BAR */}
      <div style={S.tabBar}>
        {tabs.map(tab => {
          const active = feedView === tab.key
          return (
            <button
              key={tab.key}
              onClick={() => setFeedView(tab.key)}
              style={{
                ...S.tabBtn,
                borderBottom: active ? `2px solid ${tab.color}` : '2px solid transparent',
                color: active ? tab.color : '#484F58',
              }}
            >
              <span style={{ fontWeight: active ? 700 : 400 }}>{tab.label}</span>
              <span style={{
                ...S.tabCount,
                backgroundColor: active ? tab.color : '#30363D',
                color: active ? '#0A0B0E' : '#8B949E',
              }}>
                {tab.count}
              </span>
            </button>
          )
        })}
      </div>

      {/* FEED AREA */}
      <div style={S.feedArea}>
        {feedView === 'events'        && <EventList  events={intelEvents} />}
        {feedView === 'entities'      && <EntityList entities={entities} />}
        {feedView === 'relationships' && <RelationshipList relationships={relationships} />}
        {feedView === 'findings'      && <VulnList   vulns={findings.length > 0 ? findings : vulns} />}
        {feedView === 'evidence'      && <EvidenceList observations={observations} />}
      </div>

      <div style={S.separator} />

      {/* LIVE AGENT TERMINAL */}
      <div style={S.termWrap}>
        <div style={S.sectionHeader}>
          <span style={S.sectionTitle}>LIVE AGENT TERMINAL</span>
          <span style={S.badge}>{logs.length} EVENTS</span>
        </div>
        <Terminal logs={logs} />
      </div>

      <div style={S.separator} />

      {/* EXPORT CONTROLS */}
      <div style={S.exportSection}>
        <div style={S.sectionHeader}>
          <span style={S.sectionTitle}>EXPORT CONTROLS</span>
          {!canExport && <span style={{ color: '#484F58', fontSize: 9, fontFamily: 'Fira Code' }}>SCAN PENDING</span>}
        </div>
        <div style={S.exportGrid}>
          <ExportBtn label="[ JSON ]"      disabled={!canExport} onClick={() => onExport('json')} />
          <ExportBtn label="[ CSV ]"       disabled={!canExport} onClick={() => onExport('csv')} />
          <ExportBtn label="[ RELS.CSV ]"  disabled={!canExport} onClick={() => onExport('relationships-csv')} />
          <ExportBtn label="[ VULNS.CSV ]" disabled={!canExport} onClick={() => onExport('vulnerabilities-csv')} />
          <ExportBtn label="[ REPORT.MD ]" disabled={!canExport} onClick={() => onExport('md')} primary />
        </div>
        {report && canExport && (
          <div style={S.reportBadge}>
             REPORT READY  {report.length} chars
          </div>
        )}
      </div>

    </div>
  )
}

//  Styles 

const S = {
  panel: {
    display: 'flex',
    flexDirection: 'column',
    overflow: 'hidden',
  },
  tabBar: {
    display: 'flex',
    borderBottom: '1px solid #30363D',
    flexShrink: 0,
    background: '#0D1117',
  },
  tabBtn: {
    flex: 1,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 5,
    padding: '6px 4px',
    fontFamily: 'Fira Code, monospace',
    fontSize: 10,
    letterSpacing: '0.1em',
    cursor: 'pointer',
    border: 'none',
    transition: 'color 0.15s, border-color 0.15s',
    background: 'transparent',
  },
  tabCount: {
    fontFamily: 'Fira Code, monospace',
    fontSize: 9,
    fontWeight: 700,
    padding: '1px 5px',
    borderRadius: 2,
    minWidth: 18,
    textAlign: 'center',
    transition: 'background 0.15s, color 0.15s',
  },
  feedArea: {
    flex: '1 1 0',
    minHeight: 0,
    display: 'flex',
    flexDirection: 'column',
    overflow: 'hidden',
  },
  feedBody: {
    flex: 1,
    overflowY: 'auto',
    fontFamily: 'Fira Code, monospace',
    fontSize: 10,
    background: '#0A0B0E',
    scrollbarWidth: 'thin',
    scrollbarColor: '#30363D transparent',
  },
  feedRow: {
    display: 'flex',
    alignItems: 'center',
    gap: 6,
    padding: '4px 8px',
    borderBottom: '1px solid rgba(48,54,61,0.5)',
    transition: 'background 0.1s',
    lineHeight: '1.4',
  },
  detailCard: {
    background: 'rgba(22,27,34,0.95)',
    borderLeft: '2px solid #30363D',
    margin: '0 0 0 12px',
    padding: '6px 10px',
    fontFamily: 'Fira Code, monospace',
    fontSize: 10,
    display: 'flex',
    flexDirection: 'column',
    gap: 3,
  },
  detailRow: {
    display: 'flex',
    gap: 8,
    alignItems: 'flex-start',
    color: '#8B949E',
  },
  detailKey: {
    color: '#484F58',
    flexShrink: 0,
    width: 52,
    letterSpacing: '0.08em',
    paddingTop: 1,
  },
  typePill: {
    fontSize: 9,
    padding: '1px 4px',
    border: '1px solid',
    letterSpacing: '0.06em',
    flexShrink: 0,
    fontWeight: 700,
    fontFamily: 'Fira Code, monospace',
  },
  vulnHeader: {
    display: 'flex',
    gap: 6,
    padding: '3px 8px',
    background: '#161B22',
    color: '#8B949E',
    fontSize: 9,
    letterSpacing: '0.1em',
    borderBottom: '1px solid #30363D',
    position: 'sticky',
    top: 0,
    fontFamily: 'Fira Code, monospace',
  },
  termWrap: {
    flex: '0 0 140px',
    display: 'flex',
    flexDirection: 'column',
    minHeight: 0,
  },
  termBody: {
    flex: 1,
    overflowY: 'auto',
    padding: '6px 10px',
    fontFamily: 'Fira Code, monospace',
    fontSize: 11,
    lineHeight: '1.65',
    background: '#0A0B0E',
    scrollbarWidth: 'thin',
    scrollbarColor: '#30363D transparent',
  },
  emptyState: {
    flex: 1,
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    minHeight: 60,
  },
  termLine: {
    display: 'flex',
    gap: 6,
    flexWrap: 'nowrap',
    wordBreak: 'break-all',
  },
  termTs: {
    color: '#484F58',
    flexShrink: 0,
    fontSize: 10,
  },
  termAgent: {
    flexShrink: 0,
    fontWeight: 600,
    fontSize: 10,
  },
  termMsg: {
    flex: 1,
    wordBreak: 'break-word',
  },
  sectionHeader: {
    padding: '4px 10px',
    borderBottom: '1px solid #30363D',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    flexShrink: 0,
    background: 'rgba(22,27,34,0.9)',
  },
  sectionTitle: {
    fontFamily: 'Fira Code, monospace',
    fontSize: 10,
    letterSpacing: '0.15em',
    color: '#8B949E',
    textTransform: 'uppercase',
  },
  badge: {
    fontFamily: 'Fira Code, monospace',
    fontSize: 9,
    color: '#8B949E',
    border: '1px solid #30363D',
    padding: '1px 5px',
    letterSpacing: '0.08em',
  },
  separator: {
    height: 1,
    background: '#30363D',
    flexShrink: 0,
  },
  exportSection: {
    flexShrink: 0,
    padding: '6px 8px',
    borderTop: '1px solid #30363D',
  },
  exportGrid: {
    display: 'grid',
    gridTemplateColumns: '1fr 1fr',
    gap: 4,
    marginTop: 5,
  },
  exportBtn: {
    fontFamily: 'Fira Code, monospace',
    fontSize: 9,
    letterSpacing: '0.08em',
    padding: '4px 8px',
    border: '1px solid #30363D',
    color: '#8B949E',
    background: 'transparent',
    cursor: 'pointer',
    textAlign: 'left',
    transition: 'all 0.15s',
    borderRadius: 0,
  },
  exportBtnPrimary: {
    fontFamily: 'Fira Code, monospace',
    fontSize: 9,
    letterSpacing: '0.08em',
    padding: '4px 8px',
    border: '1px solid rgba(229,57,53,0.4)',
    color: 'rgba(229,57,53,0.7)',
    background: 'transparent',
    cursor: 'pointer',
    textAlign: 'left',
    transition: 'all 0.15s',
    borderRadius: 0,
    gridColumn: '1 / -1',
  },
  exportBtnDisabled: {
    opacity: 0.3,
    cursor: 'not-allowed',
    pointerEvents: 'none',
  },
  reportBadge: {
    marginTop: 5,
    padding: '3px 6px',
    background: 'rgba(0,255,65,0.05)',
    border: '1px solid rgba(0,255,65,0.2)',
    fontFamily: 'Fira Code, monospace',
    fontSize: 9,
    color: '#00FF41',
    letterSpacing: '0.08em',
  },
  pulseDot: {
    display: 'inline-block',
    width: 6,
    height: 6,
    borderRadius: '50%',
    background: '#FFB300',
    boxShadow: '0 0 6px #FFB300',
    animation: 'pulse-dot 1.2s ease-in-out infinite',
  },
}
