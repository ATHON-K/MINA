import { useState, useCallback, useEffect } from 'react'
import LeftPanel from './components/LeftPanel'
import MiddlePanel from './components/MiddlePanel'
import RightPanel from './components/RightPanel'
import MetricsDashboard from './components/MetricsDashboard'
import useWebSocket from './hooks/useWebSocket'

const API_BASE = (import.meta.env.VITE_API_BASE || `${window.location.protocol}//${window.location.hostname}:8000`).replace(/\/+$/, '')
const WS_BASE = (import.meta.env.VITE_WS_BASE || API_BASE.replace(/^http/, 'ws')).replace(/\/+$/, '')

function TopBar({ scanStatus, target }) {
  const [time, setTime] = useState(new Date().toLocaleTimeString('vi-VN', { hour12: false }))
  const [buildStamp, setBuildStamp] = useState('')
  useEffect(() => {
    const t = setInterval(() => setTime(new Date().toLocaleTimeString('vi-VN', { hour12: false })), 1000)
    return () => clearInterval(t)
  }, [])
  useEffect(() => {
    fetch(`${API_BASE}/api/version`)
      .then(r => r.json())
      .then(d => setBuildStamp(d.build_stamp || 'unknown'))
      .catch(() => setBuildStamp('offline'))
  }, [])

  return (
    <div className="top-bar">
      <div className="sys-info">
        <span>M.I.N.A v2.0 // MULTI INTELLIGENCE NETWORK AGENT</span>
        {buildStamp && <span style={{ color: '#30363D', fontSize: 10 }}>BUILD: {buildStamp}</span>}
        {target && <span style={{ color: '#E53935' }}>TARGET: {target.toUpperCase()}</span>}
      </div>
      <div className="sys-info">
        <span>STATUS: <span style={{
          color: scanStatus === 'running' ? '#FFB300'
               : scanStatus === 'complete' ? '#00FF41'
               : scanStatus === 'error' ? '#FF3333'
               : '#8B949E',
          fontWeight: 600,
        }}>{scanStatus.toUpperCase()}</span></span>
        <span className="sys-time">{time}</span>
      </div>
    </div>
  )
}

export default function App() {
  const [scanId, setScanId] = useState(null)
  const [scanStatus, setScanStatus] = useState('idle')
  const [target, setTarget] = useState('')
  const [logs, setLogs] = useState([])
  const [graphNodes, setGraphNodes] = useState([])
  const [graphEdges, setGraphEdges] = useState([])
  const [vulns, setVulns] = useState([])
  const [entities, setEntities] = useState([])
  const [intelEvents, setIntelEvents] = useState([])
  const [report, setReport] = useState('')
  const [collectorStats, setCollectorStats] = useState({})
  const [impactInsights, setImpactInsights] = useState([])
  const [relationships, setRelationships] = useState([])
  const [observations, setObservations] = useState([])
  const [findings, setFindings] = useState([])
  const [phaseLog, setPhaseLog] = useState([])
  const [leadsQueued, setLeadsQueued] = useState(0)
  const [leadsProcessed, setLeadsProcessed] = useState(0)
  const [activeBudgetUsed, setActiveBudgetUsed] = useState(0)
  const [activeBudgetMax, setActiveBudgetMax] = useState(0)
  const [stopReason, setStopReason] = useState('')
  const [showMetrics, setShowMetrics] = useState(false)

  // WebSocket handler
  const handleWsMessage = useCallback((msg) => {
    const type = msg.type

    if (type === 'log') {
      setLogs(prev => [...prev, msg])
    } else if (type === 'graph_node') {
      const node = msg.node
      if (!node?.id) return
      setGraphNodes(prev => {
        const exists = prev.some(n => n.id === node.id)
        if (exists) return prev
        const isRoot = node.is_root
        return [...prev, {
          id: node.id,
          type: 'minaNode',
          position: _calcPosition(prev.length, isRoot),
          data: {
            label: node.value || node.id,
            value: node.value || node.id,
            nodeType: node.type,
            riskLevel: node.risk_level || 'low',
            isRoot,
            isNew: true,
          },
        }]
      })
    } else if (type === 'graph_edge') {
      const edge = msg.edge
      if (edge?.source && edge?.target) {
        const edgeId = `${edge.source}-${edge.relation_type || 'rel'}-${edge.target}`
        setGraphEdges(prev => {
          if (prev.some(e => e.id === edgeId)) return prev
          return [
            ...prev,
            {
              id: edgeId,
              source: edge.source,
              target: edge.target,
              label: edge.relation_type,
              animated: true,
              style: { stroke: '#30363D', strokeDasharray: '4,4' },
              labelStyle: { fill: '#8B949E', fontSize: 9, fontFamily: 'Fira Code' },
            },
          ]
        })
      }
    } else if (type === 'graph_vuln') {
      // Highlight a node as vulnerable
      setGraphNodes(prev =>
        prev.map(n =>
          n.data.value === msg.node_value
            ? { ...n, data: { ...n.data, riskLevel: msg.impact?.toLowerCase() || 'high' } }
            : n
        )
      )
    } else if (type === 'vulnerability') {
      setVulns(prev => [...prev, msg.vuln])
    } else if (type === 'intel_event') {
      setIntelEvents(prev => [...prev, msg.payload])
    } else if (type === 'entity_update') {
      setEntities(prev => {
        const idx = prev.findIndex(e =>
          e.entity_id === msg.payload?.entity_id ||
          (e.type === msg.payload?.type && e.canonical_value === msg.payload?.canonical_value)
        )
        if (idx >= 0) {
          const updated = [...prev]
          updated[idx] = { ...prev[idx], ...msg.payload }
          return updated
        }
        return [...prev, msg.payload]
      })
    } else if (type === 'collector_stats') {
      if (msg.payload) setCollectorStats(msg.payload)
    } else if (type === 'lead_stats') {
      if (msg.payload) {
        setLeadsQueued(msg.payload.queued ?? 0)
        setLeadsProcessed(msg.payload.processed ?? 0)
      }
    } else if (type === 'budget_update') {
      if (msg.payload) {
        setActiveBudgetUsed(msg.payload.used ?? 0)
        setActiveBudgetMax(msg.payload.max ?? 0)
      }
    } else if (type === 'phase_log') {
      if (msg.payload) setPhaseLog(prev => [...prev, msg.payload])
    } else if (type === 'vuln_update') {
      // Incremental vulnerability update — same shape as 'vulnerability'
      if (msg.vuln) setVulns(prev => [...prev, msg.vuln])
    } else if (type === 'impact_update') {
      // Incremental impact insight update
      if (msg.payload) {
        setImpactInsights(prev => {
          const idx = prev.findIndex(i => i.entity_id === msg.payload.entity_id)
          if (idx >= 0) {
            const updated = [...prev]
            updated[idx] = { ...prev[idx], ...msg.payload }
            return updated
          }
          return [...prev, msg.payload]
        })
      }
    } else if (type === 'relationship_update') {
      if (msg.payload) {
        setRelationships(prev => [...prev, msg.payload])
      }
    } else if (type === 'finding_update') {
      if (msg.payload) {
        setFindings(prev => [...prev, msg.payload])
      }
    } else if (type === 'observation_update') {
      if (msg.payload) {
        setObservations(prev => [...prev, msg.payload])
      }
    } else if (type === 'scan_complete') {
      setScanStatus('complete')
      const sid = scanId || msg.scan_id
      if (sid) {
        // Fetch final results and reconcile everything missed during WS drops
        fetch(`${API_BASE}/api/scan/${sid}/results`)
          .then(r => r.json())
          .then(data => {
            setEntities(data.entities || [])
            if (data.relationships) setRelationships(data.relationships)
            if (data.observations) setObservations(data.observations)
            if (data.findings) setFindings(data.findings)
            if (data.phase_log) setPhaseLog(data.phase_log)
            if (data.stop_reason) setStopReason(data.stop_reason)
            if (data.lead_stats) {
              setLeadsQueued(data.lead_stats.queued ?? 0)
              setLeadsProcessed(data.lead_stats.processed ?? 0)
            }
            if (data.active_budget) {
              setActiveBudgetUsed(data.active_budget.used ?? 0)
              setActiveBudgetMax(data.active_budget.max ?? 0)
            }

            // Reconcile intel_events
            const restIntel = data.intel_events || []
            if (restIntel.length > 0) setIntelEvents(restIntel)

            // Reconcile vulns — override WS-streamed ones with authoritative REST data
            const restVulns = data.vulnerabilities || []
            if (restVulns.length > 0) {
              setVulns(restVulns.map(v => ({
                asset:         v.asset         || v.target || '',
                type:          v.type          || v.vuln_type || 'finding',
                vulnerability: v.vulnerability || v.description || v.name || '',
                impact:        (v.impact || 'LOW').toUpperCase(),
              })))
            }

            // Rebuild any graph nodes that were missed (e.g. WS dropped mid-scan)
            const fetchedEntities = data.entities || []
            if (fetchedEntities.length > 0) {
              setGraphNodes(prev => {
                const existingIds = new Set(prev.map(n => n.id))
                const missing = fetchedEntities
                  .filter(e => {
                    const eid = e.entity_id || e.canonical_value
                    return eid && !existingIds.has(eid)
                  })
                  .map((e, i) => ({
                    id: e.entity_id || e.canonical_value,
                    type: 'minaNode',
                    position: _calcPosition(prev.length + i, false),
                    data: {
                      label: e.canonical_value,
                      value: e.canonical_value,
                      nodeType: e.type,
                      riskLevel: e.risk_level || 'low',
                      isRoot: false,
                    },
                  }))
                return missing.length > 0 ? [...prev, ...missing] : prev
              })
            }
            // Set collector stats from REST data
            if (data.collector_stats) setCollectorStats(data.collector_stats)
          })
          .catch(() => {})
        fetch(`${API_BASE}/api/scan/${sid}/report`)
          .then(r => r.text())
          .then(md => setReport(md))
          .catch(() => {})
      }
    } else if (type === 'error') {
      setScanStatus('error')
      setLogs(prev => [...prev, {
        type: 'log', agent: 'System', level: 'alert',
        message: `ERROR: ${msg.message}`,
        timestamp: new Date().toISOString(),
      }])
    }
  }, [scanId])

  const { connect, disconnect } = useWebSocket(handleWsMessage)

  // Polling fallback: if WS drops mid-scan, poll status every 5s
  // so scan_complete is never silently missed.
  useEffect(() => {
    if (scanStatus !== 'running' || !scanId) return
    const interval = setInterval(async () => {
      try {
        const r = await fetch(`${API_BASE}/api/scan/${scanId}/status`)
        const data = await r.json()
        if (data.status === 'complete') {
          handleWsMessage({ type: 'scan_complete', scan_id: scanId })
        } else if (data.status === 'error') {
          setScanStatus('error')
        }
      } catch { /* network hiccup — ignore */ }
    }, 5000)
    return () => clearInterval(interval)
  }, [scanStatus, scanId, handleWsMessage])

  // Start scan
  const handleStartScan = useCallback(async (formData) => {
    try {
      setScanStatus('pending')
      setLogs([])
      setGraphNodes([])
      setGraphEdges([])
      setVulns([])
      setEntities([])
      setIntelEvents([])
      setReport('')
      setCollectorStats({})
      setRelationships([])
      setObservations([])
      setFindings([])
      setPhaseLog([])
      setLeadsQueued(0)
      setLeadsProcessed(0)
      setActiveBudgetUsed(0)
      setActiveBudgetMax(0)
      setStopReason('')
      setShowMetrics(false)
      setTarget(formData.target)

      const res = await fetch(`${API_BASE}/api/scan/start`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData),
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()

      setScanId(data.scan_id)
      setScanStatus('running')
      connect(`${WS_BASE}/ws/${data.scan_id}`)
    } catch (err) {
      setScanStatus('error')
      setLogs([{
        type: 'log', agent: 'System', level: 'alert',
        message: `Failed to start scan: ${err.message}`,
        timestamp: new Date().toISOString(),
      }])
    }
  }, [connect])

  const handleExport = useCallback(async (fmt) => {
    if (!scanId) return
    const url = `${API_BASE}/api/scan/${scanId}/export/${fmt}`
    const a = document.createElement('a')
    a.href = url
    a.download = `mina_export.${fmt}`
    a.click()
  }, [scanId])

  return (
    <div className="app-wrapper">
      <TopBar scanStatus={scanStatus} target={target} />
      {/* Metrics toggle button */}
      {scanStatus !== 'idle' && (
        <div style={{ padding: '0 12px' }}>
          <button
            onClick={() => setShowMetrics(v => !v)}
            style={{
              background: 'transparent', border: '1px solid #30363D', color: '#60a5fa',
              padding: '2px 12px', borderRadius: 4, cursor: 'pointer', fontSize: '0.75rem',
              fontFamily: 'Fira Code, monospace', marginBottom: 4,
            }}
          >
            {showMetrics ? '▼ Hide Metrics' : '▶ Show Metrics'}
          </button>
          {showMetrics && (
            <MetricsDashboard
              collectorStats={collectorStats}
              entities={entities}
              relationships={relationships}
              observations={observations}
              findings={findings}
              phaseLog={phaseLog}
              leadsQueued={leadsQueued}
              leadsProcessed={leadsProcessed}
              activeBudgetUsed={activeBudgetUsed}
              activeBudgetMax={activeBudgetMax}
              stopReason={stopReason}
            />
          )}
        </div>
      )}
      <div className="panels-row">
        <LeftPanel
          onStartScan={handleStartScan}
          scanStatus={scanStatus}
        />
        <div className="panel-divider" />
        <MiddlePanel
          nodes={graphNodes}
          edges={graphEdges}
        />
        <div className="panel-divider" />
        <RightPanel
          logs={logs}
          vulns={vulns}
          entities={entities}
          intelEvents={intelEvents}
          report={report}
          scanStatus={scanStatus}
          onExport={handleExport}
          collectorStats={collectorStats}
          relationships={relationships}
          findings={findings}
          observations={observations}
        />
      </div>
    </div>
  )
}

// Helper: naive force-graph-like positioning
function _calcPosition(index, isRoot) {
  if (isRoot) return { x: 0, y: 0 }
  const angle = (index * 137.5) * (Math.PI / 180) // golden angle
  const radius = 80 + Math.floor(index / 8) * 80
  return {
    x: Math.cos(angle) * radius,
    y: Math.sin(angle) * radius,
  }
}
