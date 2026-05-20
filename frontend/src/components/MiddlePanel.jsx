import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  useReactFlow,
  ReactFlowProvider,
  addEdge,
  Handle,
  Position,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'

/* ── Risk → visual mapping ─────────────────────────────────────── */
const RISK_STYLE = {
  critical: { border: '#FF0000', bg: '#1A0000', glow: '0 0 16px #FF0000, 0 0 32px rgba(255,0,0,0.4)' },
  high:     { border: '#FF5722', bg: '#1A0A00', glow: '0 0 12px #FF5722' },
  medium:   { border: '#FFB300', bg: '#1A1200', glow: '0 0 8px #FFB300' },
  low:      { border: '#30363D', bg: '#161B22', glow: 'none' },
}

const TYPE_ICON = {
  root:         '⬡',
  domain:       '🌐',
  subdomain:    '↳',
  ip_address:   '■',
  ip:           '■',
  service:      '⚙',
  open_port:    '⚙',
  email:        '✉',
  email_address:'✉',
  organization: '🏢',
  certificate:  '📜',
  http_service: '🌍',
  endpoint:     '🔗',
  technology:   '🧩',
  repository:   '📦',
  document:     '📄',
  asn:          '🌍',
  ip_range:     '🔢',
  person:       '👤',
  webapp:       '🖥',
  info:         '●',
}

/* ── Custom node component ─────────────────────────────────────── */
function MinaNode({ data }) {
  const risk = data.riskLevel || 'low'
  const style = RISK_STYLE[risk] || RISK_STYLE.low
  const icon = TYPE_ICON[data.nodeType] || '●'
  const isRoot = data.isRoot

  return (
    <div style={{
      minWidth: isRoot ? 120 : 80,
      padding: isRoot ? '8px 14px' : '5px 10px',
      background: isRoot ? '#8B0000' : style.bg,
      border: `1px solid ${isRoot ? '#E53935' : style.border}`,
      borderRadius: isRoot ? 4 : 2,
      boxShadow: isRoot
        ? '0 0 18px rgba(229,57,53,0.6)'
        : (risk !== 'low' ? style.glow : 'none'),
      textAlign: 'center',
      cursor: 'default',
      animation: data.isNew ? 'fadeInScale 0.5s ease-out' : 'none',
      position: 'relative',
    }}>
      <Handle type="target" position={Position.Top} style={{ background: '#30363D', border: 'none', width: 6, height: 6 }} />
      <div style={{
        fontFamily: 'Fira Code, monospace',
        fontSize: isRoot ? 12 : 10,
        fontWeight: isRoot ? 700 : 400,
        color: isRoot ? '#fff' : '#E6EDF3',
        letterSpacing: '0.05em',
        whiteSpace: 'nowrap',
        overflow: 'hidden',
        textOverflow: 'ellipsis',
        maxWidth: 160,
      }}>
        <span style={{ marginRight: 4, opacity: 0.7 }}>{icon}</span>
        {data.label}
      </div>
      {risk === 'critical' && (
        <div style={{
          fontSize: 8,
          color: '#FF3333',
          fontFamily: 'Fira Code, monospace',
          marginTop: 2,
        }}>💀 CRITICAL</div>
      )}
      {risk === 'high' && (
        <div style={{ fontSize: 8, color: '#FF5722', fontFamily: 'Fira Code, monospace', marginTop: 2 }}>
          🚨 HIGH
        </div>
      )}
      <Handle type="source" position={Position.Bottom} style={{ background: '#30363D', border: 'none', width: 6, height: 6 }} />
    </div>
  )
}

const nodeTypes = { minaNode: MinaNode }

/* ── Matrix rain background ────────────────────────────────────── */
function MatrixBackground() {
  const canvasRef = useRef(null)

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    let animId

    const resize = () => {
      canvas.width = canvas.offsetWidth
      canvas.height = canvas.offsetHeight
    }
    resize()
    window.addEventListener('resize', resize)

    const cols = Math.floor(canvas.width / 18)
    const drops = Array(cols).fill(1)
    const chars = 'アイウエオカキクケコ0123456789ABCDEF'

    function draw() {
      ctx.fillStyle = 'rgba(10,11,14,0.06)'
      ctx.fillRect(0, 0, canvas.width, canvas.height)
      ctx.fillStyle = 'rgba(0,255,65,0.06)'
      ctx.font = '12px Fira Code, monospace'
      for (let i = 0; i < drops.length; i++) {
        const text = chars[Math.floor(Math.random() * chars.length)]
        ctx.fillText(text, i * 18, drops[i] * 18)
        if (drops[i] * 18 > canvas.height && Math.random() > 0.975) drops[i] = 0
        drops[i]++
      }
      animId = requestAnimationFrame(draw)
    }
    draw()

    return () => {
      cancelAnimationFrame(animId)
      window.removeEventListener('resize', resize)
    }
  }, [])

  return (
    <canvas
      ref={canvasRef}
      style={{
        position: 'absolute',
        inset: 0,
        width: '100%',
        height: '100%',
        opacity: 0.4,
        pointerEvents: 'none',
        zIndex: 0,
      }}
    />
  )
}

/* ── Main panel (inner, needs ReactFlowProvider) ──────────────── */
function MiddlePanelInner({ nodes: externalNodes, edges: externalEdges }) {
  const [nodes, setNodes, onNodesChange] = useNodesState([])
  const [edges, setEdges, onEdgesChange] = useEdgesState([])
  const prevCountRef = useRef(0)
  const { fitView } = useReactFlow()

  // Sync external nodes/edges
  useEffect(() => { setNodes(externalNodes) }, [externalNodes, setNodes])
  useEffect(() => { setEdges(externalEdges) }, [externalEdges, setEdges])

  // Auto fitView when node count changes
  useEffect(() => {
    if (externalNodes.length !== prevCountRef.current && externalNodes.length > 0) {
      prevCountRef.current = externalNodes.length
      // Small delay so ReactFlow has time to render new nodes
      const t = setTimeout(() => fitView({ padding: 0.3, duration: 300 }), 100)
      return () => clearTimeout(t)
    }
  }, [externalNodes.length, fitView])

  // Clear isNew flag after animation completes
  useEffect(() => {
    const hasNew = externalNodes.some(n => n.data?.isNew)
    if (!hasNew) return
    const t = setTimeout(() => {
      setNodes(prev => prev.map(n =>
        n.data?.isNew ? { ...n, data: { ...n.data, isNew: false } } : n
      ))
    }, 600)
    return () => clearTimeout(t)
  }, [externalNodes, setNodes])

  const onConnect = useCallback(
    (params) => setEdges(eds => addEdge({ ...params, animated: true }, eds)),
    [setEdges]
  )

  const nodeCount = nodes.length
  const edgeCount = edges.length
  const criticalCount = nodes.filter(n => n.data?.riskLevel === 'critical').length
  const highCount = nodes.filter(n => n.data?.riskLevel === 'high').length

  return (
    <div className="panel panel-mid" style={{ position: 'relative' }}>
      {/* Header */}
      <div className="panel-header" style={{ zIndex: 10, position: 'relative', background: 'var(--bg-2)' }}>
        <span className="accent">◈</span>
        TACTICAL RELATIONSHIP GRAPH
        <span style={{ marginLeft: 'auto', display: 'flex', gap: 12 }}>
          <span style={{ color: '#8B949E', fontFamily: 'var(--font-mono)', fontSize: 9 }}>
            NODES: <span style={{ color: '#E6EDF3' }}>{nodeCount}</span>
          </span>
          {criticalCount > 0 && (
            <span style={{ color: '#FF3333', fontFamily: 'var(--font-mono)', fontSize: 9 }}>
              💀 CRITICAL: {criticalCount}
            </span>
          )}
          {highCount > 0 && (
            <span style={{ color: '#FF5722', fontFamily: 'var(--font-mono)', fontSize: 9 }}>
              🚨 HIGH: {highCount}
            </span>
          )}
        </span>
      </div>

      {/* Matrix canvas */}
      <MatrixBackground />

      {/* Empty state */}
      {nodeCount === 0 && (
        <div style={{
          position: 'absolute',
          inset: 0,
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 5,
          pointerEvents: 'none',
        }}>
          <div style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 11,
            color: '#30363D',
            letterSpacing: '0.2em',
            textAlign: 'center',
          }}>
            <div style={{ fontSize: 28, marginBottom: 10, opacity: 0.3 }}>⬡</div>
            AWAITING TARGET LOCK
            <div style={{ fontSize: 9, marginTop: 6, color: '#484F58' }}>
              Launch a scan to populate the graph
            </div>
          </div>
        </div>
      )}

      {/* ReactFlow */}
      <div style={{ position: 'absolute', inset: 0, zIndex: 2, top: 36 }}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onConnect={onConnect}
          nodeTypes={nodeTypes}
          fitView
          fitViewOptions={{ padding: 0.3 }}
          style={{ background: 'transparent' }}
          proOptions={{ hideAttribution: true }}
          defaultEdgeOptions={{
            animated: true,
            style: { stroke: '#30363D', strokeDasharray: '4,4', strokeWidth: 1 },
          }}
        >
          <Background color="#1a1f27" gap={24} size={1} />
          <Controls
            style={{
              background: '#161B22',
              border: '1px solid #30363D',
              borderRadius: 2,
            }}
          />
          <MiniMap
            nodeStrokeColor={(n) => {
              const risk = n.data?.riskLevel || 'low'
              return risk === 'critical' ? '#FF0000' : risk === 'high' ? '#FF5722' : '#30363D'
            }}
            nodeColor={(n) => {
              const risk = n.data?.riskLevel || 'low'
              return risk === 'critical' ? '#1A0000' : risk === 'high' ? '#1A0A00' : '#161B22'
            }}
            style={{ background: '#0A0B0E', border: '1px solid #30363D' }}
            maskColor="rgba(10,11,14,0.7)"
          />
        </ReactFlow>
      </div>
    </div>
  )
}

/* ── Wrapped export with ReactFlowProvider ─────────────────────── */
export default function MiddlePanel(props) {
  return (
    <ReactFlowProvider>
      <MiddlePanelInner {...props} />
    </ReactFlowProvider>
  )
}
