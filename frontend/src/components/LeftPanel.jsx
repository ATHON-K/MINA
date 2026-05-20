import { useState } from 'react'

const AGENTS = [
  { key: 'passive_recon', label: 'PASSIVE RECON', default: true },
  { key: 'osint',         label: 'OSINT',         default: true },
  { key: 'karma_v2',      label: 'KARMA V2',      default: true },
  { key: 'active_recon',  label: 'ACTIVE RECON',  default: true },
  { key: 'normalizer',    label: 'NORMALIZER',    default: true },
  { key: 'reporter',      label: 'REPORTER',      default: true },
]

const SCAN_PROFILES = [
  { value: 'quick',    label: '⚡ QUICK',    desc: 'Passive only, < 5 min' },
  { value: 'balanced', label: '⚖️ BALANCED', desc: 'Passive + light active, ~15 min' },
  { value: 'deep',     label: '🔬 DEEP',     desc: 'Full collectors, 30+ min' },
]

const WORDLIST_PROFILES = [
  { value: 'small',    label: 'SMALL',    desc: 'Top 100 subdomains' },
  { value: 'medium',   label: 'MEDIUM',   desc: 'Medium wordlists' },
  { value: 'extended', label: 'EXTENDED', desc: 'Extended wordlists' },
]

const REPORT_MODES = [
  { value: 'summary',        label: 'SUMMARY',    desc: 'Concise executive report' },
  { value: 'detailed',       label: 'DETAILED',   desc: 'Full tables + narrative' },
  { value: 'full_inventory', label: 'INVENTORY',  desc: 'Complete asset inventory' },
]

// V4: Per-tool feature toggles
const TOOL_FEATURES = [
  { key: 'subfinder',    label: 'Subfinder',       default: true },
  { key: 'httpx',        label: 'HTTPX',           default: true },
  { key: 'nmap',         label: 'Nmap',            default: true },
  { key: 'nuclei',       label: 'Nuclei',          default: true },
  { key: 'crawler',      label: 'Crawler',         default: true },
  { key: 'dir_enum',     label: 'Dir Enum',        default: true },
  { key: 'shodan',       label: 'Shodan',          default: true },
  { key: 'karma',        label: 'Karma',           default: true },
]

// V4: Default tool options structure — MAX MODE
// Keys match TOOL_FEATURES keys for consistency; backend normalises to dispatch keys
const DEFAULT_TOOL_OPTIONS = {
  nmap: { ports_mode: 'top1000', service_detection: true, safe_scripts: true, timing_profile: 'T4', timeout: 600 },
  nuclei: { severity: ['low', 'medium', 'high', 'critical'], rate_limit: 150, concurrency: 25, timeout: 600, safe_mode: false },
  crawler: { max_pages: 500, depth: 5, same_host_only: true, extract_forms: true, timeout: 60 },
  dir_enum: { wordlist_type: 'medium', extensions: 'php,asp,aspx,js,json,txt,bak,xml,conf,env,zip', max_workers: 20, rate_limit: 0.3 },
  subfinder: { recursive: true, all_sources: true, timeout: 180 },
  httpx: { follow_redirects: true, capture_title: true, capture_tech: true, timeout: 60 },
  karma: { ip_scan: true, leaks: true, cve: true, smap: true, timeout: 180 },
}

export default function LeftPanel({ onStartScan, scanStatus }) {
  const [target, setTarget] = useState('')
  const [company, setCompany] = useState('')
  const [outOfScope, setOutOfScope] = useState('')
  const [activeRecon, setActiveRecon] = useState(true)
  const [rateLimit, setRateLimit] = useState(3)
  const [maxDepth, setMaxDepth] = useState(5)
  const [maxIter, setMaxIter] = useState(20)
  const [timeBudget, setTimeBudget] = useState(3600)
  const [passiveOnly, setPassiveOnly] = useState(false)
  const [allowedSources, setAllowedSources] = useState('')
  const [scanProfile, setScanProfile] = useState('deep')
  const [wordlistProfile, setWordlistProfile] = useState('extended')
  const [reportDetail, setReportDetail] = useState('full_inventory')
  const [agentsEnabled, setAgentsEnabled] = useState(() =>
    Object.fromEntries(AGENTS.map(a => [a.key, a.default]))
  )
  // V4: features (per-tool toggles)
  const [features, setFeatures] = useState(() =>
    Object.fromEntries(TOOL_FEATURES.map(t => [t.key, t.default]))
  )
  // V4: tool options
  const [toolOptions, setToolOptions] = useState(() => JSON.parse(JSON.stringify(DEFAULT_TOOL_OPTIONS)))
  // V4: collapsible sections — open by default for full visibility
  const [showToolOptions, setShowToolOptions] = useState(true)
  const [showFeatures, setShowFeatures] = useState(true)

  const isRunning = scanStatus === 'running' || scanStatus === 'pending'

  function toggleAgent(key) {
    setAgentsEnabled(prev => ({ ...prev, [key]: !prev[key] }))
  }

  function toggleFeature(key) {
    setFeatures(prev => ({ ...prev, [key]: !prev[key] }))
  }

  function updateToolOption(tool, key, value) {
    setToolOptions(prev => ({
      ...prev,
      [tool]: { ...prev[tool], [key]: value },
    }))
  }

  function handleSubmit(e) {
    e.preventDefault()
    if (!target.trim()) return
    const oos = outOfScope.split('\n').map(s => s.trim()).filter(Boolean)
    const parsedSources = allowedSources.split(',').map(s => s.trim()).filter(Boolean)
    onStartScan({
      target: target.trim(),
      company_name: company.trim(),
      allowed_scope: [target.trim()],
      out_of_scope: oos,
      active_recon_enabled: activeRecon && !passiveOnly,
      passive_only: passiveOnly,
      rate_limit: rateLimit,
      max_depth: maxDepth,
      max_iterations: maxIter,
      time_budget_seconds: timeBudget,
      scan_profile: scanProfile,
      wordlist_profile: wordlistProfile,
      agents_enabled: agentsEnabled,
      features: features,
      tool_options: toolOptions,
      report_detail: reportDetail,
      ...(parsedSources.length > 0 ? { allowed_sources: parsedSources } : {}),
    })
  }

  return (
    <div className="panel panel-left" style={{ overflowY: 'auto' }}>
      {/* ── Logo ──────────────────────────────────────────────── */}
      <div style={{
        padding: '16px 12px 12px',
        borderBottom: '1px solid #30363D',
      }}>
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
          fontFamily: 'var(--font-mono)',
          fontWeight: 700,
          fontSize: 24,
          letterSpacing: '0.2em',
          color: '#E6EDF3',
        }}>
          <span style={{ color: '#E53935', fontSize: 10, fontWeight: 400 }}>[ </span>
          M.I.N.A
          <span style={{ color: '#E53935', fontSize: 10, fontWeight: 400 }}> ]</span>
          <span style={{
            width: 8,
            height: 8,
            borderRadius: '50%',
            background: '#E53935',
            flexShrink: 0,
            animation: 'pulse-dot 1.4s ease-in-out infinite',
            boxShadow: '0 0 6px #E53935',
          }} />
        </div>
        <div style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 11,
          color: '#8B949E',
          letterSpacing: '0.15em',
          marginTop: 4,
        }}>
          MULTI INTELLIGENCE NETWORK AGENT v2.0
        </div>
        <div style={{
          fontFamily: 'var(--font-mono)',
          fontSize: 9,
          color: '#30363D',
          letterSpacing: '0.1em',
          marginTop: 2,
          userSelect: 'none',
        }}>
          SOURCE CHECK: ZIP-V4
        </div>
      </div>

      <form onSubmit={handleSubmit} style={{ padding: '12px', display: 'flex', flexDirection: 'column', gap: 16 }}>

        {/* ── TARGET LOCK ──────────────────────────────────────── */}
        <div>
          <div className="section-label">TARGET LOCK</div>
          <div style={{ position: 'relative', display: 'flex', alignItems: 'center', marginBottom: 6 }}>
            <span style={{
              position: 'absolute',
              left: 8,
              fontFamily: 'var(--font-mono)',
              color: '#00FF41',
              fontSize: 12,
              pointerEvents: 'none',
            }}>&#62;</span>
            <input
              className="mono-input"
              style={{ paddingLeft: 22 }}
              type="text"
              placeholder="target-domain.com"
              value={target}
              onChange={e => setTarget(e.target.value)}
              disabled={isRunning}
              required
            />
          </div>
          <div style={{ position: 'relative', display: 'flex', alignItems: 'center', marginBottom: 8 }}>
            <span style={{
              position: 'absolute',
              left: 8,
              fontFamily: 'var(--font-mono)',
              color: '#8B949E',
              fontSize: 12,
              pointerEvents: 'none',
            }}>@</span>
            <input
              className="mono-input"
              style={{ paddingLeft: 22 }}
              type="text"
              placeholder="Company name (optional)"
              value={company}
              onChange={e => setCompany(e.target.value)}
              disabled={isRunning}
            />
          </div>
          <button
            type="submit"
            className="btn btn-danger"
            disabled={isRunning || !target.trim()}
            style={{ width: '100%' }}
          >
            {isRunning ? '⚡ SCANNING...' : '[ LOCK TARGET ]'}
          </button>
        </div>

        {/* ── SCAN PROFILE ──────────────────────────────────── */}
        <div>
          <div className="section-label">SCAN PROFILE</div>
          <div style={{ display: 'flex', gap: 6 }}>
            {SCAN_PROFILES.map(p => (
              <button
                key={p.value}
                type="button"
                disabled={isRunning}
                onClick={() => setScanProfile(p.value)}
                style={{
                  flex: 1,
                  padding: '6px 4px',
                  fontFamily: 'var(--font-mono)',
                  fontSize: 9,
                  letterSpacing: '0.08em',
                  cursor: isRunning ? 'not-allowed' : 'pointer',
                  border: `1px solid ${scanProfile === p.value ? '#E53935' : '#30363D'}`,
                  background: scanProfile === p.value ? 'rgba(229,57,53,0.12)' : 'var(--bg-1)',
                  color: scanProfile === p.value ? '#E53935' : '#8B949E',
                  borderRadius: 2,
                  transition: 'all 0.15s',
                }}
              >
                {p.label}
              </button>
            ))}
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: '#484F58', marginTop: 4 }}>
            {SCAN_PROFILES.find(p => p.value === scanProfile)?.desc}
          </div>
        </div>

        {/* ── WORDLIST PROFILE ───────────────────────────────── */}
        <div>
          <div className="section-label">WORDLIST PROFILE</div>
          <div style={{ display: 'flex', gap: 6 }}>
            {WORDLIST_PROFILES.map(p => (
              <button
                key={p.value}
                type="button"
                disabled={isRunning}
                onClick={() => setWordlistProfile(p.value)}
                style={{
                  flex: 1,
                  padding: '6px 4px',
                  fontFamily: 'var(--font-mono)',
                  fontSize: 9,
                  letterSpacing: '0.08em',
                  cursor: isRunning ? 'not-allowed' : 'pointer',
                  border: `1px solid ${wordlistProfile === p.value ? '#58A6FF' : '#30363D'}`,
                  background: wordlistProfile === p.value ? 'rgba(88,166,255,0.1)' : 'var(--bg-1)',
                  color: wordlistProfile === p.value ? '#58A6FF' : '#8B949E',
                  borderRadius: 2,
                  transition: 'all 0.15s',
                }}
              >
                {p.label}
              </button>
            ))}
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: '#484F58', marginTop: 4 }}>
            {WORDLIST_PROFILES.find(p => p.value === wordlistProfile)?.desc}
          </div>
        </div>

        {/* ── AGENT DISPATCH ─────────────────────────────────── */}
        <div>
          <div className="section-label">AGENT DISPATCH</div>
          {AGENTS.map(agent => (
            <div className="toggle-row" key={agent.key}>
              <span className="toggle-label" style={{
                color: agentsEnabled[agent.key] ? '#E6EDF3' : '#484F58',
              }}>
                {agent.label}
              </span>
              <label className="toggle">
                <input
                  type="checkbox"
                  checked={agentsEnabled[agent.key]}
                  onChange={() => toggleAgent(agent.key)}
                  disabled={isRunning}
                />
                <span className="toggle-slider" />
              </label>
            </div>
          ))}
          <div className="toggle-row" style={{ marginTop: 4 }}>
            <span className="toggle-label" style={{
              color: activeRecon ? '#E6EDF3' : '#484F58',
            }}>ACTIVE RECON ENABLED</span>
            <label className="toggle">
              <input
                type="checkbox"
                checked={activeRecon}
                onChange={e => setActiveRecon(e.target.checked)}
                disabled={isRunning}
              />
              <span className="toggle-slider" />
            </label>
          </div>
        </div>

        {/* ── V4: TOOL FEATURES ──────────────────────────────── */}
        <div>
          <div
            className="section-label"
            style={{ cursor: 'pointer', userSelect: 'none' }}
            onClick={() => setShowFeatures(!showFeatures)}
          >
            {showFeatures ? '▾' : '▸'} TOOL FEATURES
          </div>
          {showFeatures && (
            <div>
              {TOOL_FEATURES.map(tool => (
                <div className="toggle-row" key={tool.key}>
                  <span className="toggle-label" style={{
                    color: features[tool.key] ? '#E6EDF3' : '#484F58',
                    fontSize: 10,
                  }}>
                    {tool.label}
                  </span>
                  <label className="toggle">
                    <input
                      type="checkbox"
                      checked={features[tool.key]}
                      onChange={() => toggleFeature(tool.key)}
                      disabled={isRunning}
                    />
                    <span className="toggle-slider" />
                  </label>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* ── V4: TOOL OPTIONS ───────────────────────────────── */}
        <div>
          <div
            className="section-label"
            style={{ cursor: 'pointer', userSelect: 'none' }}
            onClick={() => setShowToolOptions(!showToolOptions)}
          >
            {showToolOptions ? '▾' : '▸'} TOOL OPTIONS
          </div>
          {showToolOptions && (
            <div style={{ fontSize: 10, fontFamily: 'var(--font-mono)' }}>
              {/* Nmap */}
              <div style={{ marginBottom: 8, padding: '4px 0', borderBottom: '1px solid #21262D' }}>
                <div style={{ color: '#58A6FF', marginBottom: 4 }}>NMAP</div>
                <div style={{ display: 'flex', gap: 4, alignItems: 'center', marginBottom: 3 }}>
                  <span style={{ color: '#8B949E', width: 80 }}>Ports</span>
                  <select
                    value={toolOptions.nmap?.ports_mode || 'top100'}
                    onChange={e => updateToolOption('nmap', 'ports_mode', e.target.value)}
                    disabled={isRunning}
                    style={{ flex: 1, background: 'var(--bg-1)', color: '#E6EDF3', border: '1px solid #30363D', fontSize: 9, padding: '2px 4px' }}
                  >
                    <option value="top100">Top 100</option>
                    <option value="top1000">Top 1000</option>
                    <option value="custom">Custom</option>
                  </select>
                </div>
                <div className="toggle-row">
                  <span className="toggle-label" style={{ color: '#8B949E', fontSize: 9 }}>Service Detection</span>
                  <label className="toggle">
                    <input type="checkbox" checked={toolOptions.nmap?.service_detection ?? true}
                      onChange={e => updateToolOption('nmap', 'service_detection', e.target.checked)}
                      disabled={isRunning} />
                    <span className="toggle-slider" />
                  </label>
                </div>
                <div className="toggle-row">
                  <span className="toggle-label" style={{ color: '#8B949E', fontSize: 9 }}>Safe Scripts</span>
                  <label className="toggle">
                    <input type="checkbox" checked={toolOptions.nmap?.safe_scripts ?? true}
                      onChange={e => updateToolOption('nmap', 'safe_scripts', e.target.checked)}
                      disabled={isRunning} />
                    <span className="toggle-slider" />
                  </label>
                </div>
              </div>

              {/* Nuclei */}
              <div style={{ marginBottom: 8, padding: '4px 0', borderBottom: '1px solid #21262D' }}>
                <div style={{ color: '#58A6FF', marginBottom: 4 }}>NUCLEI</div>
                <div style={{ display: 'flex', gap: 4, alignItems: 'center', marginBottom: 3 }}>
                  <span style={{ color: '#8B949E', width: 80 }}>Severity</span>
                  <input
                    type="text"
                    value={(toolOptions.nuclei?.severity || []).join(',')}
                    onChange={e => updateToolOption('nuclei', 'severity', e.target.value.split(',').map(s => s.trim()).filter(Boolean))}
                    disabled={isRunning}
                    placeholder="medium,high,critical"
                    style={{ flex: 1, background: 'var(--bg-1)', color: '#E6EDF3', border: '1px solid #30363D', fontSize: 9, padding: '2px 4px' }}
                  />
                </div>
                <div style={{ display: 'flex', gap: 4, alignItems: 'center', marginBottom: 3 }}>
                  <span style={{ color: '#8B949E', width: 80 }}>Rate Limit</span>
                  <input type="number" value={toolOptions.nuclei?.rate_limit ?? 50}
                    onChange={e => updateToolOption('nuclei', 'rate_limit', parseInt(e.target.value) || 50)}
                    disabled={isRunning} min={1} max={200}
                    style={{ width: 50, background: 'var(--bg-1)', color: '#E6EDF3', border: '1px solid #30363D', fontSize: 9, padding: '2px 4px' }}
                  />
                </div>
                <div style={{ display: 'flex', gap: 4, alignItems: 'center', marginBottom: 3 }}>
                  <span style={{ color: '#8B949E', width: 80 }}>Timeout (s)</span>
                  <input type="number" value={toolOptions.nuclei?.timeout ?? 300}
                    onChange={e => updateToolOption('nuclei', 'timeout', parseInt(e.target.value) || 300)}
                    disabled={isRunning} min={30} max={900}
                    style={{ width: 50, background: 'var(--bg-1)', color: '#E6EDF3', border: '1px solid #30363D', fontSize: 9, padding: '2px 4px' }}
                  />
                </div>
              </div>

              {/* Crawl */}
              <div style={{ marginBottom: 8, padding: '4px 0', borderBottom: '1px solid #21262D' }}>
                <div style={{ color: '#58A6FF', marginBottom: 4 }}>CRAWLER</div>
                <div style={{ display: 'flex', gap: 4, alignItems: 'center', marginBottom: 3 }}>
                  <span style={{ color: '#8B949E', width: 80 }}>Max Pages</span>
                  <input type="number" value={toolOptions.crawl?.max_pages ?? 100}
                    onChange={e => updateToolOption('crawl', 'max_pages', parseInt(e.target.value) || 100)}
                    disabled={isRunning} min={10} max={500}
                    style={{ width: 50, background: 'var(--bg-1)', color: '#E6EDF3', border: '1px solid #30363D', fontSize: 9, padding: '2px 4px' }}
                  />
                </div>
                <div style={{ display: 'flex', gap: 4, alignItems: 'center', marginBottom: 3 }}>
                  <span style={{ color: '#8B949E', width: 80 }}>Depth</span>
                  <input type="number" value={toolOptions.crawl?.depth ?? 2}
                    onChange={e => updateToolOption('crawl', 'depth', parseInt(e.target.value) || 2)}
                    disabled={isRunning} min={1} max={5}
                    style={{ width: 50, background: 'var(--bg-1)', color: '#E6EDF3', border: '1px solid #30363D', fontSize: 9, padding: '2px 4px' }}
                  />
                </div>
                <div className="toggle-row">
                  <span className="toggle-label" style={{ color: '#8B949E', fontSize: 9 }}>Extract Forms</span>
                  <label className="toggle">
                    <input type="checkbox" checked={toolOptions.crawl?.extract_forms ?? true}
                      onChange={e => updateToolOption('crawl', 'extract_forms', e.target.checked)}
                      disabled={isRunning} />
                    <span className="toggle-slider" />
                  </label>
                </div>
              </div>

              {/* Dirs */}
              <div style={{ marginBottom: 8, padding: '4px 0', borderBottom: '1px solid #21262D' }}>
                <div style={{ color: '#58A6FF', marginBottom: 4 }}>DIR ENUM</div>
                <div style={{ display: 'flex', gap: 4, alignItems: 'center', marginBottom: 3 }}>
                  <span style={{ color: '#8B949E', width: 80 }}>Wordlist</span>
                  <select
                    value={toolOptions.dirs?.wordlist_type || 'small'}
                    onChange={e => updateToolOption('dirs', 'wordlist_type', e.target.value)}
                    disabled={isRunning}
                    style={{ flex: 1, background: 'var(--bg-1)', color: '#E6EDF3', border: '1px solid #30363D', fontSize: 9, padding: '2px 4px' }}
                  >
                    <option value="small">Small</option>
                    <option value="medium">Medium</option>
                    <option value="extended">Extended</option>
                  </select>
                </div>
                <div style={{ display: 'flex', gap: 4, alignItems: 'center', marginBottom: 3 }}>
                  <span style={{ color: '#8B949E', width: 80 }}>Extensions</span>
                  <input type="text" value={toolOptions.dirs?.extensions || 'php,asp,js,json,txt,bak'}
                    onChange={e => updateToolOption('dirs', 'extensions', e.target.value)}
                    disabled={isRunning}
                    style={{ flex: 1, background: 'var(--bg-1)', color: '#E6EDF3', border: '1px solid #30363D', fontSize: 9, padding: '2px 4px' }}
                  />
                </div>
                <div style={{ display: 'flex', gap: 4, alignItems: 'center', marginBottom: 3 }}>
                  <span style={{ color: '#8B949E', width: 80 }}>Workers</span>
                  <input type="number" value={toolOptions.dirs?.max_workers ?? 10}
                    onChange={e => updateToolOption('dirs', 'max_workers', parseInt(e.target.value) || 10)}
                    disabled={isRunning} min={1} max={50}
                    style={{ width: 50, background: 'var(--bg-1)', color: '#E6EDF3', border: '1px solid #30363D', fontSize: 9, padding: '2px 4px' }}
                  />
                </div>
              </div>

              {/* Subfinder */}
              <div style={{ marginBottom: 8, padding: '4px 0', borderBottom: '1px solid #21262D' }}>
                <div style={{ color: '#58A6FF', marginBottom: 4 }}>SUBFINDER</div>
                <div className="toggle-row">
                  <span className="toggle-label" style={{ color: '#8B949E', fontSize: 9 }}>Recursive</span>
                  <label className="toggle">
                    <input type="checkbox" checked={toolOptions.subfinder?.recursive ?? false}
                      onChange={e => updateToolOption('subfinder', 'recursive', e.target.checked)}
                      disabled={isRunning} />
                    <span className="toggle-slider" />
                  </label>
                </div>
                <div className="toggle-row">
                  <span className="toggle-label" style={{ color: '#8B949E', fontSize: 9 }}>All Sources</span>
                  <label className="toggle">
                    <input type="checkbox" checked={toolOptions.subfinder?.all_sources ?? false}
                      onChange={e => updateToolOption('subfinder', 'all_sources', e.target.checked)}
                      disabled={isRunning} />
                    <span className="toggle-slider" />
                  </label>
                </div>
              </div>

              {/* HTTPX */}
              <div style={{ marginBottom: 8, padding: '4px 0', borderBottom: '1px solid #21262D' }}>
                <div style={{ color: '#58A6FF', marginBottom: 4 }}>HTTPX</div>
                <div className="toggle-row">
                  <span className="toggle-label" style={{ color: '#8B949E', fontSize: 9 }}>Follow Redirects</span>
                  <label className="toggle">
                    <input type="checkbox" checked={toolOptions.httpx?.follow_redirects ?? true}
                      onChange={e => updateToolOption('httpx', 'follow_redirects', e.target.checked)}
                      disabled={isRunning} />
                    <span className="toggle-slider" />
                  </label>
                </div>
                <div className="toggle-row">
                  <span className="toggle-label" style={{ color: '#8B949E', fontSize: 9 }}>Capture Title</span>
                  <label className="toggle">
                    <input type="checkbox" checked={toolOptions.httpx?.capture_title ?? true}
                      onChange={e => updateToolOption('httpx', 'capture_title', e.target.checked)}
                      disabled={isRunning} />
                    <span className="toggle-slider" />
                  </label>
                </div>
                <div className="toggle-row">
                  <span className="toggle-label" style={{ color: '#8B949E', fontSize: 9 }}>Capture Tech</span>
                  <label className="toggle">
                    <input type="checkbox" checked={toolOptions.httpx?.capture_tech ?? true}
                      onChange={e => updateToolOption('httpx', 'capture_tech', e.target.checked)}
                      disabled={isRunning} />
                    <span className="toggle-slider" />
                  </label>
                </div>
              </div>

              {/* Karma / Passive Engines */}
              <div style={{ marginBottom: 8, padding: '4px 0' }}>
                <div style={{ color: '#FF3D00', marginBottom: 4 }}>KARMA / PASSIVE ENGINES</div>
                <div className="toggle-row">
                  <span className="toggle-label" style={{ color: '#8B949E', fontSize: 9 }}>Karma IP Scan</span>
                  <label className="toggle">
                    <input type="checkbox" checked={toolOptions.karma?.ip_scan ?? true}
                      onChange={e => updateToolOption('karma', 'ip_scan', e.target.checked)}
                      disabled={isRunning} />
                    <span className="toggle-slider" />
                  </label>
                </div>
                <div className="toggle-row">
                  <span className="toggle-label" style={{ color: '#8B949E', fontSize: 9 }}>Karma Leaks</span>
                  <label className="toggle">
                    <input type="checkbox" checked={toolOptions.karma?.leaks ?? true}
                      onChange={e => updateToolOption('karma', 'leaks', e.target.checked)}
                      disabled={isRunning} />
                    <span className="toggle-slider" />
                  </label>
                </div>
                <div className="toggle-row">
                  <span className="toggle-label" style={{ color: '#8B949E', fontSize: 9 }}>Karma CVE</span>
                  <label className="toggle">
                    <input type="checkbox" checked={toolOptions.karma?.cve ?? true}
                      onChange={e => updateToolOption('karma', 'cve', e.target.checked)}
                      disabled={isRunning} />
                    <span className="toggle-slider" />
                  </label>
                </div>
                <div className="toggle-row">
                  <span className="toggle-label" style={{ color: '#8B949E', fontSize: 9 }}>SMAP (Shodan-free Nmap)</span>
                  <label className="toggle">
                    <input type="checkbox" checked={toolOptions.karma?.smap ?? false}
                      onChange={e => updateToolOption('karma', 'smap', e.target.checked)}
                      disabled={isRunning} />
                    <span className="toggle-slider" />
                  </label>
                </div>
                <div style={{ display: 'flex', gap: 4, alignItems: 'center', marginBottom: 3 }}>
                  <span style={{ color: '#8B949E', width: 80 }}>Timeout (s)</span>
                  <input type="number" value={toolOptions.karma?.timeout ?? 90}
                    onChange={e => updateToolOption('karma', 'timeout', parseInt(e.target.value) || 90)}
                    disabled={isRunning} min={30} max={600}
                    style={{ width: 50, background: 'var(--bg-1)', color: '#E6EDF3', border: '1px solid #30363D', fontSize: 9, padding: '2px 4px' }}
                  />
                </div>
              </div>
            </div>
          )}
        </div>

        {/* ── V4: REPORT MODE ────────────────────────────────── */}
        <div>
          <div className="section-label">REPORT MODE</div>
          <div style={{ display: 'flex', gap: 6 }}>
            {REPORT_MODES.map(p => (
              <button
                key={p.value}
                type="button"
                disabled={isRunning}
                onClick={() => setReportDetail(p.value)}
                style={{
                  flex: 1,
                  padding: '6px 4px',
                  fontFamily: 'var(--font-mono)',
                  fontSize: 9,
                  letterSpacing: '0.08em',
                  cursor: isRunning ? 'not-allowed' : 'pointer',
                  border: `1px solid ${reportDetail === p.value ? '#00FF41' : '#30363D'}`,
                  background: reportDetail === p.value ? 'rgba(0,255,65,0.08)' : 'var(--bg-1)',
                  color: reportDetail === p.value ? '#00FF41' : '#8B949E',
                  borderRadius: 2,
                  transition: 'all 0.15s',
                }}
              >
                {p.label}
              </button>
            ))}
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: '#484F58', marginTop: 4 }}>
            {REPORT_MODES.find(p => p.value === reportDetail)?.desc}
          </div>
        </div>

        {/* ── RULES OF ENGAGEMENT ────────────────────────────── */}
        <div>
          <div className="section-label">RULES OF ENGAGEMENT</div>

          <div style={{ marginBottom: 10 }}>
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              marginBottom: 4,
              fontFamily: 'var(--font-mono)',
              fontSize: 10,
              color: '#8B949E',
            }}>
              <span>RATE LIMIT (sec)</span>
              <span style={{ color: '#FFB300' }}>{rateLimit}s</span>
            </div>
            <input
              type="range"
              className="styled-range"
              min="0.5" max="10" step="0.5"
              value={rateLimit}
              onChange={e => setRateLimit(parseFloat(e.target.value))}
              disabled={isRunning}
            />
          </div>

          <div style={{ marginBottom: 10 }}>
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              marginBottom: 4,
              fontFamily: 'var(--font-mono)',
              fontSize: 10,
              color: '#8B949E',
            }}>
              <span>MAX DEPTH</span>
              <span style={{ color: '#FFB300' }}>{maxDepth}</span>
            </div>
            <input
              type="range"
              className="styled-range"
              min="1" max="5" step="1"
              value={maxDepth}
              onChange={e => setMaxDepth(parseInt(e.target.value))}
              disabled={isRunning}
            />
          </div>

          <div style={{ marginBottom: 10 }}>
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              marginBottom: 4,
              fontFamily: 'var(--font-mono)',
              fontSize: 10,
              color: '#8B949E',
            }}>
              <span>MAX ITERATIONS</span>
              <span style={{ color: '#FFB300' }}>{maxIter}</span>
            </div>
            <input
              type="range"
              className="styled-range"
              min="1" max="20" step="1"
              value={maxIter}
              onChange={e => setMaxIter(parseInt(e.target.value))}
              disabled={isRunning}
            />
          </div>

          <div style={{ marginBottom: 10 }}>
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              marginBottom: 4,
              fontFamily: 'var(--font-mono)',
              fontSize: 10,
              color: '#8B949E',
            }}>
              <span>TIME BUDGET (sec)</span>
              <span style={{ color: '#FFB300' }}>{timeBudget}s</span>
            </div>
            <input
              type="range"
              className="styled-range"
              min="60" max="3600" step="60"
              value={timeBudget}
              onChange={e => setTimeBudget(parseInt(e.target.value))}
              disabled={isRunning}
            />
          </div>

          <div className="toggle-row" style={{ marginBottom: 6 }}>
            <span className="toggle-label" style={{
              color: passiveOnly ? '#00FF41' : '#484F58',
              fontSize: 10,
            }}>PASSIVE ONLY</span>
            <label className="toggle">
              <input
                type="checkbox"
                checked={passiveOnly}
                onChange={e => {
                  setPassiveOnly(e.target.checked)
                  if (e.target.checked) setActiveRecon(false)
                }}
                disabled={isRunning}
              />
              <span className="toggle-slider" />
            </label>
          </div>

          <div style={{ marginBottom: 6, fontFamily: 'var(--font-mono)', fontSize: 10, color: '#8B949E' }}>
            ALLOWED SOURCES (comma-sep, empty = auto)
          </div>
          <input
            className="mono-input"
            style={{ marginBottom: 8, fontSize: 9 }}
            type="text"
            placeholder="dns,whois,crt_sh,subfinder..."
            value={allowedSources}
            onChange={e => setAllowedSources(e.target.value)}
            disabled={isRunning}
          />

          <div style={{ marginBottom: 4, fontFamily: 'var(--font-mono)', fontSize: 10, color: '#8B949E' }}>
            OUT-OF-SCOPE IPs / DOMAINS
          </div>
          <textarea
            className="mono-input"
            style={{ height: 64, resize: 'none', lineHeight: 1.5 }}
            placeholder="192.168.1.0/24&#10;internal.example.com"
            value={outOfScope}
            onChange={e => setOutOfScope(e.target.value)}
            disabled={isRunning}
          />
        </div>

        {/* ── Status indicator ───────────────────────────────── */}
        {scanStatus !== 'idle' && (
          <div style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 10,
            padding: '6px 8px',
            background: 'var(--bg-1)',
            border: `1px solid ${
              scanStatus === 'running' ? '#FFB300'
              : scanStatus === 'complete' ? '#00FF41'
              : scanStatus === 'error' ? '#FF3333'
              : '#30363D'
            }`,
            color: scanStatus === 'running' ? '#FFB300'
              : scanStatus === 'complete' ? '#00FF41'
              : scanStatus === 'error' ? '#FF3333'
              : '#8B949E',
          }}>
            STATUS: {scanStatus.toUpperCase()}
          </div>
        )}
      </form>
    </div>
  )
}
