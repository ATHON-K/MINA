import { SCAN_PROFILES } from '../api/config'

export default function ScanProfileSelector({ selected, onChange }) {
  return (
    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
      {Object.entries(SCAN_PROFILES).map(([key, profile]) => (
        <button
          key={key}
          onClick={() => onChange(key, profile.config)}
          style={{
            background: selected === key ? '#1e40af' : '#1e293b',
            border: `1px solid ${selected === key ? '#3b82f6' : '#334155'}`,
            color: selected === key ? '#e0f2fe' : '#94a3b8',
            borderRadius: 8,
            padding: '8px 16px',
            cursor: 'pointer',
            textAlign: 'left',
            minWidth: 140,
            transition: 'all 0.15s',
          }}
        >
          <div style={{ fontWeight: 700, fontSize: '0.85rem' }}>{profile.label}</div>
          <div style={{ fontSize: '0.7rem', color: selected === key ? '#93c5fd' : '#64748b', marginTop: 2 }}>
            {profile.description}
          </div>
        </button>
      ))}
    </div>
  )
}
