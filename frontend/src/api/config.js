// frontend/src/api/config.js
// Every UI toggle MUST map to the correct field in EngagementSpec

const TOGGLE_BACKEND_MAP = {
  // UI toggle name   → backend field in engagement_spec
  activeRecon:        'active_recon_enabled',
  passiveOnly:        'passive_only',
  secretScanning:     'enable_secret_scanning',
  repoIntel:          'enable_repo_intel',
  docIntel:           'enable_doc_intel',
  endpointCrawl:      'enable_endpoint_crawl',
  karmaV2:            'enable_karma_v2',
  scanProfile:        'profile',          // "quick" | "balanced" | "deep"
  maxDepth:           'max_depth',
  maxLeads:           'max_leads',
  rateLimitSeconds:   'rate_limit_seconds',
  timeBudget:         'time_budget_seconds',
  allowedSources:     'allowed_sources',
}

/**
 * Build an engagement_spec object from the UI state.
 * @param {Object} uiState
 * @returns {Object} engagement_spec for POST /api/scan/start
 */
export function buildEngagementSpec(uiState) {
  const spec = {}
  for (const [uiKey, backendKey] of Object.entries(TOGGLE_BACKEND_MAP)) {
    if (uiState[uiKey] !== undefined) {
      spec[backendKey] = uiState[uiKey]
    }
  }
  return spec
}

/** Preset scan profiles */
export const SCAN_PROFILES = {
  quick: {
    label: '⚡ Quick',
    description: 'Passive only, < 5 minutes',
    config: {
      active_recon_enabled: false,
      max_iterations: 5,
      max_leads: 20,
      profile: 'quick',
    },
  },
  balanced: {
    label: '⚖️ Balanced',
    description: 'Passive + light active, ~15 minutes',
    config: {
      active_recon_enabled: true,
      max_iterations: 10,
      max_leads: 50,
      profile: 'balanced',
    },
  },
  deep: {
    label: '🔬 Deep',
    description: 'Full collectors + deep web surface, 30+ minutes',
    config: {
      active_recon_enabled: true,
      max_iterations: 20,
      max_leads: 500,
      enable_endpoint_crawl: true,
      enable_secret_scanning: true,
      enable_repo_intel: true,
      enable_doc_intel: true,
      enable_karma_v2: true,
      profile: 'deep',
    },
  },
}

export const API_BASE = (
  import.meta.env.VITE_API_BASE ||
  `${window.location.protocol}//${window.location.hostname}:8000`
).replace(/\/+$/, '')

export const WS_BASE = (
  import.meta.env.VITE_WS_BASE || API_BASE.replace(/^http/, 'ws')
).replace(/\/+$/, '')
