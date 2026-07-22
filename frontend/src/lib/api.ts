/**
 * api.ts — Typed API client.
 *
 * All API calls go through these functions. They use fetch() with
 * credentials: 'include' so the session cookie is sent automatically.
 *
 * The Next.js rewrite in next.config.js proxies /api/* to FastAPI,
 * so we never hardcode the backend URL in frontend code.
 */

export interface CveMatch {
  cve_id: string
  description: string | null
  cvss_vector: string | null
  cvss_score: number | null
  epss_score: number | null
  kev_flag: boolean
  kev_date_added: string | null
  published_at: string | null
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Unknown' | 'None'
  priority_score: number
  matched_at: string
  seen_at: string | null
  dismissed: boolean
  primary_product_name: string
  product_names: string[]
  product_count: number
}

export interface CveAffectedProduct {
  vendor: string
  product: string
  version_start: string | null
  version_start_including: boolean
  version_end: string | null
  version_end_including: boolean
  single_version: string | null
  condition_group: string | null
  config_path: string | null
  is_vulnerable_match: boolean
  match_context: Record<string, unknown> | null
  range_display: string
}

export interface CveReference {
  url: string | null
  source: string | null
  tags: string[] | null
}

export interface MatchedStackItem {
  id: string
  product_name: string
  vendor: string
  cpe_product: string
  version: string
  category: string | null
  matched_at: string
  seen_at: string | null
}

export interface CveDetail {
  cve_id: string
  description: string | null
  cvss_vector: string | null
  cvss_score: number | null
  epss_score: number | null
  kev_flag: boolean
  kev_date_added: string | null
  published_at: string | null
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Unknown' | 'None'
  priority_score: number
  matched_at: string
  seen_at: string | null
  dismissed: boolean
  stack_item_id: string
  product_name: string
  references: CveReference[] | null
  useful_reference: CveReference | null
  matched_stack_items: MatchedStackItem[]
  affected_products: CveAffectedProduct[] | null
}

export type CveSortBy = 'priority' | 'published' | 'cvss' | 'product'

export interface PaginatedCveMatches {
  items: CveMatch[]
  page: number
  per_page: number
  total_items: number
  total_pages: number
  sort_by: CveSortBy
}

export interface StackItem {
  id: string
  product_name: string
  vendor: string
  cpe_product: string
  version: string
  cpe_string: string
  category: string | null
  added_at: string
}

export interface StackMutationResult extends StackItem {
  matching_queued: boolean
  matching_message: string | null
}

export interface SeverityDistributionItem {
  severity: string
  count: number
}

export interface TopProductItem {
  name: string
  count: number
  crit_count: number
  kev_count: number
}

export interface Stats {
  total_cves: number
  critical_count: number
  kev_count: number
  new_since_last_visit: number
  severity_distribution: SeverityDistributionItem[]
  top_products: TopProductItem[]
}

export interface User {
  id: string
  email: string
  daily_digest: boolean
  instant_alerts: boolean
}

export interface Product {
  id: string
  display_name: string
  vendor: string
  cpe_product: string
  category: string | null
  popular: boolean
}

async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  let res: Response

  try {
    res = await fetch(path, {
      credentials: 'include',  // send session cookie
      headers: { 'Content-Type': 'application/json' },
      ...options,
    })
  } catch {
    throw new Error('Could not reach CVE Radar. Make sure the API, Redis, and Docker services are running.')
  }

  if (!res.ok) {
    // Database unreachable — fire a global event so the app can overlay a maintenance page.
    if (res.status === 503) {
      if (typeof window !== 'undefined') {
        window.dispatchEvent(new CustomEvent('cveradar:maintenance'))
      }
      throw new Error('maintenance')
    }

    const contentType = res.headers.get('content-type') || ''
    let detail = ''

    if (contentType.includes('application/json')) {
      const error = await res.json().catch(() => null)
      detail = error?.detail || error?.message || ''
    } else {
      detail = (await res.text().catch(() => '')).trim()
    }

    if (!detail) {
      if (res.status === 401) detail = 'Your session expired. Please sign in again.'
      else if (res.status === 404) detail = 'The requested resource could not be found.'
      else if (res.status >= 500) detail = 'CVE Radar hit a server error while processing your request.'
      else detail = `Request failed with status ${res.status}.`
    }

    throw new Error(detail)
  }

  // 204 No Content (e.g. DELETE) — no body to parse
  if (res.status === 204) return undefined as T

  // A 2xx can still arrive with an empty or truncated body if a proxy cuts the
  // response short. res.json() would surface that as a raw DOMException
  // ("Unexpected end of JSON input"), which tells the user nothing — parse it
  // ourselves so the failure is named and the Retry button reads as the fix.
  const raw = await res.text()
  if (!raw.trim()) {
    throw new Error('The server returned an empty response. This is usually temporary — please retry.')
  }
  try {
    return JSON.parse(raw) as T
  } catch {
    throw new Error('The server returned a malformed response. This is usually temporary — please retry.')
  }
}

// ── Auth ──────────────────────────────────────────────────────────────────────

export const auth = {
  requestMagicLink: (email: string) =>
    apiFetch('/api/auth/magic-link', { method: 'POST', body: JSON.stringify({ email }) }),

  me: () => apiFetch<User>('/api/auth/me'),

  logout: () => apiFetch('/api/auth/logout', { method: 'POST' }),
}

// ── Stack ─────────────────────────────────────────────────────────────────────

export const stack = {
  list: () => apiFetch<StackItem[]>('/api/stack'),

  add: (item: Omit<StackItem, 'id' | 'added_at'>) =>
    apiFetch<StackMutationResult>('/api/stack', { method: 'POST', body: JSON.stringify(item) }),

  update: (id: string, version: string, cpe_string: string) =>
    apiFetch<StackMutationResult>(`/api/stack/${id}`, {
      method: 'PUT',
      body: JSON.stringify({ version, cpe_string }),
    }),

  // Convenience: recompute the cpe_string from the existing item's vendor/product + new version
  updateVersion: (item: StackItem, newVersion: string) => {
    const newCpe = item.cpe_string.replace(
      // Replace the version segment (3rd colon-delimited field after "cpe:2.3:a:")
      /^(cpe:2\.3:[^:]+:[^:]+:[^:]+:)(.+)$/,
      `$1${newVersion}:*:*:*:*:*:*:*`,
    )
    return apiFetch<StackMutationResult>(`/api/stack/${item.id}`, {
      method: 'PUT',
      body: JSON.stringify({ version: newVersion, cpe_string: newCpe }),
    })
  },

  remove: (id: string) =>
    apiFetch(`/api/stack/${id}`, { method: 'DELETE' }),
}

// ── CVEs ──────────────────────────────────────────────────────────────────────

export interface CveFilters {
  product?: string
  severity?: string
  kev_only?: boolean
  unseen_only?: boolean
  sort_by?: CveSortBy
  page?: number
  per_page?: number
}

export const cves = {
  list: (filters: CveFilters = {}) => {
    const params = new URLSearchParams()
    if (filters.product) params.set('product', filters.product)
    if (filters.severity) params.set('severity', filters.severity)
    if (filters.kev_only) params.set('kev_only', 'true')
    if (filters.unseen_only) params.set('unseen_only', 'true')
    if (filters.sort_by) params.set('sort_by', filters.sort_by)
    if (filters.page) params.set('page', String(filters.page))
    if (filters.per_page) params.set('per_page', String(filters.per_page))
    return apiFetch<PaginatedCveMatches>(`/api/cves?${params}`)
  },

  get: (id: string) => apiFetch<CveDetail>(`/api/cves/${id}`),

  markSeen: (id: string) => apiFetch<{ ok: boolean; seen_at: string }>(`/api/cves/${id}/seen`, { method: 'POST' }),

  dismiss: (id: string) => apiFetch(`/api/cves/${id}/dismiss`, { method: 'POST' }),

  /** Undo a dismissal — puts the CVE back on the dashboard. */
  restore: (id: string) => apiFetch(`/api/cves/${id}/restore`, { method: 'POST' }),
}

// ── Products ──────────────────────────────────────────────────────────────────

export const products = {
  search: (q: string) => apiFetch<Product[]>(`/api/products/search?q=${encodeURIComponent(q)}`),
  popular: () => apiFetch<Product[]>('/api/products/popular'),
}

// ── Stats ─────────────────────────────────────────────────────────────────────

export const stats = {
  get: () => apiFetch<Stats>('/api/stats'),
  markDashboardVisited: () => apiFetch<{ ok: boolean; last_seen_at: string }>('/api/stats/visit', { method: 'POST' }),
}

// ── Settings ──────────────────────────────────────────────────────────────────

export interface NotificationPrefs {
  daily_digest: boolean
  instant_alerts: boolean
}

export const settings = {
  get: () => apiFetch<NotificationPrefs>('/api/settings'),
  // The type argument matters: without it this resolved to Promise<unknown>,
  // and the settings page could not spread the server response into its cache.
  update: (prefs: NotificationPrefs) =>
    apiFetch<NotificationPrefs>('/api/settings', { method: 'PUT', body: JSON.stringify(prefs) }),
  deleteAccount: () => apiFetch('/api/account', { method: 'DELETE' }),
}
