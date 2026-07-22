import Head from 'next/head'
import Link from 'next/link'
import { useRouter } from 'next/router'
import { useEffect, useMemo, useRef, useState } from 'react'
import useSWR from 'swr'
import {
  cves,
  stack,
  stats,
  type CveMatch,
  type CveSortBy,
  type PaginatedCveMatches,
  type StackItem,
  type Stats,
  type TopProductItem,
} from '@/lib/api'
import { useUser } from '@/lib/auth'
import { Layout } from '@/components/Layout'
import { CveCard } from '@/components/CveCard'
import { CveFilters } from '@/components/CveFilters'
import { StatsHeader } from '@/components/StatsHeader'

const PAGE_SIZE = 15

const defaultFilters: {
  severity: string
  kev_only: boolean
  unseen_only: boolean
  product: string
  sort_by: CveSortBy
} = {
  severity: '',
  kev_only: false,
  unseen_only: false,
  product: '',
  sort_by: 'priority',
}

function recalculateTotalPages(totalItems: number, perPage: number) {
  return totalItems > 0 ? Math.ceil(totalItems / perPage) : 0
}

// ── Analytics helpers ─────────────────────────────────────────────────────────

function computeSeverityDistribution(statsData: Stats | undefined) {
  if (!statsData || statsData.severity_distribution.length === 0) return []
  const total = statsData.severity_distribution.reduce((s, d) => s + d.count, 0)
  return statsData.severity_distribution.map(d => ({
    sev: d.severity,
    count: d.count,
    pct: total > 0 ? (d.count / total) * 100 : 0,
  }))
}

function useAttackSurfaceScore(statsData: Stats | undefined) {
  return useMemo(() => {
    if (!statsData) return 0
    const { total_cves, critical_count, kev_count } = statsData
    if (total_cves === 0) return 0
    // Weighted risk formula
    const raw = (critical_count * 3 + kev_count * 2 + (total_cves - critical_count) * 0.5)
    const max = total_cves * 3
    return Math.min(Math.round((raw / max) * 100), 100)
  }, [statsData])
}

// ── Severity color map ────────────────────────────────────────────────────────

const SEV_CSS: Record<string, { bar: string; text: string; bg: string }> = {
  Critical: { bar: 'bg-[var(--crit)]', text: 'text-[var(--crit)]', bg: 'bg-[var(--crit-bg)]' },
  High:     { bar: 'bg-[var(--high)]', text: 'text-[var(--high)]', bg: 'bg-[var(--high-bg)]' },
  Medium:   { bar: 'bg-[var(--med)]',  text: 'text-[var(--med)]',  bg: 'bg-[var(--med-bg)]' },
  Low:      { bar: 'bg-[var(--low)]',  text: 'text-[var(--low)]',  bg: 'bg-[var(--low-bg)]' },
  Unknown:  { bar: 'bg-wire-2',         text: 'text-ink-2',          bg: 'bg-wire-0' },
}

// ── Sub-components ────────────────────────────────────────────────────────────

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-2 mb-3">
      <span className="w-1 h-4 bg-acid rounded-full shrink-0" />
      <p className="text-[11px] font-bold tracking-widest uppercase text-ink-2 font-mono">{children}</p>
    </div>
  )
}

function SidebarCard({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={`rounded-lg border border-wire-1 bg-surface-1 p-4 ${className}`}>
      {children}
    </div>
  )
}

function SeverityDistribution({ statsData }: { statsData?: Stats }) {
  const dist = computeSeverityDistribution(statsData)
  const maxPct = Math.max(...dist.map(d => d.pct), 1)
  const totalCves = statsData?.total_cves ?? 0

  if (totalCves === 0) {
    return (
      <SidebarCard>
        <SectionLabel>Severity Breakdown</SectionLabel>
        <p className="text-[12px] text-ink-2 font-mono">No data yet</p>
      </SidebarCard>
    )
  }

  return (
    <SidebarCard>
      <SectionLabel>Severity Breakdown</SectionLabel>
      <div className="space-y-2">
        {dist.map(({ sev, count, pct }) => {
          const c = SEV_CSS[sev] ?? SEV_CSS.Unknown
          return (
            <div key={sev}>
              <div className="flex items-center justify-between mb-0.5">
                <span className={`text-[11px] font-mono font-semibold ${c.text}`}>{sev}</span>
                <span className="text-[11px] font-mono text-ink-2 tabular">{count}</span>
              </div>
              <div className="h-1.5 rounded-full bg-surface-3 overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all duration-700 ease-out ${c.bar}`}
                  style={{ width: `${(pct / maxPct) * 100}%`, opacity: 0.85 }}
                />
              </div>
            </div>
          )
        })}
      </div>
      <p className="text-[10px] text-ink-3 font-mono mt-3 pt-2 border-t border-wire-0">
        {totalCves} total CVEs
      </p>
    </SidebarCard>
  )
}

function AttackSurfaceMeter({ score, statsData }: { score: number; statsData?: Stats }) {
  const color =
    score >= 70 ? 'var(--crit)' :
    score >= 45 ? 'var(--high)' :
    score >= 20 ? 'var(--med)'  :
                  'var(--acid)'

  const label =
    score >= 70 ? 'CRITICAL' :
    score >= 45 ? 'ELEVATED' :
    score >= 20 ? 'MODERATE' :
                  'LOW'

  const r = 28
  const circ = 2 * Math.PI * r
  const offset = circ * (1 - score / 100)

  return (
    <SidebarCard>
      <SectionLabel>Attack Surface Score</SectionLabel>
      <div className="flex items-center gap-4">
        <div className="relative w-16 h-16 shrink-0">
          <svg viewBox="0 0 64 64" className="w-16 h-16" style={{ transform: 'rotate(-90deg)' }}>
            <circle cx="32" cy="32" r={r} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="4" />
            <circle
              cx="32" cy="32" r={r}
              fill="none"
              stroke={color}
              strokeWidth="4"
              strokeLinecap="round"
              strokeDasharray={`${circ}`}
              strokeDashoffset={`${offset}`}
              style={{
                transition: 'stroke-dashoffset 1.2s ease-out',
                filter: `drop-shadow(0 0 4px ${color})`,
              }}
            />
          </svg>
          <div className="absolute inset-0 flex items-center justify-center flex-col leading-none">
            <span className="text-[16px] font-bold font-mono tabular" style={{ color }}>{score}</span>
          </div>
        </div>
        <div className="flex-1">
          <p className="text-[12px] font-bold font-mono tracking-widest" style={{ color }}>{label}</p>
          <p className="text-[11px] text-ink-2 mt-1 leading-relaxed">
            Based on critical, exploited, and total CVE exposure in your stack.
          </p>
          {statsData && (
            <div className="flex gap-3 mt-2 text-[10px] font-mono text-ink-3">
              <span>{statsData.critical_count} critical</span>
              <span>{statsData.kev_count} KEV</span>
            </div>
          )}
        </div>
      </div>
    </SidebarCard>
  )
}

function TopExposedProducts({ topProducts }: { topProducts: TopProductItem[] }) {
  if (topProducts.length === 0) {
    return null
  }

  const maxCount = topProducts[0]?.count ?? 1

  return (
    <SidebarCard>
      <SectionLabel>Top Exposed Products</SectionLabel>
      <div className="space-y-2">
        {topProducts.map(({ name, count, crit_count: critCount, kev_count: kevCount }) => (
          <div key={name} className="group">
            <div className="flex items-center justify-between gap-2 mb-0.5">
              <span className="text-[12px] text-ink-0 truncate font-medium" title={name}>{name}</span>
              <div className="flex items-center gap-1.5 shrink-0">
                {critCount > 0 && (
                  <span className="text-[10px] font-mono text-[var(--crit)] bg-[var(--crit-bg)] px-1.5 py-px rounded">
                    {critCount}C
                  </span>
                )}
                {kevCount > 0 && (
                  <span className="text-[10px] font-mono text-[var(--high)] bg-[var(--high-bg)] px-1.5 py-px rounded">
                    {kevCount}K
                  </span>
                )}
                <span className="text-[11px] font-mono text-ink-2 tabular w-4 text-right">{count}</span>
              </div>
            </div>
            <div className="h-1 rounded-full bg-surface-3 overflow-hidden">
              <div
                className="h-full rounded-full bg-acid/60 transition-all duration-700"
                style={{ width: `${(count / maxCount) * 100}%` }}
              />
            </div>
          </div>
        ))}
      </div>
    </SidebarCard>
  )
}

function StackSummary({
  stackItems,
  stackSummary,
}: {
  stackItems: StackItem[]
  stackSummary: {
    totalProducts: number
    totalCategories: number
    topCategories: [string, number][]
    recentProducts: StackItem[]
  }
}) {
  return (
    <SidebarCard>
      <SectionLabel>Stack Coverage</SectionLabel>

      <div className="grid grid-cols-2 gap-2 mb-3">
        <div className="rounded bg-surface-2 border border-wire-1 p-2.5">
          <p className="text-[10px] font-mono tracking-widest uppercase text-ink-3 mb-1">Products</p>
          <p className="text-xl font-bold font-mono text-acid tabular">{stackSummary.totalProducts}</p>
        </div>
        <div className="rounded bg-surface-2 border border-wire-1 p-2.5">
          <p className="text-[10px] font-mono tracking-widest uppercase text-ink-3 mb-1">Categories</p>
          <p className="text-xl font-bold font-mono text-ink-0 tabular">{stackSummary.totalCategories}</p>
        </div>
      </div>

      {stackSummary.topCategories.length > 0 && (
        <div className="mb-3">
          <p className="text-[10px] font-mono tracking-widest uppercase text-ink-3 mb-2">By Category</p>
          <div className="space-y-1">
            {stackSummary.topCategories.map(([cat, count]) => (
              <div key={cat} className="flex items-center justify-between text-[11px]">
                <span className="text-ink-1 font-mono truncate">{cat}</span>
                <span className="text-ink-2 font-mono tabular shrink-0 ml-2">{count}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <Link
        href="/stack"
        className="flex items-center justify-between gap-2 w-full px-3 py-2 rounded bg-surface-2 border border-wire-1 hover:border-acid/30 hover:bg-acid/5 transition-all duration-200 group"
      >
        <span className="text-[12px] font-semibold text-ink-1 group-hover:text-acid transition-colors">
          Manage stack
        </span>
        <svg width="12" height="12" viewBox="0 0 12 12" fill="none" className="text-ink-3 group-hover:text-acid transition-colors shrink-0">
          <path d="M2 6h8M7 3l3 3-3 3" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </Link>
    </SidebarCard>
  )
}

function ThreatBanner({
  statsData,
  score,
}: {
  statsData?: Stats
  score: number
}) {
  if (!statsData || statsData.total_cves === 0) return null

  const color =
    score >= 70 ? 'border-[rgba(255,23,68,0.3)] bg-[rgba(255,23,68,0.04)]' :
    score >= 45 ? 'border-[rgba(255,109,0,0.25)] bg-[rgba(255,109,0,0.04)]' :
                  'border-wire-1 bg-surface-1'

  const textColor =
    score >= 70 ? 'text-[var(--crit)]' :
    score >= 45 ? 'text-[var(--high)]' :
                  'text-acid'

  return (
    <div className={`mb-5 rounded-lg border px-4 py-3 flex items-center justify-between gap-4 ${color}`}>
      <div className="flex items-center gap-3">
        <svg width="16" height="16" viewBox="0 0 16 16" fill="none" className={`shrink-0 ${textColor}`}>
          <path d="M8 1L15 5.5V10.5L8 15L1 10.5V5.5L8 1Z" stroke="currentColor" strokeWidth="1.5" />
          <path d="M8 5v3.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
          <circle cx="8" cy="11" r="0.75" fill="currentColor" />
        </svg>
        <div>
          <p className={`text-[12px] font-bold font-mono tracking-wide ${textColor}`}>
            {statsData.new_since_last_visit > 0
              ? `${statsData.new_since_last_visit} new threat${statsData.new_since_last_visit !== 1 ? 's' : ''} since your last visit`
              : 'Stack monitoring active'}
          </p>
          <p className="text-[11px] text-ink-2 font-mono mt-0.5">
            {statsData.critical_count > 0
              ? `${statsData.critical_count} critical · ${statsData.kev_count} actively exploited · ${statsData.total_cves} total`
              : `${statsData.total_cves} vulnerabilities tracked · ${statsData.kev_count} actively exploited`}
          </p>
        </div>
      </div>
      <div className="hidden sm:flex items-center gap-1.5 shrink-0">
        <span className="w-1.5 h-1.5 rounded-full bg-acid animate-pulse" />
        <span className="text-[10px] font-mono tracking-widest uppercase text-ink-2">Monitoring</span>
      </div>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function DashboardPage() {
  const router = useRouter()
  const { user, isLoading: userLoading } = useUser()
  const [filters, setFilters] = useState(defaultFilters)
  const [page, setPage] = useState(1)
  // CVE id of the most recent dismissal, so it can be undone.
  const [undoDismiss, setUndoDismiss] = useState<string | null>(null)
  const hasRedirectedToOnboarding = useRef(false)
  const hasMarkedDashboardVisit = useRef(false)

  const { data: stackItems, isLoading: stackLoading, error: stackError } = useSWR<StackItem[]>(
    user ? '/api/stack' : null,
    stack.list,
    { revalidateOnFocus: false }
  )

  const { data, isLoading, mutate, error } = useSWR<PaginatedCveMatches>(
    user ? ['cves', filters, page] : null,
    () => cves.list({ ...filters, page, per_page: PAGE_SIZE }),
    { revalidateOnFocus: true, refreshInterval: 60_000 }
  )

  const { data: statsData, isLoading: statsLoading, mutate: mutateStats, error: statsError } = useSWR<Stats>(
    user ? '/api/stats' : null,
    stats.get,
    { revalidateOnFocus: true, refreshInterval: 60_000 }
  )

  // Mark visit
  useEffect(() => {
    if (!user || !statsData || stackLoading || hasMarkedDashboardVisit.current) return
    if (!stackItems || stackItems.length === 0) return
    hasMarkedDashboardVisit.current = true
    void stats.markDashboardVisited().then(() => void mutateStats()).catch(() => {
      hasMarkedDashboardVisit.current = false
    })
  }, [mutateStats, stackItems, stackLoading, statsData, user])

  // Redirect to onboarding if stack is empty
  useEffect(() => {
    if (!user || stackLoading || hasRedirectedToOnboarding.current) return
    if (!stackItems || stackItems.length > 0) return
    hasRedirectedToOnboarding.current = true
    void router.replace('/stack?onboarding=1')
  }, [router, stackItems, stackLoading, user])

  // Fix page out of bounds + auto-advance when current page is emptied by dismissals
  useEffect(() => {
    if (!data) return
    if (data.total_pages > 0 && page > data.total_pages) setPage(data.total_pages)
    if (data.total_pages === 0 && page !== 1) setPage(1)
    // Optimistic dismissals can leave the page empty while more CVEs exist on the server.
    // Revalidate so the next batch is loaded without the user having to refresh.
    if (data.items.length === 0 && data.total_items > 0) {
      void mutate()
    }
  }, [data, mutate, page])

  const stackSummary = useMemo(() => {
    const items = stackItems || []
    const categoryCounts = items.reduce<Record<string, number>>((acc, item) => {
      const category = item.category || 'Uncategorized'
      acc[category] = (acc[category] || 0) + 1
      return acc
    }, {})
    return {
      totalProducts: items.length,
      totalCategories: Object.keys(categoryCounts).length,
      topCategories: Object.entries(categoryCounts)
        .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
        .slice(0, 4) as [string, number][],
      recentProducts: items.slice(0, 5),
    }
  }, [stackItems])

  const attackSurfaceScore = useAttackSurfaceScore(statsData)

  const hasActiveFilters = Boolean(
    filters.severity || filters.kev_only || filters.unseen_only ||
    filters.product || filters.sort_by !== 'priority'
  )

  const updateFilters = (partial: Partial<typeof defaultFilters>) => {
    setPage(1)
    setFilters(current => ({ ...current, ...partial }))
  }

  const resetFilters = () => {
    setPage(1)
    setFilters(defaultFilters)
  }

  const applySeenLocally = (cveId: string, seenAt: string) => {
    mutate(current => {
      if (!current) return current
      const nextItems = current.items.map(m => m.cve_id === cveId ? { ...m, seen_at: seenAt } : m)
      const removed = filters.unseen_only && nextItems.some(m => m.cve_id === cveId)
      const visibleItems = removed ? nextItems.filter(m => m.cve_id !== cveId) : nextItems
      const totalItems = removed ? Math.max(current.total_items - 1, 0) : current.total_items
      return { ...current, items: visibleItems, total_items: totalItems, total_pages: recalculateTotalPages(totalItems, current.per_page) }
    }, { revalidate: false })
  }

  const handleMarkSeen = async (cveId: string) => {
    applySeenLocally(cveId, new Date().toISOString())
    try {
      const result = await cves.markSeen(cveId)
      applySeenLocally(cveId, result.seen_at)
    } catch { await mutate() }
    finally { void mutateStats() }
  }

  const handleOpen = (cveId: string) => {
    const existing = data?.items.find(m => m.cve_id === cveId)
    if (!existing || existing.seen_at) return
    applySeenLocally(cveId, new Date().toISOString())
    void cves.markSeen(cveId)
      .then(result => { applySeenLocally(cveId, result.seen_at); void mutateStats() })
      .catch(() => void mutate())
  }

  const handleDismiss = (cveId: string) => {
    // Optimistic: remove from local cache immediately
    mutate(current => {
      if (!current) return current
      const exists = current.items.some(m => m.cve_id === cveId)
      const totalItems = exists ? Math.max(current.total_items - 1, 0) : current.total_items
      return { ...current, items: current.items.filter(m => m.cve_id !== cveId), total_items: totalItems, total_pages: recalculateTotalPages(totalItems, current.per_page) }
    }, { revalidate: false })
    // Fire API + refresh stats; on failure, revalidate to restore correct state
    cves.dismiss(cveId)
      .then(() => {
        void mutateStats()
        // Dismissing hides a vulnerability from the only view that surfaces it,
        // so always offer a way back from a misclick.
        setUndoDismiss(cveId)
      })
      .catch(() => { void mutate(); void mutateStats() })
  }

  const handleUndoDismiss = (cveId: string) => {
    setUndoDismiss(null)
    cves.restore(cveId)
      .then(() => { void mutate(); void mutateStats() })
      .catch(() => { void mutate(); void mutateStats() })
  }

  // ── Loading skeleton ────────────────────────────────────────────────────────
  if (userLoading || stackLoading) {
    return (
      <Layout>
        <Head><title>Dashboard — CVE Radar</title></Head>
        <div className="space-y-4 animate-pulse">
          <div className="h-5 w-48 rounded bg-surface-2" />
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="h-[88px] rounded-lg border border-wire-1 bg-surface-1" />
            ))}
          </div>
          <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_300px]">
            <div className="space-y-3">
              {[...Array(6)].map((_, i) => (
                <div key={i} className="h-[88px] rounded-lg border border-wire-1 bg-surface-1" />
              ))}
            </div>
            <div className="space-y-3">
              <div className="h-40 rounded-lg border border-wire-1 bg-surface-1" />
              <div className="h-48 rounded-lg border border-wire-1 bg-surface-1" />
            </div>
          </div>
        </div>
      </Layout>
    )
  }

  if (stackItems && stackItems.length === 0) return null

  const currentItems = data?.items || []
  const showingFrom = data && data.total_items > 0 ? (data.page - 1) * data.per_page + 1 : 0
  const showingTo   = data ? (data.page - 1) * data.per_page + currentItems.length : 0

  return (
    <Layout>
      <Head><title>Dashboard — CVE Radar</title></Head>

      {/* Page header */}
      <div className="mb-5 flex items-center justify-between gap-4 flex-wrap">
        <div>
          <div className="flex items-center gap-2 mb-0.5">
            <h1 className="text-xl font-bold text-ink-0 tracking-wide">Threat Intelligence</h1>
            <span className="text-[11px] font-mono text-ink-3 border border-wire-1 rounded px-1.5 py-px">
              {new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}
            </span>
          </div>
          <p className="text-[13px] text-ink-2">
            Vulnerabilities affecting your registered stack, ranked by exploitation priority.
          </p>
        </div>

        {/* Quick triage link */}
        {data && data.total_items > 0 && (
          <button
            type="button"
            onClick={() => updateFilters({ unseen_only: true, sort_by: 'priority' })}
            className="hidden sm:inline-flex items-center gap-2 px-3 py-2 rounded border border-acid/30 bg-acid/8 text-acid text-[12px] font-semibold font-mono hover:bg-acid/15 transition-all duration-200"
          >
            <svg width="13" height="13" viewBox="0 0 13 13" fill="none">
              <path d="M1 2.5h11M3 6.5h7M5 10.5h3" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
            </svg>
            Triage unread
          </button>
        )}
      </div>

      {/* Undo a dismissal — dismissing removes the CVE from the only view that
          surfaces it, so a misclick needs a way back. */}
      {undoDismiss && (
        <div className="mb-4 flex items-center justify-between gap-3 rounded-lg border border-wire-1 bg-surface-1 px-4 py-2.5">
          <p className="text-[13px] text-ink-2">
            Dismissed <span className="font-mono text-ink-1">{undoDismiss}</span>. It no longer appears on your dashboard.
          </p>
          <div className="flex items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={() => handleUndoDismiss(undoDismiss)}
              className="px-3 py-1.5 rounded border border-acid/30 bg-acid/8 text-acid text-[12px] font-semibold font-mono hover:bg-acid/15 transition-colors"
            >
              Undo
            </button>
            <button
              type="button"
              onClick={() => setUndoDismiss(null)}
              aria-label="Dismiss this notice"
              className="px-2 py-1.5 rounded text-ink-3 hover:text-ink-1 text-[12px] transition-colors"
            >
              ✕
            </button>
          </div>
        </div>
      )}

      {/* Threat banner */}
      <ThreatBanner statsData={statsData} score={attackSurfaceScore} />

      {/* Stats */}
      <StatsHeader data={statsData} isLoading={statsLoading} />

      {/* Main layout — CVE list + sidebar */}
      <div className="grid gap-5 xl:grid-cols-[minmax(0,1fr)_300px]">

        {/* ── CVE list ──────────────────────────────────────────────────────── */}
        <section className="min-w-0">
          <CveFilters filters={filters} onChange={updateFilters} onReset={resetFilters} />

          {/* Error */}
          {error && (
            <div className="mb-4 rounded-lg border border-[rgba(255,23,68,0.3)] bg-[rgba(255,23,68,0.05)] p-4">
              <p className="text-[13px] font-semibold text-[var(--crit)]">Failed to load CVEs</p>
              <p className="mt-1 text-[12px] text-ink-2">{error.message}</p>
              <button
                type="button"
                onClick={() => void mutate()}
                className="mt-3 px-3 py-1.5 rounded border border-[rgba(255,23,68,0.3)] text-[12px] text-[var(--crit)] hover:bg-[var(--crit-bg)] transition-colors font-mono"
              >
                Retry
              </button>
            </div>
          )}

          {/* Loading rows */}
          {isLoading ? (
            <div className="space-y-2">
              {[...Array(6)].map((_, i) => (
                <div key={i} className="h-[88px] rounded-lg border border-wire-1 bg-surface-1 animate-pulse" />
              ))}
            </div>
          ) : currentItems.length === 0 ? (
            // Empty state
            <div className="rounded-lg border border-wire-1 bg-surface-1 p-10 text-center">
              <div className="inline-flex items-center justify-center w-12 h-12 rounded-full border border-wire-2 bg-surface-2 mb-4">
                <svg width="20" height="20" viewBox="0 0 20 20" fill="none" className="text-ink-2">
                  <path d="M10 2L18 6V14L10 18L2 14V6L10 2Z" stroke="currentColor" strokeWidth="1.5" />
                  <path d="M10 7v4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
                  <circle cx="10" cy="13.5" r="0.75" fill="currentColor" />
                </svg>
              </div>
              <p className="text-[15px] font-semibold text-ink-0 mb-1.5">
                {hasActiveFilters ? 'No CVEs match these filters' : 'All clear for now'}
              </p>
              <p className="text-[13px] text-ink-2 max-w-sm mx-auto">
                {hasActiveFilters
                  ? 'Try widening your filters or clearing the search to see your full CVE list.'
                  : 'Matching runs continuously. New vulnerabilities will appear here as they\'re detected.'}
              </p>
              <div className="mt-5 flex flex-wrap items-center justify-center gap-2">
                {hasActiveFilters && (
                  <button
                    type="button"
                    onClick={resetFilters}
                    className="px-4 py-2 rounded border border-acid/30 bg-acid/8 text-acid text-[13px] font-semibold hover:bg-acid/15 transition-all font-mono"
                  >
                    Clear filters
                  </button>
                )}
                <Link
                  href="/stack"
                  className="px-4 py-2 rounded border border-wire-2 text-[13px] text-ink-1 hover:border-wire-3 hover:text-ink-0 transition-all font-mono"
                >
                  Review stack
                </Link>
              </div>
            </div>
          ) : (
            <>
              {/* Result count + sort info */}
              <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
                <p className="text-[12px] text-ink-2 font-mono">
                  <span className="text-ink-0">{showingFrom}–{showingTo}</span>
                  <span> of </span>
                  <span className="text-ink-0">{data?.total_items ?? 0}</span>
                  <span> CVEs</span>
                </p>
                <p className="text-[12px] text-ink-2 font-mono">
                  sorted by{' '}
                  <span className="text-acid">
                    {filters.sort_by === 'priority'  && 'priority score'}
                    {filters.sort_by === 'published' && 'publish date'}
                    {filters.sort_by === 'cvss'      && 'CVSS score'}
                    {filters.sort_by === 'product'   && 'product name'}
                  </span>
                </p>
              </div>

              {/* CVE rows */}
              <div className="space-y-2">
                {currentItems.map((match: CveMatch, idx: number) => (
                  <CveCard
                    key={match.cve_id}
                    match={match}
                    onDismiss={handleDismiss}
                    onMarkSeen={handleMarkSeen}
                    onOpen={handleOpen}
                    animationDelay={idx * 30}
                  />
                ))}
              </div>

              {/* Pagination */}
              {data && data.total_pages > 1 && (
                <div className="mt-4 flex items-center justify-between gap-3 rounded-lg border border-wire-1 bg-surface-1 px-4 py-3">
                  <p className="text-[12px] text-ink-2 font-mono">
                    Page <span className="text-ink-0">{data.page}</span> / <span className="text-ink-0">{data.total_pages}</span>
                  </p>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      disabled={data.page <= 1}
                      onClick={() => setPage(p => Math.max(1, p - 1))}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded border border-wire-1 text-[12px] font-mono text-ink-1 hover:border-wire-2 hover:text-ink-0 disabled:opacity-30 disabled:cursor-not-allowed transition-all"
                    >
                      <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
                        <path d="M8 2L4 6l4 4" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
                      </svg>
                      Prev
                    </button>

                    {/* Page number pills */}
                    <div className="hidden sm:flex items-center gap-1">
                      {Array.from({ length: Math.min(data.total_pages, 7) }, (_, i) => {
                        const p = i + 1
                        const active = p === data.page
                        return (
                          <button
                            key={p}
                            type="button"
                            onClick={() => setPage(p)}
                            className={`w-7 h-7 rounded text-[12px] font-mono transition-all
                              ${active
                                ? 'bg-acid/15 border border-acid/40 text-acid'
                                : 'border border-wire-1 text-ink-2 hover:border-wire-2 hover:text-ink-1'
                              }`}
                          >
                            {p}
                          </button>
                        )
                      })}
                      {data.total_pages > 7 && (
                        <span className="text-[12px] text-ink-3 font-mono px-1">…{data.total_pages}</span>
                      )}
                    </div>

                    <button
                      type="button"
                      disabled={data.page >= data.total_pages}
                      onClick={() => setPage(p => p + 1)}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded border border-wire-1 text-[12px] font-mono text-ink-1 hover:border-wire-2 hover:text-ink-0 disabled:opacity-30 disabled:cursor-not-allowed transition-all"
                    >
                      Next
                      <svg width="12" height="12" viewBox="0 0 12 12" fill="none">
                        <path d="M4 2l4 4-4 4" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
                      </svg>
                    </button>
                  </div>
                </div>
              )}
            </>
          )}
        </section>

        {/* ── Analytics sidebar ─────────────────────────────────────────────── */}
        <aside className="space-y-3">

          {/* Attack surface score */}
          <AttackSurfaceMeter score={attackSurfaceScore} statsData={statsData} />

          {/* Severity breakdown */}
          <SeverityDistribution statsData={statsData} />

          {/* Top exposed products */}
          {(statsData?.top_products?.length ?? 0) > 0 && (
            <TopExposedProducts topProducts={statsData?.top_products ?? []} />
          )}

          {/* Stack summary */}
          {stackItems && (
            <StackSummary stackItems={stackItems} stackSummary={stackSummary} />
          )}

          {/* Quick links */}
          <SidebarCard>
            <SectionLabel>Quick Actions</SectionLabel>
            <div className="space-y-1.5">
              {[
                { href: '/stack', label: 'Edit my stack', icon: '⬡', desc: 'Add or remove products' },
                { href: '/settings', label: 'Alert settings', icon: '◈', desc: 'Email digest & instant alerts' },
                {
                  href: `/dashboard`,
                  label: 'KEV threats only',
                  icon: '◉',
                  desc: 'Show actively exploited',
                  onClick: () => updateFilters({ kev_only: true }),
                },
              ].map(({ href, label, icon, desc, onClick }) => (
                <Link
                  key={label}
                  href={href}
                  onClick={onClick}
                  className="flex items-center gap-3 px-3 py-2.5 rounded border border-wire-1 bg-surface-2 hover:border-acid/25 hover:bg-acid/5 transition-all duration-200 group"
                >
                  <span className="text-[14px] text-ink-2 group-hover:text-acid transition-colors font-mono w-5 text-center shrink-0">
                    {icon}
                  </span>
                  <div className="min-w-0 flex-1">
                    <p className="text-[12px] font-semibold text-ink-1 group-hover:text-acid transition-colors leading-none mb-0.5">
                      {label}
                    </p>
                    <p className="text-[10px] text-ink-3 leading-none">{desc}</p>
                  </div>
                  <svg width="10" height="10" viewBox="0 0 10 10" fill="none" className="text-ink-3 group-hover:text-acid transition-colors shrink-0">
                    <path d="M2 5h6M5.5 2l3 3-3 3" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                </Link>
              ))}
            </div>
          </SidebarCard>

          {/* Data freshness */}
          {!stackError && !statsError && (
            <div className="flex items-center gap-2 px-3 py-2 rounded border border-wire-0 bg-surface-0">
              <span className="w-1.5 h-1.5 rounded-full bg-acid shrink-0" />
              <p className="text-[10px] text-ink-3 font-mono">
                NVD sync · KEV sync · EPSS sync running hourly
              </p>
            </div>
          )}
          {(stackError || statsError) && (
            <div className="flex items-center gap-2 px-3 py-2 rounded border border-[rgba(255,214,0,0.2)] bg-[rgba(255,214,0,0.04)]">
              <span className="w-1.5 h-1.5 rounded-full bg-med shrink-0" />
              <p className="text-[10px] text-ink-2 font-mono">
                Some sidebar data could not load
              </p>
            </div>
          )}
        </aside>
      </div>
    </Layout>
  )
}
