import { type CveSortBy } from '@/lib/api'

interface Filters {
  severity: string
  kev_only: boolean
  unseen_only: boolean
  product: string
  sort_by: CveSortBy
}

interface Props {
  filters: Filters
  onChange: (f: Partial<Filters>) => void
  onReset?: () => void
}

const SEVERITIES = ['', 'critical', 'high', 'medium', 'low'] as const
const SORTS: { value: CveSortBy; label: string }[] = [
  { value: 'priority', label: 'Priority' },
  { value: 'published', label: 'Date' },
  { value: 'cvss', label: 'CVSS' },
  { value: 'product', label: 'Product' },
]

function severityLabel(v: string) {
  if (!v) return 'All'
  return v.charAt(0).toUpperCase() + v.slice(1)
}

export function CveFilters({ filters, onChange, onReset }: Props) {
  const hasActiveFilters = Boolean(
    filters.severity || filters.kev_only || filters.unseen_only ||
    filters.product || filters.sort_by !== 'priority'
  )

  return (
    <div className="mb-4 rounded-lg border border-wire-1 bg-surface-1 overflow-hidden">
      {/* Header bar */}
      <div className="flex items-center justify-between gap-3 px-4 py-2.5 border-b border-wire-0 bg-surface-0">
        <div className="flex items-center gap-2">
          <svg width="14" height="14" viewBox="0 0 14 14" fill="none" className="text-acid shrink-0">
            <path d="M1 3h12M3 7h8M5 11h4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
          </svg>
          <span className="text-[12px] font-semibold tracking-widest uppercase text-ink-2 font-mono">Filter &amp; Sort</span>
        </div>
        {hasActiveFilters && onReset && (
          <button
            type="button"
            onClick={onReset}
            className="inline-flex items-center gap-1 text-[11px] text-ink-2 hover:text-crit transition-colors font-mono"
          >
            <svg width="10" height="10" viewBox="0 0 10 10" fill="none">
              <path d="M2 2l6 6M8 2l-6 6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
            </svg>
            Reset
          </button>
        )}
      </div>

      <div className="px-4 py-3 flex flex-wrap gap-3 items-center">

        {/* Product search */}
        <div className="relative min-w-[180px] flex-1 max-w-xs">
          <svg width="13" height="13" viewBox="0 0 13 13" fill="none"
            className="absolute left-3 top-1/2 -translate-y-1/2 text-ink-3 pointer-events-none">
            <circle cx="5" cy="5" r="4" stroke="currentColor" strokeWidth="1.4" />
            <line x1="8.5" y1="8.5" x2="12" y2="12" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
          </svg>
          <input
            type="text"
            placeholder="Product / vendor / CPE…"
            value={filters.product}
            onChange={e => onChange({ product: e.target.value })}
            className="focus-acid w-full bg-surface-2 border border-wire-1 text-[13px] rounded px-3 py-1.5 pl-8 text-ink-0 placeholder-ink-3 focus:outline-none transition-all duration-200 font-mono"
          />
        </div>

        {/* Severity pills */}
        <div className="flex items-center gap-1 flex-wrap">
          {SEVERITIES.map(sev => {
            const active = filters.severity === sev
            const dotColors: Record<string, string> = {
              critical: 'var(--crit)',
              high: 'var(--high)',
              medium: 'var(--med)',
              low: 'var(--low)',
            }
            const dotColor = sev ? dotColors[sev] : undefined
            return (
              <button
                key={sev || 'all'}
                type="button"
                onClick={() => onChange({ severity: sev })}
                className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-semibold tracking-wide uppercase font-mono transition-all duration-150
                  ${active
                    ? 'bg-acid/15 border border-acid/40 text-acid'
                    : 'bg-surface-2 border border-wire-1 text-ink-2 hover:border-wire-2 hover:text-ink-1'
                  }`}
              >
                {dotColor && (
                  <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: dotColor }} />
                )}
                {severityLabel(sev)}
              </button>
            )
          })}
        </div>

        {/* Sort pills */}
        <div className="flex items-center gap-1">
          <span className="text-[11px] text-ink-3 font-mono mr-0.5 uppercase tracking-wider">Sort</span>
          {SORTS.map(s => {
            const active = filters.sort_by === s.value
            return (
              <button
                key={s.value}
                type="button"
                onClick={() => onChange({ sort_by: s.value })}
                className={`px-2.5 py-1 rounded text-[11px] font-semibold tracking-wide uppercase font-mono transition-all duration-150
                  ${active
                    ? 'bg-acid/15 border border-acid/40 text-acid'
                    : 'bg-surface-2 border border-wire-1 text-ink-2 hover:border-wire-2 hover:text-ink-1'
                  }`}
              >
                {s.label}
              </button>
            )
          })}
        </div>

        {/* Toggle buttons */}
        <div className="flex items-center gap-2">
          <ToggleButton
            label="KEV Only"
            active={filters.kev_only}
            onClick={() => onChange({ kev_only: !filters.kev_only })}
            color="crit"
          />
          <ToggleButton
            label="Unread"
            active={filters.unseen_only}
            onClick={() => onChange({ unseen_only: !filters.unseen_only })}
            color="acid"
          />
        </div>
      </div>

      {/* Active filter chips */}
      {hasActiveFilters && (
        <div className="flex flex-wrap gap-1.5 px-4 pb-3">
          {filters.severity && (
            <span className="filter-chip">
              sev:{filters.severity}
              <button
                onClick={() => onChange({ severity: '' })}
                className="ml-1 hover:text-crit"
              >×</button>
            </span>
          )}
          {filters.kev_only && (
            <span className="filter-chip">
              kev:true
              <button onClick={() => onChange({ kev_only: false })} className="ml-1 hover:text-crit">×</button>
            </span>
          )}
          {filters.unseen_only && (
            <span className="filter-chip">
              seen:false
              <button onClick={() => onChange({ unseen_only: false })} className="ml-1 hover:text-crit">×</button>
            </span>
          )}
          {filters.product && (
            <span className="filter-chip">
              product:{filters.product.length > 16 ? filters.product.slice(0, 16) + '…' : filters.product}
              <button onClick={() => onChange({ product: '' })} className="ml-1 hover:text-crit">×</button>
            </span>
          )}
          {filters.sort_by !== 'priority' && (
            <span className="filter-chip">
              sort:{filters.sort_by}
              <button onClick={() => onChange({ sort_by: 'priority' })} className="ml-1 hover:text-crit">×</button>
            </span>
          )}
        </div>
      )}
    </div>
  )
}

function ToggleButton({
  label,
  active,
  onClick,
  color,
}: {
  label: string
  active: boolean
  onClick: () => void
  color: 'acid' | 'crit'
}) {
  const styles = {
    acid: active
      ? 'bg-acid/15 border-acid/40 text-acid shadow-acid-sm'
      : 'bg-surface-2 border-wire-1 text-ink-2 hover:border-wire-2 hover:text-ink-1',
    crit: active
      ? 'bg-[var(--crit-bg)] border-[rgba(255,23,68,0.35)] text-[var(--crit)] shadow-crit-sm'
      : 'bg-surface-2 border-wire-1 text-ink-2 hover:border-wire-2 hover:text-ink-1',
  }

  return (
    <button
      type="button"
      onClick={onClick}
      className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded border text-[11px] font-semibold tracking-wide uppercase font-mono transition-all duration-150 ${styles[color]}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full transition-all ${active ? (color === 'acid' ? 'bg-acid' : 'bg-[var(--crit)]') : 'bg-ink-3'}`} />
      {label}
    </button>
  )
}
