import Link from 'next/link'
import { type CveMatch } from '@/lib/api'
import { SeverityBadge } from './SeverityBadge'
import { KevBadge } from './KevBadge'

interface Props {
  match: CveMatch
  onDismiss?: (id: string) => void
  onMarkSeen?: (id: string) => void
  onOpen?: (id: string) => void
  animationDelay?: number
}

function PriorityRing({ score }: { score: number }) {
  const r = 17
  const circ = 2 * Math.PI * r
  const clamped = Math.min(Math.max(score, 0), 100)
  const offset = circ * (1 - clamped / 100)

  const color =
    clamped >= 75 ? 'var(--crit)' :
    clamped >= 50 ? 'var(--high)' :
    clamped >= 25 ? 'var(--med)'  :
                    'var(--low)'

  return (
    <div className="relative w-11 h-11 shrink-0" title={`Priority: ${Math.round(score)}/100`}>
      <svg viewBox="0 0 40 40" className="w-11 h-11" style={{ transform: 'rotate(-90deg)' }}>
        {/* Track */}
        <circle
          cx="20" cy="20" r={r}
          fill="none"
          stroke="rgba(255,255,255,0.05)"
          strokeWidth="2.5"
        />
        {/* Progress */}
        <circle
          cx="20" cy="20" r={r}
          fill="none"
          stroke={color}
          strokeWidth="2.5"
          strokeLinecap="round"
          strokeDasharray={`${circ}`}
          strokeDashoffset={`${offset}`}
          style={{
            transition: 'stroke-dashoffset 1s ease-out',
            filter: `drop-shadow(0 0 3px ${color})`,
          }}
        />
      </svg>
      <div className="absolute inset-0 flex items-center justify-center flex-col leading-none">
        <span className="text-[11px] font-bold font-mono tabular" style={{ color }}>
          {Math.round(score)}
        </span>
      </div>
    </div>
  )
}

const sevBarClass: Record<string, string> = {
  Critical: 'sev-bar-crit',
  High:     'sev-bar-high',
  Medium:   'sev-bar-med',
  Low:      'sev-bar-low',
  None:     'sev-bar-none',
  Unknown:  'sev-bar-none',
}

export function CveCard({ match, onDismiss, onMarkSeen, onOpen, animationDelay = 0 }: Props) {
  const isNew = !match.seen_at
  const publishedDate = match.published_at
    ? new Date(match.published_at).toLocaleDateString('en-US', {
        month: 'short', day: 'numeric', year: 'numeric',
      })
    : null
  const extraCount = Math.max(match.product_count - 1, 0)
  const productLabel = extraCount > 0
    ? `${match.primary_product_name} +${extraCount}`
    : match.primary_product_name

  const barClass = sevBarClass[match.severity] ?? 'sev-bar-none'

  return (
    <div
      className={`group relative rounded-lg border transition-all duration-200 animate-fade-in-up overflow-hidden
        ${isNew
          ? 'border-wire-2 hover:border-wire-3'
          : 'border-wire-1 hover:border-wire-2'
        }
        ${barClass}
        bg-surface-1 hover:bg-surface-2`
      }
      style={{ animationDelay: `${animationDelay}ms` }}
    >
      {/* New indicator pulse */}
      {isNew && (
        <span className="absolute top-3 right-3 flex h-2 w-2">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-acid opacity-50" />
          <span className="relative inline-flex rounded-full h-2 w-2 bg-acid/80" />
        </span>
      )}

      <div className="flex items-start gap-4 p-4">
        {/* Priority ring */}
        <div className="mt-0.5">
          <PriorityRing score={match.priority_score} />
        </div>

        {/* Main content */}
        <div className="flex-1 min-w-0">
          {/* Header row */}
          <div className="flex items-center flex-wrap gap-2 mb-1.5">
            <Link
              href={`/cve/${match.cve_id}`}
              onClick={() => onOpen?.(match.cve_id)}
              className="font-mono font-bold text-[14px] text-acid hover:text-acid/80 transition-colors tracking-wide"
            >
              {match.cve_id}
            </Link>
            <SeverityBadge severity={match.severity} />
            {match.kev_flag && <KevBadge />}
            {isNew && (
              <span className="inline-flex items-center gap-1 text-[10px] font-mono font-bold tracking-widest uppercase px-2 py-0.5 rounded bg-acid/10 text-acid border border-acid/25">
                NEW
              </span>
            )}
          </div>

          {/* Description */}
          {match.description && (
            <p className="text-[13px] text-ink-1 line-clamp-2 mb-2 leading-relaxed">
              {match.description}
            </p>
          )}

          {/* Meta row */}
          <div className="flex items-center flex-wrap gap-x-4 gap-y-1 text-[11px] font-mono text-ink-2">
            {/* Product */}
            <span
              className="inline-flex items-center gap-1 text-ink-1"
              title={match.product_names.join(', ')}
            >
              <svg width="11" height="11" viewBox="0 0 11 11" fill="none">
                <rect x="1" y="1" width="9" height="9" rx="1.5" stroke="currentColor" strokeWidth="1.2" />
                <path d="M4 5.5h3M5.5 4v3" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" />
              </svg>
              {productLabel}
            </span>

            {match.cvss_score != null && (
              <span>CVSS <span className="text-ink-0">{match.cvss_score.toFixed(1)}</span></span>
            )}
            {match.epss_score != null && (
              <span>EPSS <span className="text-ink-0">{(match.epss_score * 100).toFixed(1)}%</span></span>
            )}
            {publishedDate && <span>{publishedDate}</span>}
          </div>
        </div>

        {/* Actions — visible on hover */}
        <div className="flex flex-col items-end gap-2 shrink-0 pt-0.5">
          {isNew && onMarkSeen && (
            <button
              onClick={() => onMarkSeen(match.cve_id)}
              className="text-[11px] font-mono font-semibold text-acid/70 hover:text-acid transition-colors border border-acid/20 hover:border-acid/40 rounded px-2 py-0.5 whitespace-nowrap"
            >
              Mark seen
            </button>
          )}
          {onDismiss && (
            <button
              onClick={() => onDismiss(match.cve_id)}
              className="text-[11px] font-mono text-ink-3 hover:text-crit/80 transition-all opacity-0 group-hover:opacity-100 border border-transparent hover:border-crit/20 rounded px-2 py-0.5 whitespace-nowrap"
            >
              Dismiss
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
