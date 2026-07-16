import { useEffect, useRef, useState } from 'react'
import { type Stats } from '@/lib/api'

function useCountUp(target: number, duration = 900) {
  const [count, setCount] = useState(0)
  const rafRef = useRef<number | null>(null)

  useEffect(() => {
    if (target === 0) { setCount(0); return }
    const startTime = performance.now()
    const step = (now: number) => {
      const elapsed = now - startTime
      const progress = Math.min(elapsed / duration, 1)
      // Ease-out cubic
      const eased = 1 - Math.pow(1 - progress, 3)
      setCount(Math.round(eased * target))
      if (progress < 1) {
        rafRef.current = requestAnimationFrame(step)
      }
    }
    rafRef.current = requestAnimationFrame(step)
    return () => { if (rafRef.current) cancelAnimationFrame(rafRef.current) }
  }, [target, duration])

  return count
}

function StatCard({
  label,
  value,
  sublabel,
  accentColor,
  delay = 0,
  icon,
}: {
  label: string
  value: number
  sublabel?: string
  accentColor: 'acid' | 'crit' | 'high' | 'low'
  delay?: number
  icon: React.ReactNode
}) {
  const count = useCountUp(value)

  const colors = {
    acid: {
      border:  'border-[var(--acid)]/20',
      glow:    'hover:shadow-acid-sm',
      number:  'text-acid',
      iconBg:  'bg-[var(--acid-bg)]',
      iconCol: 'text-acid',
      bar:     'bg-acid',
    },
    crit: {
      border:  'border-[var(--crit)]/25',
      glow:    'hover:shadow-crit-sm',
      number:  'text-[var(--crit)]',
      iconBg:  'bg-[var(--crit-bg)]',
      iconCol: 'text-[var(--crit)]',
      bar:     'bg-[var(--crit)]',
    },
    high: {
      border:  'border-[var(--high)]/20',
      glow:    'hover:shadow-high-sm',
      number:  'text-[var(--high)]',
      iconBg:  'bg-[var(--high-bg)]',
      iconCol: 'text-[var(--high)]',
      bar:     'bg-[var(--high)]',
    },
    low: {
      border:  'border-wire-2',
      glow:    '',
      number:  'text-ink-0',
      iconBg:  'bg-surface-2',
      iconCol: 'text-ink-1',
      bar:     'bg-ink-2',
    },
  }

  const c = colors[accentColor]

  return (
    <div
      className={`dot-grid relative rounded-lg border bg-surface-1 p-4 transition-all duration-300 animate-count-up overflow-hidden ${c.border} ${c.glow}`}
      style={{ animationDelay: `${delay}ms` }}
    >
      {/* Top accent bar */}
      <div className={`absolute top-0 left-4 right-4 h-px ${c.bar} opacity-50`} />

      <div className="flex items-start justify-between gap-2">
        <div className="flex-1 min-w-0">
          <p className="text-[11px] font-semibold tracking-widest uppercase text-ink-2 mb-2 font-mono">
            {label}
          </p>
          <p className={`text-3xl font-bold tabular font-mono leading-none ${c.number}`}>
            {count}
          </p>
          {sublabel && (
            <p className="text-[11px] text-ink-2 mt-1.5 font-mono">{sublabel}</p>
          )}
        </div>
        <div className={`flex items-center justify-center w-9 h-9 rounded ${c.iconBg} ${c.iconCol} shrink-0`}>
          {icon}
        </div>
      </div>
    </div>
  )
}

export function StatsHeader({ data, isLoading = false }: { data?: Stats; isLoading?: boolean }) {
  if (isLoading || !data) {
    return (
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-6">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="h-[88px] rounded-lg border border-wire-1 bg-surface-1 animate-pulse" />
        ))}
      </div>
    )
  }

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-6">
      <StatCard
        label="Total CVEs"
        value={data.total_cves}
        sublabel="in your stack"
        accentColor="acid"
        delay={0}
        icon={
          <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
            <path d="M9 1L16 5V13L9 17L2 13V5L9 1Z" stroke="currentColor" strokeWidth="1.5" fill="none" />
            <path d="M9 5V9L12 11" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
          </svg>
        }
      />
      <StatCard
        label="Critical"
        value={data.critical_count}
        sublabel="CVSS ≥ 9.0"
        accentColor={data.critical_count > 0 ? 'crit' : 'low'}
        delay={80}
        icon={
          <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
            <path d="M9 2L16.5 15H1.5L9 2Z" stroke="currentColor" strokeWidth="1.5" fill="none" strokeLinejoin="round" />
            <line x1="9" y1="7" x2="9" y2="11" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
            <circle cx="9" cy="13" r="0.75" fill="currentColor" />
          </svg>
        }
      />
      <StatCard
        label="Exploited"
        value={data.kev_count}
        sublabel="CISA KEV"
        accentColor={data.kev_count > 0 ? 'high' : 'low'}
        delay={160}
        icon={
          <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
            <circle cx="9" cy="9" r="7" stroke="currentColor" strokeWidth="1.5" />
            <path d="M6 9L8 11L12 7" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        }
      />
      <StatCard
        label="New Alerts"
        value={data.new_since_last_visit}
        sublabel="since last visit"
        accentColor={data.new_since_last_visit > 0 ? 'acid' : 'low'}
        delay={240}
        icon={
          <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
            <path d="M9 2C5.7 2 3 4.7 3 8v5l-1 1h14l-1-1V8c0-3.3-2.7-6-6-6Z" stroke="currentColor" strokeWidth="1.5" fill="none" strokeLinejoin="round" />
            <path d="M7 14a2 2 0 0 0 4 0" stroke="currentColor" strokeWidth="1.5" />
          </svg>
        }
      />
    </div>
  )
}
