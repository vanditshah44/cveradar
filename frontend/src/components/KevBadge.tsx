export function KevBadge() {
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-bold tracking-wider uppercase font-mono bg-[var(--crit-bg)] text-[var(--crit)] border border-[rgba(255,23,68,0.4)] shadow-crit-sm">
      <span className="relative flex h-1.5 w-1.5 shrink-0">
        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[var(--crit)] opacity-60" />
        <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-[var(--crit)]" />
      </span>
      KEV
    </span>
  )
}
