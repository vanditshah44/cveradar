type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'None' | 'Unknown'

const config: Record<Severity, { bg: string; text: string; border: string; dot: string }> = {
  Critical: {
    bg:     'bg-[var(--crit-bg)]',
    text:   'text-[var(--crit)]',
    border: 'border-[rgba(255,23,68,0.3)]',
    dot:    'bg-[var(--crit)]',
  },
  High: {
    bg:     'bg-[var(--high-bg)]',
    text:   'text-[var(--high)]',
    border: 'border-[rgba(255,109,0,0.3)]',
    dot:    'bg-[var(--high)]',
  },
  Medium: {
    bg:     'bg-[var(--med-bg)]',
    text:   'text-[var(--med)]',
    border: 'border-[rgba(255,214,0,0.3)]',
    dot:    'bg-[var(--med)]',
  },
  Low: {
    bg:     'bg-[var(--low-bg)]',
    text:   'text-[var(--low)]',
    border: 'border-[rgba(0,176,255,0.3)]',
    dot:    'bg-[var(--low)]',
  },
  None: {
    bg:     'bg-wire-0',
    text:   'text-ink-2',
    border: 'border-wire-2',
    dot:    'bg-ink-3',
  },
  Unknown: {
    bg:     'bg-wire-0',
    text:   'text-ink-2',
    border: 'border-wire-2',
    dot:    'bg-ink-3',
  },
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  const c = config[severity] ?? config.Unknown
  return (
    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-bold tracking-wider uppercase border font-mono ${c.bg} ${c.text} ${c.border}`}>
      <span className={`w-1 h-1 rounded-full ${c.dot}`} />
      {severity}
    </span>
  )
}
