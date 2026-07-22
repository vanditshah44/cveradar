import Link from 'next/link'
import { useRouter } from 'next/router'
import useSWR, { useSWRConfig } from 'swr'
import { auth, stats } from '@/lib/api'
import { useUser } from '@/lib/auth'

function RadarIcon() {
  return (
    <svg width="28" height="28" viewBox="0 0 28 28" fill="none" aria-hidden="true">
      {/* Outer ring */}
      <circle cx="14" cy="14" r="12" stroke="rgba(0,230,118,0.25)" strokeWidth="1" />
      {/* Middle ring */}
      <circle cx="14" cy="14" r="7" stroke="rgba(0,230,118,0.18)" strokeWidth="1" />
      {/* Inner dot */}
      <circle cx="14" cy="14" r="2" fill="#00e676" />
      {/* Crosshairs */}
      <line x1="14" y1="2" x2="14" y2="5" stroke="rgba(0,230,118,0.35)" strokeWidth="1" />
      <line x1="14" y1="23" x2="14" y2="26" stroke="rgba(0,230,118,0.35)" strokeWidth="1" />
      <line x1="2" y1="14" x2="5" y2="14" stroke="rgba(0,230,118,0.35)" strokeWidth="1" />
      <line x1="23" y1="14" x2="26" y2="14" stroke="rgba(0,230,118,0.35)" strokeWidth="1" />
      {/* Sweep arm */}
      <line
        x1="14" y1="14" x2="14" y2="2"
        stroke="#00e676" strokeWidth="1.5" strokeLinecap="round"
        className="radar-sweep"
        style={{ transformOrigin: '14px 14px' }}
      />
      {/* Sweep gradient arc (simulated with a wide line) */}
      <path
        d="M14 2 A12 12 0 0 1 24.5 19"
        stroke="url(#sweep-grad)" strokeWidth="2" fill="none" strokeLinecap="round"
        className="radar-sweep"
        style={{ transformOrigin: '14px 14px', opacity: 0.4 }}
      />
      <defs>
        <linearGradient id="sweep-grad" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop offset="0%" stopColor="#00e676" stopOpacity="0.6" />
          <stop offset="100%" stopColor="#00e676" stopOpacity="0" />
        </linearGradient>
      </defs>
    </svg>
  )
}

export function Navbar() {
  const { user } = useUser({ redirectIfUnauthenticated: false })
  const router = useRouter()
  const { data: statsData } = useSWR(
    user ? '/api/stats' : null,
    stats.get,
    { revalidateOnFocus: false, refreshInterval: 60000 }
  )

  const { mutate: mutateGlobal } = useSWRConfig()

  const handleLogout = async () => {
    await auth.logout()
    // Wipe all SWR caches so no stale user/CVE data leaks if another account signs in
    await mutateGlobal(() => true, undefined, { revalidate: false })
    void router.push('/login?signed_out=1')
  }

  const newCount = statsData?.new_since_last_visit ?? 0

  return (
    <nav className="border-b border-wire-1 bg-surface-0/80 backdrop-blur-sm sticky top-0 z-50">
      {/* Top accent line */}
      <div className="h-px bg-gradient-to-r from-transparent via-acid to-transparent opacity-40" />

      <div className="max-w-[1400px] mx-auto px-4 sm:px-6 lg:px-8 h-14 flex items-center justify-between gap-4">
        {/* Logo */}
        <Link
          href="/"
          className="flex items-center gap-2.5 shrink-0 group"
          aria-label="CVE Radar home"
        >
          <div className="transition-all duration-300 group-hover:drop-shadow-[0_0_8px_rgba(0,230,118,0.6)]">
            <RadarIcon />
          </div>
          <div className="flex flex-col leading-none">
            <span className="text-[15px] font-bold tracking-widest text-acid uppercase font-rajdhani">
              CVE
            </span>
            <span className="text-[10px] tracking-[0.25em] text-ink-2 uppercase font-mono -mt-0.5">
              RADAR
            </span>
          </div>
        </Link>

        {/* Nav links */}
        {user && (
          <div className="flex items-center gap-1 sm:gap-2">
            <NavLink href="/dashboard" label="Dashboard" active={router.pathname === '/dashboard'}>
              {newCount > 0 && (
                <span className="ml-1.5 inline-flex items-center justify-center min-w-[18px] h-[18px] rounded-sm bg-acid/15 border border-acid/30 text-acid text-[10px] font-bold font-mono px-1">
                  {newCount > 99 ? '99+' : newCount}
                </span>
              )}
            </NavLink>
            <NavLink href="/stack" label="My Stack" active={router.pathname === '/stack'} />
          </div>
        )}

        {/* Right side */}
        <div className="flex items-center gap-3 shrink-0">
          {user ? (
            <>
              {/* System status dot */}
              <div className="hidden sm:flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-acid animate-pulse" />
                <span className="text-[11px] text-ink-2 font-mono tracking-wider uppercase">Live</span>
              </div>
              <div className="h-4 w-px bg-wire-2 hidden sm:block" />
              <NavLink href="/settings" label="Settings" active={router.pathname === '/settings'} />
              {/* Hidden below sm: logo + nav links + Settings + Sign out measured
                  433px against a 390px viewport, so every page scrolled sideways
                  on a phone. Settings (one tap away) carries its own Sign out. */}
              <button
                onClick={handleLogout}
                className="hidden sm:block text-[13px] font-medium text-ink-2 hover:text-crit transition-colors duration-200 px-2 py-1 rounded border border-transparent hover:border-crit/20 hover:bg-crit/5"
              >
                Sign out
              </button>
            </>
          ) : (
            <Link
              href="/login"
              className="inline-flex items-center gap-1.5 text-[13px] font-semibold text-void bg-acid hover:bg-acid/90 px-4 py-1.5 rounded font-rajdhani tracking-wide transition-all duration-200 shadow-acid-sm"
            >
              Sign in
            </Link>
          )}
        </div>
      </div>
    </nav>
  )
}

function NavLink({
  href,
  label,
  active,
  children,
}: {
  href: string
  label: string
  active: boolean
  children?: React.ReactNode
}) {
  return (
    <Link
      href={href}
      className={`relative inline-flex items-center px-3 py-1.5 text-[14px] font-semibold tracking-wide transition-all duration-200 rounded
        ${active
          ? 'text-acid bg-acid/8'
          : 'text-ink-2 hover:text-ink-0 hover:bg-surface-2'
        }`}
    >
      {label}
      {children}
      {active && (
        <span className="absolute -bottom-[1px] left-3 right-3 h-px bg-acid shadow-[0_0_6px_rgba(0,230,118,0.6)]" />
      )}
    </Link>
  )
}
