/**
 * Login page — magic link auth.
 *
 * Dev mode: when RESEND_API_KEY is not set on the backend, the API returns
 * a dev_link token directly. We auto-navigate to it so login is instant —
 * no email check needed during local development.
 */
import Head from 'next/head'
import { useRouter } from 'next/router'
import { useEffect, useRef, useState } from 'react'
import { useUser } from '@/lib/auth'

function RadarLogo() {
  return (
    <div className="flex items-center gap-3 mb-8">
      <svg width="32" height="32" viewBox="0 0 32 32" fill="none">
        <circle cx="16" cy="16" r="14" stroke="rgba(0,230,118,0.2)" strokeWidth="1" />
        <circle cx="16" cy="16" r="8"  stroke="rgba(0,230,118,0.15)" strokeWidth="1" />
        <circle cx="16" cy="16" r="2.5" fill="#00e676" />
        <line x1="16" y1="2"  x2="16" y2="6"  stroke="rgba(0,230,118,0.4)" strokeWidth="1" />
        <line x1="16" y1="26" x2="16" y2="30" stroke="rgba(0,230,118,0.4)" strokeWidth="1" />
        <line x1="2"  y1="16" x2="6"  y2="16" stroke="rgba(0,230,118,0.4)" strokeWidth="1" />
        <line x1="26" y1="16" x2="30" y2="16" stroke="rgba(0,230,118,0.4)" strokeWidth="1" />
        <line
          x1="16" y1="16" x2="16" y2="2"
          stroke="#00e676" strokeWidth="1.5" strokeLinecap="round"
          style={{ transformOrigin: '16px 16px', animation: 'spin 5s linear infinite' }}
        />
      </svg>
      <div className="flex flex-col leading-none">
        <span className="text-[17px] font-bold tracking-widest text-[#00e676] uppercase" style={{ fontFamily: 'var(--font-rajdhani, system-ui)' }}>
          CVE
        </span>
        <span className="text-[11px] tracking-[0.3em] text-[#4a6a88] uppercase -mt-0.5" style={{ fontFamily: 'var(--font-mono, monospace)' }}>
          RADAR
        </span>
      </div>
    </div>
  )
}

export default function LoginPage() {
  const router = useRouter()
  const [email, setEmail] = useState('')
  const [state, setState] = useState<'idle' | 'loading' | 'sent' | 'error'>('idle')
  const [errorMsg, setErrorMsg] = useState('')
  const inputRef = useRef<HTMLInputElement>(null)

  const signedOut      = router.query.signed_out      === '1'
  const accountDeleted = router.query.account_deleted === '1'

  // If the user already has a valid session, skip the login page
  const { user, isLoading: authLoading } = useUser({ redirectIfUnauthenticated: false })
  useEffect(() => {
    if (!authLoading && user) {
      void router.replace('/dashboard')
    }
  }, [user, authLoading, router])

  // Auto-focus the input on mount
  useEffect(() => { inputRef.current?.focus() }, [])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setState('loading')
    setErrorMsg('')

    try {
      const res = await fetch('/api/auth/magic-link', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email }),
      })

      if (!res.ok) {
        const body = await res.json().catch(() => ({}))
        throw new Error(body?.detail || `Request failed (${res.status})`)
      }

      const data = await res.json()

      // Dev mode: backend returned the link directly — navigate immediately, no email needed
      if (data.dev_link) {
        setState('sent')
        // Small delay so the user sees the transition, then auto-navigate
        setTimeout(() => { window.location.href = data.dev_link }, 400)
        return
      }

      setState('sent')
    } catch (err) {
      setState('error')
      setErrorMsg(err instanceof Error ? err.message : 'Something went wrong. Make sure the API is running.')
    }
  }

  return (
    <>
      <Head><title>Sign in — CVE Radar</title></Head>

      {/* Full-screen void background with subtle grid */}
      <div
        className="min-h-screen flex flex-col items-center justify-center px-4 relative overflow-hidden"
        style={{
          background: '#030810',
          backgroundImage: 'radial-gradient(circle at 50% 0%, rgba(0,230,118,0.04) 0%, transparent 60%)',
        }}
      >
        {/* Dot grid */}
        <div
          className="absolute inset-0 pointer-events-none"
          style={{
            backgroundImage: 'radial-gradient(circle, rgba(255,255,255,0.03) 1px, transparent 1px)',
            backgroundSize: '24px 24px',
          }}
        />

        {/* Corner decorations */}
        <CornerDecor position="tl" />
        <CornerDecor position="tr" />
        <CornerDecor position="bl" />
        <CornerDecor position="br" />

        <div className="relative z-10 w-full max-w-[380px]">
          <div className="flex flex-col items-center">
            <RadarLogo />
          </div>

          {/* Card */}
          <div
            className="rounded-lg border p-6 relative"
            style={{
              background: '#0c1624',
              borderColor: '#1f3f5a',
              boxShadow: '0 0 40px rgba(0,0,0,0.6), inset 0 1px 0 rgba(255,255,255,0.03)',
            }}
          >
            {/* Top accent line */}
            <div
              className="absolute top-0 left-8 right-8 h-px"
              style={{ background: 'linear-gradient(90deg, transparent, rgba(0,230,118,0.5), transparent)' }}
            />

            {/* Signed-out / deleted notice */}
            {(signedOut || accountDeleted) && state === 'idle' && (
              <div
                className="mb-4 rounded px-3 py-2 text-[12px] font-mono border"
                style={accountDeleted
                  ? { borderColor: 'rgba(255,214,0,0.25)', background: 'rgba(255,214,0,0.05)', color: '#ffd600' }
                  : { borderColor: 'rgba(0,230,118,0.25)', background: 'rgba(0,230,118,0.05)', color: '#00e676' }
                }
              >
                {accountDeleted
                  ? 'Account deleted. Create a new one anytime.'
                  : 'Signed out successfully.'}
              </div>
            )}

            {state === 'sent' ? (
              // ── Sent / auto-redirect state ──────────────────────────────────
              <div className="text-center py-2">
                <div
                  className="inline-flex items-center justify-center w-12 h-12 rounded-full mb-4"
                  style={{ background: 'rgba(0,230,118,0.08)', border: '1px solid rgba(0,230,118,0.25)' }}
                >
                  <svg width="22" height="22" viewBox="0 0 22 22" fill="none">
                    <path d="M4 11l5 5 9-9" stroke="#00e676" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                </div>
                <p className="text-[15px] font-semibold text-[#daeeff] mb-1" style={{ fontFamily: 'var(--font-rajdhani, system-ui)' }}>
                  Signing you in…
                </p>
                <p className="text-[12px] font-mono" style={{ color: '#4a6a88' }}>
                  Redirecting to dashboard
                </p>
                {/* Animated dots */}
                <div className="flex items-center justify-center gap-1.5 mt-4">
                  {[0, 1, 2].map(i => (
                    <span
                      key={i}
                      className="w-1.5 h-1.5 rounded-full"
                      style={{
                        background: '#00e676',
                        animation: `pulse 1.2s ease-in-out ${i * 0.2}s infinite`,
                      }}
                    />
                  ))}
                </div>
              </div>
            ) : (
              // ── Login form ───────────────────────────────────────────────────
              <>
                <h2
                  className="text-[18px] font-bold mb-0.5"
                  style={{ color: '#daeeff', fontFamily: 'var(--font-rajdhani, system-ui)' }}
                >
                  Sign in
                </h2>
                <p className="text-[12px] font-mono mb-5" style={{ color: '#4a6a88' }}>
                  Enter your email — we&apos;ll send a sign-in link.
                </p>

                <form onSubmit={handleSubmit} className="space-y-3">
                  <div className="relative">
                    <input
                      ref={inputRef}
                      type="email"
                      value={email}
                      onChange={e => setEmail(e.target.value)}
                      placeholder="analyst@example.com"
                      required
                      className="w-full rounded px-4 py-2.5 text-[14px] font-mono transition-all duration-200 focus:outline-none"
                      style={{
                        background: '#111e2e',
                        border: '1px solid #1f3f5a',
                        color: '#daeeff',
                      }}
                      onFocus={e => {
                        e.currentTarget.style.borderColor = 'rgba(0,230,118,0.45)'
                        e.currentTarget.style.boxShadow  = '0 0 0 2px rgba(0,230,118,0.10)'
                      }}
                      onBlur={e => {
                        e.currentTarget.style.borderColor = '#1f3f5a'
                        e.currentTarget.style.boxShadow  = 'none'
                      }}
                    />
                  </div>

                  {state === 'error' && (
                    <p className="text-[11px] font-mono px-1" style={{ color: '#ff1744' }}>
                      {errorMsg}
                    </p>
                  )}

                  <button
                    type="submit"
                    disabled={state === 'loading' || !email}
                    className="w-full py-2.5 rounded text-[14px] font-bold tracking-wide transition-all duration-200 disabled:opacity-40 disabled:cursor-not-allowed"
                    style={{
                      background: state === 'loading' ? 'rgba(0,230,118,0.15)' : '#00e676',
                      color: state === 'loading' ? '#00e676' : '#030810',
                      border: state === 'loading' ? '1px solid rgba(0,230,118,0.3)' : '1px solid #00e676',
                      fontFamily: 'var(--font-rajdhani, system-ui)',
                      boxShadow: state === 'loading' ? 'none' : '0 0 16px rgba(0,230,118,0.2)',
                    }}
                  >
                    {state === 'loading' ? (
                      <span className="inline-flex items-center justify-center gap-2">
                        <svg width="14" height="14" viewBox="0 0 14 14" fill="none" className="animate-spin">
                          <circle cx="7" cy="7" r="5" stroke="currentColor" strokeWidth="1.5" strokeDasharray="8 24" />
                        </svg>
                        Sending…
                      </span>
                    ) : 'Send sign-in link'}
                  </button>
                </form>

                {/* Dev mode hint — only relevant on localhost */}
                <DevModeHint />
              </>
            )}
          </div>

          <p className="text-center text-[11px] font-mono mt-5" style={{ color: '#2a4060' }}>
            No password. No OAuth. Just your email.
          </p>
        </div>
      </div>

      <style jsx global>{`
        @keyframes pulse {
          0%, 100% { opacity: 0.2; transform: scale(0.85); }
          50%       { opacity: 1;   transform: scale(1); }
        }
      `}</style>
    </>
  )
}

// ── Dev mode hint ─────────────────────────────────────────────────────────────

function DevModeHint() {
  const [isLocalhost, setIsLocalhost] = useState(false)
  useEffect(() => {
    setIsLocalhost(
      typeof window !== 'undefined' &&
      (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1')
    )
  }, [])

  if (!isLocalhost) return null

  return (
    <div
      className="mt-4 rounded px-3 py-3 border"
      style={{
        background: 'rgba(0,230,118,0.04)',
        borderColor: 'rgba(0,230,118,0.18)',
      }}
    >
      <div className="flex items-center gap-2 mb-1.5">
        <span
          className="px-1.5 py-0.5 rounded text-[9px] font-bold tracking-widest uppercase font-mono"
          style={{ background: 'rgba(0,230,118,0.15)', color: '#00e676', border: '1px solid rgba(0,230,118,0.3)' }}
        >
          DEV
        </span>
        <span className="text-[11px] font-mono" style={{ color: '#00e676' }}>
          localhost detected
        </span>
      </div>
      <p className="text-[11px] font-mono leading-relaxed" style={{ color: '#4a6a88' }}>
        If <code style={{ color: '#8aaac8' }}>RESEND_API_KEY</code> is not set in your <code style={{ color: '#8aaac8' }}>.env</code>,
        submitting the form will auto-sign you in without email — no link to click.
      </p>
    </div>
  )
}

// ── Corner decorations ────────────────────────────────────────────────────────

function CornerDecor({ position }: { position: 'tl' | 'tr' | 'bl' | 'br' }) {
  const pos = {
    tl: 'top-0 left-0',
    tr: 'top-0 right-0',
    bl: 'bottom-0 left-0',
    br: 'bottom-0 right-0',
  }[position]

  const rot = { tl: '0', tr: '90', bl: '270', br: '180' }[position]

  return (
    <div className={`absolute ${pos} pointer-events-none`} style={{ transform: `rotate(${rot}deg)` }}>
      <svg width="48" height="48" viewBox="0 0 48 48" fill="none">
        <path d="M2 24 L2 2 L24 2" stroke="rgba(0,230,118,0.12)" strokeWidth="1" fill="none" />
        <circle cx="2" cy="2" r="2" fill="rgba(0,230,118,0.2)" />
      </svg>
    </div>
  )
}
