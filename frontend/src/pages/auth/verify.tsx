/**
 * /auth/verify — receives the magic link token and hands it to the backend.
 *
 * Flow:
 *   1. User clicks magic link → lands here at /auth/verify?token=xxx
 *   2. This page does a full browser redirect to /api/auth/verify?token=xxx
 *   3. FastAPI verifies the token, sets the HTTP-only session cookie, and
 *      redirects to /dashboard
 *
 * Why window.location.href instead of router.push?
 *   The backend sets a Set-Cookie header on its redirect response. That only
 *   works with a real browser navigation — not a client-side router push
 *   which intercepts the response before the browser can save the cookie.
 */
import { useEffect, useState } from 'react'
import { useRouter } from 'next/router'
import Head from 'next/head'

export default function VerifyPage() {
  const router = useRouter()
  const [error, setError] = useState(false)

  useEffect(() => {
    // router.query is populated after hydration
    if (!router.isReady) return

    const { token } = router.query

    if (!token || typeof token !== 'string') {
      setError(true)
      return
    }

    // Full browser navigation → backend sets cookie → redirects to /dashboard
    window.location.href = `/api/auth/verify?token=${token}`
  }, [router.isReady, router.query])

  if (error) {
    return (
      <>
        <Head><title>Invalid link — CVE Radar</title></Head>
        <div className="min-h-screen bg-neutral-950 flex flex-col items-center justify-center gap-3">
          <p className="text-white font-medium">Invalid or expired sign-in link.</p>
          <a href="/login" className="text-sm text-neutral-400 hover:text-white transition-colors">
            Request a new one →
          </a>
        </div>
      </>
    )
  }

  return (
    <>
      <Head><title>Signing in... — CVE Radar</title></Head>
      <div className="min-h-screen bg-neutral-950 flex flex-col items-center justify-center gap-3">
        <div className="w-5 h-5 border-2 border-neutral-600 border-t-white rounded-full animate-spin" />
        <p className="text-neutral-400 text-sm">Signing you in...</p>
      </div>
    </>
  )
}
