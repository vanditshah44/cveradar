/**
 * Landing page — public, no auth required.
 * Hero section with value prop and sign-up CTA.
 * Authenticated users are redirected to their dashboard.
 */
import Head from 'next/head'
import Link from 'next/link'
import { useRouter } from 'next/router'
import { useEffect } from 'react'
import { useUser } from '@/lib/auth'

export default function LandingPage() {
  const router = useRouter()
  const { user, isLoading } = useUser({ redirectIfUnauthenticated: false })

  useEffect(() => {
    if (!isLoading && user) {
      void router.replace('/dashboard')
    }
  }, [user, isLoading, router])

  return (
    <>
      <Head>
        <title>CVE Radar — Know which vulnerabilities actually affect you</title>
      </Head>
      <div className="min-h-screen bg-neutral-950 text-white">
        {/* Nav */}
        <nav className="border-b border-neutral-800">
          <div className="max-w-5xl mx-auto px-4 h-14 flex items-center justify-between">
            <span className="font-semibold tracking-tight">CVE Radar</span>
            <Link href="/login" className="text-sm bg-white text-black font-medium px-4 py-1.5 rounded-lg hover:bg-neutral-200 transition-colors">
              Get started
            </Link>
          </div>
        </nav>

        {/* Hero */}
        <div className="max-w-3xl mx-auto px-4 pt-24 pb-16 text-center">
          <div className="inline-flex items-center gap-2 bg-red-500/10 border border-red-500/20 text-red-400 text-xs px-3 py-1.5 rounded-full mb-6">
            <span className="w-1.5 h-1.5 rounded-full bg-red-400 animate-pulse" />
            50–100 new CVEs published daily
          </div>
          <h1 className="text-4xl md:text-5xl font-bold tracking-tight mb-4">
            Know which vulnerabilities<br />
            <span className="text-neutral-400">actually affect you</span>
          </h1>
          <p className="text-lg text-neutral-400 mb-8 max-w-xl mx-auto">
            Tell CVE Radar what you run. We&apos;ll tell you what matters — prioritized by real-world exploitation risk, not just CVSS scores.
          </p>
          <Link href="/login" className="inline-flex items-center gap-2 bg-white text-black font-semibold px-6 py-3 rounded-lg hover:bg-neutral-200 transition-colors">
            Add your stack, know your risk →
          </Link>
          <p className="mt-3 text-sm text-neutral-600">Free. No password required.</p>
        </div>

        {/* How it works */}
        <div className="max-w-4xl mx-auto px-4 pb-20">
          <div className="grid md:grid-cols-3 gap-4">
            {[
              { step: '01', title: 'Register your stack', body: 'Add the software you run — nginx, PostgreSQL, Docker, etc. We support 50+ common homelab and dev tools.' },
              { step: '02', title: 'We watch the feeds', body: 'NVD, CISA KEV, and EPSS — synced hourly. Every new CVE is cross-referenced against your stack automatically.' },
              { step: '03', title: 'You only see what matters', body: 'Your dashboard shows only CVEs affecting your software, ranked by a composite risk score: KEV × EPSS × CVSS.' },
            ].map(({ step, title, body }) => (
              <div key={step} className="bg-neutral-900 border border-neutral-800 rounded-lg p-6">
                <div className="text-xs font-mono text-neutral-600 mb-2">{step}</div>
                <h3 className="font-semibold text-white mb-2">{title}</h3>
                <p className="text-sm text-neutral-400">{body}</p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </>
  )
}
