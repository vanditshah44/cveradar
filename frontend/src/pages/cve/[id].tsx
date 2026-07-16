/**
 * CVE detail page — full info about one CVE including references, matches, and affected versions.
 */
import Head from 'next/head'
import Link from 'next/link'
import { useRouter } from 'next/router'
import { useEffect, useRef, useState } from 'react'
import useSWR from 'swr'
import { cves, type CveAffectedProduct, type CveReference } from '@/lib/api'
import { useUser } from '@/lib/auth'
import { Layout } from '@/components/Layout'
import { SeverityBadge } from '@/components/SeverityBadge'
import { KevBadge } from '@/components/KevBadge'

const REFERENCE_TAG_PREFERENCE = [
  'Vendor Advisory',
  'Patch',
  'Mitigation',
  'Release Notes',
  'Third Party Advisory',
]

function referenceLabel(reference: CveReference) {
  const tags = reference.tags || []
  for (const preferred of REFERENCE_TAG_PREFERENCE) {
    if (tags.includes(preferred)) return preferred
  }
  if (reference.source) return reference.source
  if (reference.url) {
    try {
      return new URL(reference.url).hostname.replace(/^www\./, '')
    } catch {
      return 'Reference'
    }
  }
  return 'Reference'
}

function formatDate(value: string | null) {
  if (!value) return null
  return new Date(value).toLocaleDateString('en-US', { dateStyle: 'long' })
}

/**
 * Ensure a URL from an external data source (NVD references) is safe to use
 * as an href. Blocks javascript: and data: URIs that could execute code.
 */
function safeUrl(url: string | null | undefined): string {
  if (!url) return '#'
  try {
    const { protocol } = new URL(url)
    if (protocol === 'javascript:' || protocol === 'data:' || protocol === 'vbscript:') return '#'
    return url
  } catch {
    return '#'
  }
}

function RuleCard({ rule }: { rule: CveAffectedProduct }) {
  return (
    <div className="rounded-lg border border-neutral-800 bg-neutral-950 p-4">
      <div className="flex flex-wrap items-center gap-2 mb-2">
        <p className="text-sm font-medium text-white">
          {rule.vendor}/{rule.product}
        </p>
        <span
          className={`rounded-full border px-2 py-0.5 text-[11px] ${
            rule.is_vulnerable_match
              ? 'border-red-500/30 bg-red-500/10 text-red-300'
              : 'border-amber-500/30 bg-amber-500/10 text-amber-300'
          }`}
        >
          {rule.is_vulnerable_match ? 'Target match' : 'Supporting condition'}
        </span>
        {rule.condition_group && (
          <span className="rounded-full border border-neutral-700 px-2 py-0.5 text-[11px] text-neutral-400">
            Group {rule.condition_group}
          </span>
        )}
      </div>
      <p className="text-sm text-neutral-300">Affected versions: {rule.range_display}</p>
      {rule.config_path && (
        <p className="mt-2 text-xs font-mono text-neutral-500">{rule.config_path}</p>
      )}
    </div>
  )
}

export default function CveDetailPage() {
  useUser()
  const router = useRouter()
  const { id } = router.query
  const hasMarkedSeen = useRef(false)
  const [dismissError, setDismissError] = useState('')
  const [isDismissing, setIsDismissing] = useState(false)

  const { data: cve, isLoading, error, mutate } = useSWR(
    id ? `cve-${id}` : null,
    () => cves.get(id as string),
    { revalidateOnFocus: false }
  )

  useEffect(() => {
    if (typeof id !== 'string' || !cve || cve.seen_at || hasMarkedSeen.current) {
      return
    }

    hasMarkedSeen.current = true
    const optimisticSeenAt = new Date().toISOString()
    void mutate({ ...cve, seen_at: optimisticSeenAt }, { revalidate: false })
    void cves.markSeen(id)
      .then(result => {
        void mutate(current => current ? { ...current, seen_at: result.seen_at } : current, { revalidate: false })
      })
      .catch(() => {
        hasMarkedSeen.current = false
        void mutate()
      })
  }, [cve, id, mutate])

  const handleDismiss = async () => {
    if (typeof id !== 'string') return

    setIsDismissing(true)
    setDismissError('')
    try {
      await cves.dismiss(id)
      await router.push('/dashboard')
    } catch (err) {
      setDismissError(err instanceof Error ? err.message : 'Could not dismiss this CVE.')
    } finally {
      setIsDismissing(false)
    }
  }

  if (isLoading) {
    return (
      <Layout>
        <div className="animate-pulse space-y-4">
          <div className="h-6 w-40 rounded bg-neutral-900" />
          <div className="h-10 w-72 rounded bg-neutral-900" />
          <div className="h-5 w-full rounded bg-neutral-900" />
          <div className="grid gap-3 md:grid-cols-4">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="h-20 rounded-lg border border-neutral-800 bg-neutral-900" />
            ))}
          </div>
        </div>
      </Layout>
    )
  }

  if (error || !cve) {
    return (
      <Layout>
        <div className="max-w-2xl rounded-xl border border-red-900 bg-red-500/10 p-5">
          <p className="text-sm font-medium text-red-200">This CVE detail page could not be loaded.</p>
          <p className="mt-1 text-sm text-red-200/80">{error instanceof Error ? error.message : 'Unknown error.'}</p>
          <div className="mt-4 flex gap-3">
            <button
              type="button"
              onClick={() => void mutate()}
              className="rounded-lg border border-red-800 px-4 py-2 text-sm text-red-100 hover:border-red-700 hover:bg-red-500/10 transition-colors"
            >
              Try again
            </button>
            <Link
              href="/dashboard"
              className="rounded-lg border border-neutral-700 px-4 py-2 text-sm text-neutral-300 hover:border-neutral-500 hover:text-white transition-colors"
            >
              Back to dashboard
            </Link>
          </div>
        </div>
      </Layout>
    )
  }

  const publishedDate = formatDate(cve.published_at)
  const kevDateAdded = formatDate(cve.kev_date_added)
  const targetRules = (cve.affected_products || []).filter(rule => rule.is_vulnerable_match)
  const supportingRules = (cve.affected_products || []).filter(rule => !rule.is_vulnerable_match)
  const usefulReference = cve.useful_reference?.url ? cve.useful_reference : null
  const visibleReferences = (cve.references || []).filter(reference => reference.url)

  return (
    <Layout>
      <Head><title>{cve.cve_id} — CVE Radar</title></Head>

      <div className="max-w-5xl">
        <div className="mb-6 flex flex-wrap items-center justify-between gap-3">
          <Link href="/dashboard" className="text-sm text-neutral-400 hover:text-white transition-colors">
            ← Back to dashboard
          </Link>
          <button
            type="button"
            onClick={handleDismiss}
            disabled={isDismissing}
            className="rounded-lg border border-neutral-700 px-3 py-2 text-sm text-neutral-300 transition-colors disabled:cursor-not-allowed disabled:opacity-50 hover:border-neutral-500 hover:text-white"
          >
            {isDismissing ? 'Dismissing…' : 'Dismiss from dashboard'}
          </button>
        </div>

        <div className="mb-6">
          <div className="flex items-center flex-wrap gap-2 mb-3">
            <h1 className="text-2xl font-mono font-bold text-white">{cve.cve_id}</h1>
            <SeverityBadge severity={cve.severity} />
            {cve.kev_flag && <KevBadge />}
            <span className={`rounded-full border px-2 py-0.5 text-[11px] ${cve.seen_at ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300' : 'border-blue-500/30 bg-blue-500/10 text-blue-300'}`}>
              {cve.seen_at ? 'Seen' : 'Marking as seen…'}
            </span>
          </div>
          {cve.description && (
            <p className="max-w-3xl text-neutral-300 leading-relaxed">{cve.description}</p>
          )}
          {dismissError && (
            <p className="mt-3 text-sm text-red-300">{dismissError}</p>
          )}
        </div>

        <div className="grid grid-cols-2 gap-3 md:grid-cols-5 mb-6">
          {[
            { label: 'Priority', value: `${Math.round(cve.priority_score)}/100`, highlight: cve.priority_score >= 70 },
            { label: 'CVSS', value: cve.cvss_score != null ? cve.cvss_score.toFixed(1) : 'N/A', highlight: false },
            { label: 'EPSS', value: cve.epss_score != null ? `${(cve.epss_score * 100).toFixed(1)}%` : 'N/A', highlight: false },
            { label: 'Published', value: publishedDate || 'Unknown', highlight: false },
            { label: 'KEV added', value: kevDateAdded || (cve.kev_flag ? 'Known exploited' : 'No'), highlight: cve.kev_flag },
          ].map(({ label, value, highlight }) => (
            <div key={label} className="rounded-lg border border-neutral-800 bg-neutral-900 p-3">
              <p className="text-xs text-neutral-500 mb-1">{label}</p>
              <p className={`font-semibold ${highlight ? 'text-red-400' : 'text-white'}`}>{value}</p>
            </div>
          ))}
        </div>

        <div className="mb-6 flex flex-wrap gap-3">
          {usefulReference && (
            <a
              href={safeUrl(usefulReference.url)}
              target="_blank"
              rel="noopener noreferrer"
              className="rounded-lg border border-sky-800 bg-sky-500/10 px-4 py-2 text-sm text-sky-200 hover:border-sky-700 hover:text-white transition-colors"
            >
              Open best advisory →
            </a>
          )}
          <a
            href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`}
            target="_blank"
            rel="noopener noreferrer"
            className="rounded-lg border border-neutral-700 px-4 py-2 text-sm text-neutral-300 hover:border-neutral-500 hover:text-white transition-colors"
          >
            View on NVD →
          </a>
          {cve.kev_flag && (
            <a
              href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
              target="_blank"
              rel="noopener noreferrer"
              className="rounded-lg border border-red-800 px-4 py-2 text-sm text-red-300 hover:border-red-700 hover:text-red-200 transition-colors"
            >
              View in CISA KEV →
            </a>
          )}
        </div>

        <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_320px]">
          <section className="space-y-6">
            <div className="rounded-xl border border-neutral-800 bg-neutral-900/70 p-5">
              <div className="flex items-start justify-between gap-4 mb-4">
                <div>
                  <h2 className="text-sm font-semibold text-white">Matched stack items</h2>
                  <p className="mt-1 text-sm text-neutral-400">
                    This CVE matched {cve.matched_stack_items.length} item{cve.matched_stack_items.length !== 1 ? 's' : ''} in your stack.
                  </p>
                </div>
                <Link href="/stack" className="text-sm text-neutral-400 hover:text-white transition-colors">
                  Edit stack
                </Link>
              </div>

              <div className="space-y-3">
                {cve.matched_stack_items.map(item => (
                  <div key={item.id} className="rounded-lg border border-neutral-800 bg-neutral-950 p-4">
                    <div className="flex flex-wrap items-center gap-2 mb-2">
                      <p className="text-sm font-medium text-white">{item.product_name}</p>
                      <span className="rounded-full border border-neutral-700 px-2 py-0.5 text-[11px] text-neutral-400">
                        {item.version}
                      </span>
                      {item.category && (
                        <span className="rounded-full border border-neutral-700 px-2 py-0.5 text-[11px] text-neutral-500">
                          {item.category}
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-neutral-500">
                      Vendor: {item.vendor} | CPE product: {item.cpe_product}
                    </p>
                  </div>
                ))}
              </div>
            </div>

            <div className="rounded-xl border border-neutral-800 bg-neutral-900/70 p-5">
              <h2 className="text-sm font-semibold text-white mb-4">Affected version rules</h2>

              {targetRules.length > 0 ? (
                <div className="space-y-3">
                  {targetRules.map((rule, index) => (
                    <RuleCard key={`${rule.vendor}-${rule.product}-${rule.range_display}-${index}`} rule={rule} />
                  ))}
                </div>
              ) : (
                <p className="text-sm text-neutral-500">NVD did not provide explicit target version ranges for this CVE.</p>
              )}

              {supportingRules.length > 0 && (
                <div className="mt-5">
                  <h3 className="text-xs font-semibold uppercase tracking-wide text-neutral-500 mb-3">
                    Supporting environment conditions
                  </h3>
                  <div className="space-y-3">
                    {supportingRules.map((rule, index) => (
                      <RuleCard key={`${rule.vendor}-${rule.product}-${rule.range_display}-${rule.condition_group || 'env'}-${index}`} rule={rule} />
                    ))}
                  </div>
                </div>
              )}
            </div>
          </section>

          <aside className="space-y-6">
            <div className="rounded-xl border border-neutral-800 bg-neutral-900/70 p-5">
              <h2 className="text-sm font-semibold text-white mb-3">Why you are seeing this</h2>
              <p className="text-sm text-neutral-400">
                CVE Radar matched this CVE against your saved stack items and versions. The matched products above are the ones currently driving this alert in your account.
              </p>
            </div>

            <div className="rounded-xl border border-neutral-800 bg-neutral-900/70 p-5">
              <div className="flex items-center justify-between gap-3 mb-3">
                <h2 className="text-sm font-semibold text-white">References</h2>
                <span className="text-xs text-neutral-500">{visibleReferences.length}</span>
              </div>

              {visibleReferences.length > 0 ? (
                <div className="space-y-3">
                  {visibleReferences.map((reference, index) => (
                    <a
                      key={`${reference.url}-${index}`}
                      href={safeUrl(reference.url)}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="block rounded-lg border border-neutral-800 bg-neutral-950 p-3 hover:border-neutral-700 transition-colors"
                    >
                      <div className="flex flex-wrap items-center gap-2 mb-1">
                        <span className="text-sm font-medium text-white">{referenceLabel(reference)}</span>
                        {(reference.tags || []).slice(0, 3).map(tag => (
                          <span key={tag} className="rounded-full border border-neutral-700 px-2 py-0.5 text-[11px] text-neutral-400">
                            {tag}
                          </span>
                        ))}
                      </div>
                      <p className="break-all text-xs text-neutral-500">{reference.url}</p>
                    </a>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-neutral-500">No references were provided for this CVE.</p>
              )}
            </div>
          </aside>
        </div>
      </div>
    </Layout>
  )
}
