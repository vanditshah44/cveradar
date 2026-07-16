/**
 * Stack management page — add, edit, and remove products from your stack.
 *
 * Flow:
 *  1. User searches for a product → ProductSearch autocomplete
 *  2. User types a version → clicks Add (or presses Enter)
 *  3. POST /api/stack → item appears in the list below
 *  4. Each item can have its version edited inline or be removed
 *
 * After every add/update the backend enqueues a Celery matching task so the
 * dashboard starts populating with relevant CVEs immediately.
 */
import Head from 'next/head'
import Link from 'next/link'
import { useRouter } from 'next/router'
import { useState } from 'react'
import useSWR from 'swr'
import { products, stack, type StackItem, type Product } from '@/lib/api'
import { useUser } from '@/lib/auth'
import { Layout } from '@/components/Layout'
import { StackItemCard } from '@/components/StackItemCard'
import { ProductSearch } from '@/components/ProductSearch'

type NoticeState = {
  tone: 'success' | 'warning'
  message: string
}

export default function StackPage() {
  const router = useRouter()
  const { user } = useUser()
  const onboarding = router.query.onboarding === '1'

  // The product the user picked from the autocomplete
  const [selectedProduct, setSelectedProduct] = useState<Product | null>(null)
  // The version they typed
  const [version, setVersion] = useState('')
  // Submission state for the add form
  const [adding, setAdding] = useState(false)
  const [addError, setAddError] = useState('')
  const [notice, setNotice] = useState<NoticeState | null>(null)

  // SWR fetches the list and gives us `mutate` to update it locally without a refetch
  const { data: items, isLoading, mutate } = useSWR<StackItem[]>(
    user ? '/api/stack' : null,
    stack.list,
  )
  const { data: popularProducts } = useSWR<Product[]>(
    '/api/products/popular',
    products.popular,
    { revalidateOnFocus: false }
  )

  const showOnboarding = !items?.length

  // ── Add ───────────────────────────────────────────────────────────────────

  async function handleAdd(e: React.FormEvent) {
    e.preventDefault()
    if (!selectedProduct || !version.trim()) return

    setAdding(true)
    setAddError('')

    try {
      const newItem = await stack.add({
        product_name: selectedProduct.display_name,
        vendor: selectedProduct.vendor,
        cpe_product: selectedProduct.cpe_product,
        version: version.trim(),
        // Build the CPE string: cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*
        cpe_string: `cpe:2.3:a:${selectedProduct.vendor}:${selectedProduct.cpe_product}:${version.trim()}:*:*:*:*:*:*:*`,
        category: selectedProduct.category ?? null,
      })

      // Add the new item to the top of the list (matches backend's "order by added_at desc")
      mutate([newItem, ...(items || [])])
      setNotice({
        tone: newItem.matching_queued ? 'success' : 'warning',
        message: newItem.matching_message || 'Saved successfully.',
      })
      setSelectedProduct(null)
      setVersion('')
      setAddError('')
    } catch (err) {
      setAddError(err instanceof Error ? err.message : 'Failed to add product')
    } finally {
      setAdding(false)
    }
  }

  // ── Update version ────────────────────────────────────────────────────────

  async function handleUpdate(id: string, newVersion: string) {
    const item = items?.find(i => i.id === id)
    if (!item) return

    const updated = await stack.updateVersion(item, newVersion)

    // Replace the old item in the list with the updated one
    mutate(items?.map(i => i.id === id ? updated : i))
    setNotice({
      tone: updated.matching_queued ? 'success' : 'warning',
      message: updated.matching_message || 'Updated successfully.',
    })
  }

  // ── Remove ────────────────────────────────────────────────────────────────

  async function handleRemove(id: string) {
    await stack.remove(id)
    // Only update the list after a confirmed successful DELETE
    mutate(items?.filter(i => i.id !== id))
  }

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <Layout>
      <Head><title>My Stack — CVE Radar</title></Head>

      <div className="max-w-2xl">
        <div className="flex items-baseline justify-between mb-1">
          <h1 className="text-xl font-semibold text-white">
          {showOnboarding || onboarding ? 'Set up your stack' : 'My Stack'}
          </h1>
          {items && items.length > 0 && (
            <span className="text-sm text-neutral-500">{items.length} product{items.length !== 1 ? 's' : ''}</span>
          )}
        </div>
        <p className="text-sm text-neutral-500 mb-6">
          {showOnboarding || onboarding
            ? 'Pick a product you actually run, enter its version, and we will start matching CVEs against it right away.'
            : 'Add the software you run to start receiving relevant CVE alerts.'}
        </p>

        {notice && (
          <div
            className={`mb-4 rounded-lg px-4 py-3 text-sm ${
              notice.tone === 'success'
                ? 'border border-emerald-800 bg-emerald-500/10 text-emerald-200'
                : 'border border-amber-800 bg-amber-500/10 text-amber-200'
            }`}
          >
            <p>{notice.message}</p>
            {notice.tone === 'success' && (
              <p className="mt-1 text-xs text-emerald-300/80">
                Matching usually finishes within a few seconds. Check your dashboard after adding a couple of products.
              </p>
            )}
          </div>
        )}

        {showOnboarding && (
          <div className="mb-6 rounded-xl border border-neutral-800 bg-neutral-900/80 p-5">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div>
                <h2 className="text-sm font-semibold text-white mb-2">Start with the software you know you run</h2>
                <p className="text-sm text-neutral-400 max-w-xl">
                  Add your reverse proxy, database, or core self-hosted app first. Once one product is saved,
                  CVE Radar will begin matching in the background and your dashboard will stop being empty.
                </p>
              </div>
              {items && items.length > 0 && (
                <Link
                  href="/dashboard"
                  className="shrink-0 rounded-lg border border-neutral-700 px-3 py-2 text-sm text-neutral-300 hover:border-neutral-500 hover:text-white transition-colors"
                >
                  Open dashboard
                </Link>
              )}
            </div>

            {popularProducts && popularProducts.length > 0 && (
              <div className="mt-5">
                <p className="text-xs font-medium uppercase tracking-wide text-neutral-500 mb-3">
                  Popular products
                </p>
                <div className="flex flex-wrap gap-2">
                  {popularProducts.slice(0, 12).map(product => (
                    <button
                      key={product.id}
                      type="button"
                      onClick={() => {
                        setSelectedProduct(product)
                        setVersion('')
                        setAddError('')
                        setNotice(null)
                      }}
                      className={`rounded-full border px-3 py-1.5 text-sm transition-colors ${
                        selectedProduct?.id === product.id
                          ? 'border-white bg-white text-black'
                          : 'border-neutral-700 text-neutral-300 hover:border-neutral-500 hover:text-white'
                      }`}
                    >
                      {product.display_name}
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── Add form ──────────────────────────────────────────────────── */}
        <div className="bg-neutral-900 border border-neutral-800 rounded-lg p-4 mb-6">
          <h2 className="text-sm font-medium text-white mb-3">
            {selectedProduct ? 'Confirm product and version' : 'Add a product'}
          </h2>
          <form onSubmit={handleAdd} className="space-y-3">

            <ProductSearch
              onSelect={p => {
                setSelectedProduct(p)
                setVersion('')
                setAddError('')
                setNotice(null)
              }}
            />

            {selectedProduct && (
              <div className="flex items-center gap-2">
                {/* Show which product was selected */}
                <div className="flex items-center gap-2 flex-1 bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm">
                  <span className="text-white font-medium">{selectedProduct.display_name}</span>
                  <button
                    type="button"
                    onClick={() => setSelectedProduct(null)}
                    className="ml-auto text-neutral-500 hover:text-white transition-colors text-xs"
                  >
                    ✕
                  </button>
                </div>

                {/* Version input */}
                <input
                  type="text"
                  value={version}
                  onChange={e => setVersion(e.target.value)}
                  placeholder="Version (e.g. 1.24.0)"
                  autoFocus
                  className="w-40 bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm text-white placeholder-neutral-500 focus:outline-none focus:border-neutral-500"
                  required
                />

                <button
                  type="submit"
                  disabled={adding || !version.trim()}
                  className="bg-white text-black text-sm font-medium px-4 py-2 rounded-lg hover:bg-neutral-200 disabled:opacity-50 transition-colors shrink-0"
                >
                  {adding ? 'Adding...' : 'Add'}
                </button>
              </div>
            )}

            {addError && <p className="text-xs text-red-400">{addError}</p>}
            {!selectedProduct && showOnboarding && (
              <p className="text-xs text-neutral-500">
                Tip: pick one of the popular products above, or search for the exact software name you run.
              </p>
            )}
          </form>
        </div>

        {/* ── Stack list ────────────────────────────────────────────────── */}
        {isLoading ? (
          // Skeleton placeholders while loading
          <div className="space-y-2">
            {[...Array(3)].map((_, i) => (
              <div key={i} className="bg-neutral-900 border border-neutral-800 rounded-lg h-12 animate-pulse" />
            ))}
          </div>
        ) : !items?.length ? (
          <div className="border border-dashed border-neutral-800 rounded-lg p-6">
            <p className="text-sm font-medium text-white">Your stack is empty.</p>
            <p className="text-sm text-neutral-400 mt-2">
              Add at least one product and version above. CVE Radar will use that to find matching vulnerabilities,
              rank them, and start populating your dashboard.
            </p>
            <div className="mt-4 grid gap-3 md:grid-cols-3">
              {[
                { title: '1. Pick software', body: 'Start with something important like Nginx, PostgreSQL, Docker, or Nextcloud.' },
                { title: '2. Enter the version', body: 'Use the version you actually run so the matcher can compare it against NVD ranges.' },
                { title: '3. Wait a moment', body: 'Matching runs in the background after each save and your dashboard should update shortly.' },
              ].map(step => (
                <div key={step.title} className="rounded-lg border border-neutral-800 bg-neutral-900 px-4 py-3">
                  <p className="text-xs font-semibold uppercase tracking-wide text-neutral-500">{step.title}</p>
                  <p className="mt-2 text-sm text-neutral-400">{step.body}</p>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div className="space-y-2">
            {items.map(item => (
              <StackItemCard
                key={item.id}
                item={item}
                onRemove={handleRemove}
                onUpdate={handleUpdate}
              />
            ))}
          </div>
        )}
      </div>
    </Layout>
  )
}
