/**
 * ProductSearch — autocomplete input for adding products to the stack.
 *
 * Two states:
 *   - Empty / focused: show the popular products list (fetched once on mount)
 *   - Typing: show live search results from /api/products/search
 *
 * Closes the dropdown when clicking outside (via a document mousedown listener).
 */
import { useState, useEffect, useRef } from 'react'
import { products, type Product } from '@/lib/api'

interface Props {
  onSelect: (product: Product) => void
}

export function ProductSearch({ onSelect }: Props) {
  const [query, setQuery] = useState('')
  const [results, setResults] = useState<Product[]>([])
  const [popular, setPopular] = useState<Product[]>([])
  const [open, setOpen] = useState(false)
  const [loadingPopular, setLoadingPopular] = useState(false)

  const containerRef = useRef<HTMLDivElement>(null)
  const debounceRef = useRef<ReturnType<typeof setTimeout>>()

  // Fetch popular products once on mount so they're ready when user focuses
  useEffect(() => {
    setLoadingPopular(true)
    products.popular()
      .then(setPopular)
      .catch(() => setPopular([]))
      .finally(() => setLoadingPopular(false))
  }, [])

  // Search as the user types (debounced 200ms)
  useEffect(() => {
    clearTimeout(debounceRef.current)

    if (query.length === 0) {
      // Back to empty — drop search results so we fall back to popular list
      setResults([])
      return
    }

    debounceRef.current = setTimeout(async () => {
      try {
        const data = await products.search(query)
        setResults(data)
      } catch {
        setResults([])
      }
    }, 200)

    return () => clearTimeout(debounceRef.current)
  }, [query])

  // Close dropdown when clicking outside this component
  useEffect(() => {
    function handleClickOutside(e: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  // What to show in the dropdown
  const displayList = query.length > 0 ? results : popular
  const showDropdown = open && displayList.length > 0

  function handleSelect(product: Product) {
    setQuery('')
    setResults([])
    setOpen(false)
    onSelect(product)
  }

  return (
    <div ref={containerRef} className="relative">
      <input
        type="text"
        value={query}
        onChange={e => setQuery(e.target.value)}
        onFocus={() => setOpen(true)}
        placeholder="Search products (nginx, postgres, redis...)"
        className="w-full bg-neutral-800 border border-neutral-700 rounded-lg px-4 py-2.5 text-sm text-white placeholder-neutral-500 focus:outline-none focus:border-neutral-500"
      />

      {showDropdown && (
        <div className="absolute z-10 w-full mt-1 bg-neutral-900 border border-neutral-700 rounded-lg shadow-xl overflow-hidden">
          {/* Label row */}
          <div className="px-4 py-1.5 text-xs text-neutral-600 border-b border-neutral-800">
            {query.length === 0 ? 'Popular products' : `${results.length} result${results.length !== 1 ? 's' : ''}`}
          </div>

          {displayList.map(product => (
            <button
              key={product.id}
              type="button"
              onMouseDown={e => {
                // Use mousedown instead of click so it fires before the input's onBlur
                e.preventDefault()
                handleSelect(product)
              }}
              className="w-full text-left px-4 py-2.5 text-sm hover:bg-neutral-800 transition-colors flex items-center justify-between"
            >
              <span className="text-white font-medium">{product.display_name}</span>
              {product.category && (
                <span className="text-neutral-500 text-xs capitalize">
                  {product.category.replace(/_/g, ' ')}
                </span>
              )}
            </button>
          ))}
        </div>
      )}

      {/* Show a subtle hint when focused but popular list is still loading */}
      {open && displayList.length === 0 && loadingPopular && (
        <div className="absolute z-10 w-full mt-1 bg-neutral-900 border border-neutral-700 rounded-lg px-4 py-3 text-xs text-neutral-500">
          Loading...
        </div>
      )}

      {/* No results for typed query */}
      {open && query.length > 0 && results.length === 0 && !loadingPopular && (
        <div className="absolute z-10 w-full mt-1 bg-neutral-900 border border-neutral-700 rounded-lg px-4 py-3 text-xs text-neutral-500">
          No products found for &ldquo;{query}&rdquo;
        </div>
      )}
    </div>
  )
}
