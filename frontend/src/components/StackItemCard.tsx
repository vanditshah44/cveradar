/**
 * StackItemCard — one row in the user's stack list.
 *
 * Normal state: product name, version, category tag, remove button.
 * Edit state: version becomes a text input with Save / Cancel buttons.
 *
 * The parent passes onRemove and onUpdate. Both are async — the card shows
 * a loading state while either is in flight.
 */
import { useState } from 'react'
import { type StackItem } from '@/lib/api'

interface Props {
  item: StackItem
  onRemove: (id: string) => Promise<void>
  onUpdate: (id: string, version: string) => Promise<void>
}

// Map CPE category slugs to a readable label + colour
const CATEGORY_STYLES: Record<string, { label: string; color: string }> = {
  web_server:  { label: 'Web server',  color: 'bg-green-900 text-green-300' },
  database:    { label: 'Database',    color: 'bg-blue-900 text-blue-300' },
  cms:         { label: 'CMS',         color: 'bg-purple-900 text-purple-300' },
  self_hosted: { label: 'Self-hosted', color: 'bg-orange-900 text-orange-300' },
  container:   { label: 'Container',   color: 'bg-cyan-900 text-cyan-300' },
  runtime:     { label: 'Runtime',     color: 'bg-yellow-900 text-yellow-300' },
  os:          { label: 'OS',          color: 'bg-neutral-700 text-neutral-300' },
  monitoring:  { label: 'Monitoring',  color: 'bg-pink-900 text-pink-300' },
  mail:        { label: 'Mail',        color: 'bg-red-900 text-red-300' },
}

export function StackItemCard({ item, onRemove, onUpdate }: Props) {
  const [editing, setEditing] = useState(false)
  const [editVersion, setEditVersion] = useState(item.version)
  const [saving, setSaving] = useState(false)
  const [removing, setRemoving] = useState(false)
  const [error, setError] = useState('')

  // The category is stored on the catalog but not returned from /api/stack.
  // We derive a rough category from the cpe_product name as a fallback.
  // This will be empty for most items — that's fine, we just don't show the badge.
  const categoryStyle = item.category ? CATEGORY_STYLES[item.category] : undefined

  async function handleSave() {
    if (!editVersion.trim() || editVersion === item.version) {
      setEditing(false)
      return
    }
    setSaving(true)
    setError('')
    try {
      await onUpdate(item.id, editVersion.trim())
      setEditing(false)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update')
    } finally {
      setSaving(false)
    }
  }

  async function handleRemove() {
    setRemoving(true)
    setError('')
    try {
      await onRemove(item.id)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to remove')
      setRemoving(false)
    }
    // If remove succeeds the parent will un-mount this card, so we don't reset
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'Enter') handleSave()
    if (e.key === 'Escape') { setEditing(false); setEditVersion(item.version) }
  }

  return (
    <div className={`bg-neutral-900 border rounded-lg px-4 py-3 transition-colors ${removing ? 'opacity-50 border-neutral-800' : 'border-neutral-800'}`}>
      <div className="flex items-center justify-between gap-3">
        {/* Left: name + version */}
        <div className="flex items-center gap-3 min-w-0">
          <span className="font-medium text-white truncate">{item.product_name}</span>

          {editing ? (
            <input
              autoFocus
              value={editVersion}
              onChange={e => setEditVersion(e.target.value)}
              onKeyDown={handleKeyDown}
              className="w-32 bg-neutral-800 border border-neutral-600 rounded px-2 py-0.5 text-sm font-mono text-white focus:outline-none focus:border-neutral-400"
            />
          ) : (
            <span className="font-mono text-sm text-neutral-400">{item.version}</span>
          )}

          {categoryStyle && (
            <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${categoryStyle.color}`}>
              {categoryStyle.label}
            </span>
          )}
        </div>

        {/* Right: action buttons */}
        <div className="flex items-center gap-2 shrink-0">
          {editing ? (
            <>
              <button
                onClick={handleSave}
                disabled={saving}
                className="text-xs text-white bg-neutral-700 hover:bg-neutral-600 px-2.5 py-1 rounded transition-colors disabled:opacity-50"
              >
                {saving ? 'Saving...' : 'Save'}
              </button>
              <button
                onClick={() => { setEditing(false); setEditVersion(item.version) }}
                className="text-xs text-neutral-500 hover:text-white transition-colors"
              >
                Cancel
              </button>
            </>
          ) : (
            <>
              <button
                onClick={() => setEditing(true)}
                disabled={removing}
                className="text-xs text-neutral-600 hover:text-neutral-300 transition-colors"
              >
                Edit version
              </button>
              <button
                onClick={handleRemove}
                disabled={removing}
                className="text-xs text-neutral-600 hover:text-red-400 transition-colors disabled:opacity-50"
              >
                {removing ? 'Removing...' : 'Remove'}
              </button>
            </>
          )}
        </div>
      </div>

      {error && <p className="mt-1.5 text-xs text-red-400">{error}</p>}
    </div>
  )
}
