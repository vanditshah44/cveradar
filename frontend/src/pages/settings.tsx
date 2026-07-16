import Head from 'next/head'
import { useEffect, useState } from 'react'
import useSWR from 'swr'
import { settings as settingsApi, auth } from '@/lib/api'
import { useUser } from '@/lib/auth'
import { Layout } from '@/components/Layout'
import { useRouter } from 'next/router'

type NoticeState = {
  tone: 'success' | 'error'
  message: string
}

export default function SettingsPage() {
  const { user, mutate: mutateUser } = useUser()
  const router = useRouter()
  const { data, mutate, isLoading } = useSWR(
    user ? 'settings' : null,
    settingsApi.get,
    { revalidateOnFocus: false }
  )
  const [saving, setSaving] = useState(false)
  const [signOutConfirm, setSignOutConfirm] = useState(false)
  const [deleteConfirm, setDeleteConfirm] = useState(false)
  const [deletePhrase, setDeletePhrase] = useState('')
  const [deleting, setDeleting] = useState(false)
  const [signingOut, setSigningOut] = useState(false)
  const [notice, setNotice] = useState<NoticeState | null>(null)

  useEffect(() => {
    if (!data || !user) return
    if (data.daily_digest === user.daily_digest && data.instant_alerts === user.instant_alerts) {
      return
    }

    void mutateUser(current => current ? {
      ...current,
      daily_digest: data.daily_digest,
      instant_alerts: data.instant_alerts,
    } : current, { revalidate: false })
  }, [data, mutateUser, user])

  const handleToggle = async (key: 'daily_digest' | 'instant_alerts') => {
    if (!data) return

    const updated = { ...data, [key]: !data[key] }
    setSaving(true)
    setNotice(null)

    mutate(updated, { revalidate: false })
    void mutateUser(current => current ? { ...current, ...updated } : current, { revalidate: false })

    try {
      const serverState = await settingsApi.update(updated)
      await mutate(serverState, { revalidate: false })
      await mutateUser(current => current ? { ...current, ...serverState } : current, { revalidate: false })
      setNotice({
        tone: 'success',
        message: `${key === 'daily_digest' ? 'Daily digest' : 'Instant KEV alerts'} preference updated.`,
      })
    } catch (err) {
      await mutate()
      await mutateUser()
      setNotice({
        tone: 'error',
        message: err instanceof Error ? err.message : 'Could not update your notification preferences.',
      })
    } finally {
      setSaving(false)
    }
  }

  const handleSignOut = async () => {
    setSigningOut(true)
    setNotice(null)

    try {
      await auth.logout()
      await mutateUser(undefined, { revalidate: false })
      await router.push('/login?signed_out=1')
    } catch (err) {
      setNotice({
        tone: 'error',
        message: err instanceof Error ? err.message : 'Could not sign you out right now.',
      })
      setSigningOut(false)
    }
  }

  const handleDeleteAccount = async () => {
    setDeleting(true)
    setNotice(null)

    try {
      await settingsApi.deleteAccount()
      await mutate(undefined, { revalidate: false })
      await mutateUser(undefined, { revalidate: false })
      await router.push('/login?account_deleted=1')
    } catch (err) {
      setNotice({
        tone: 'error',
        message: err instanceof Error ? err.message : 'Could not delete your account right now.',
      })
      setDeleting(false)
    }
  }

  return (
    <Layout>
      <Head><title>Settings — CVE Radar</title></Head>
      <div className="max-w-lg">
        <h1 className="text-xl font-semibold text-white mb-6">Settings</h1>

        {notice && (
          <div
            className={`mb-4 rounded-lg border px-4 py-3 text-sm ${
              notice.tone === 'success'
                ? 'border-emerald-800 bg-emerald-500/10 text-emerald-200'
                : 'border-red-900 bg-red-500/10 text-red-200'
            }`}
          >
            {notice.message}
          </div>
        )}

        <div className="bg-neutral-900 border border-neutral-800 rounded-lg divide-y divide-neutral-800">
          {/* Notifications */}
          <div className="p-4">
            <h2 className="text-sm font-medium text-white mb-4">Notifications</h2>
            <div className="space-y-4">
              {[
                { key: 'daily_digest' as const, label: 'Daily digest', desc: 'Morning summary of new CVEs affecting your stack' },
                { key: 'instant_alerts' as const, label: 'Instant KEV alerts', desc: 'Immediate email when a CVE is added to CISA KEV and affects you' },
              ].map(({ key, label, desc }) => (
                <div key={key} className="flex items-center justify-between">
                  <div>
                    <p className="text-sm text-white">{label}</p>
                    <p className="text-xs text-neutral-500 mt-0.5">{desc}</p>
                  </div>
                  <button
                    onClick={() => handleToggle(key)}
                    disabled={saving || !data || isLoading}
                    aria-pressed={Boolean(data?.[key])}
                    className={`relative w-10 h-6 rounded-full transition-colors disabled:cursor-not-allowed disabled:opacity-60 ${data?.[key] ? 'bg-white' : 'bg-neutral-700'}`}
                  >
                    <span className={`absolute top-1 left-1 w-4 h-4 rounded-full transition-transform ${data?.[key] ? 'bg-black translate-x-4' : 'bg-neutral-400'}`} />
                  </button>
                </div>
              ))}
            </div>
            <p className="mt-4 text-xs text-neutral-500">
              {saving ? 'Saving your notification preferences…' : 'Changes are saved to your account immediately.'}
            </p>
          </div>

          {/* Account */}
          <div className="p-4">
            <h2 className="text-sm font-medium text-white mb-1">Account</h2>
            <p className="text-xs text-neutral-500 mb-3">{user?.email}</p>
            <div className="space-y-5">
              <div className="rounded-lg border border-neutral-800 bg-neutral-950 p-4">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <p className="text-sm text-white">Sign out</p>
                    <p className="mt-1 text-xs text-neutral-500">End your session on this browser without changing your saved data.</p>
                  </div>
                  {!signOutConfirm ? (
                    <button
                      onClick={() => {
                        setSignOutConfirm(true)
                        setDeleteConfirm(false)
                      }}
                      className="text-xs text-neutral-300 hover:text-white transition-colors"
                    >
                      Sign out
                    </button>
                  ) : (
                    <div className="flex items-center gap-2">
                      <button
                        onClick={handleSignOut}
                        disabled={signingOut}
                        className="rounded bg-white px-3 py-1.5 text-xs text-black disabled:cursor-not-allowed disabled:opacity-60"
                      >
                        {signingOut ? 'Signing out…' : 'Confirm'}
                      </button>
                      <button
                        onClick={() => setSignOutConfirm(false)}
                        className="text-xs text-neutral-500 hover:text-white transition-colors"
                      >
                        Cancel
                      </button>
                    </div>
                  )}
                </div>
                {signOutConfirm && (
                  <p className="mt-3 text-xs text-neutral-400">
                    You will be signed out from this browser and sent back to the login page.
                  </p>
                )}
              </div>

              <div className="rounded-lg border border-red-950 bg-red-500/5 p-4">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <p className="text-sm text-white">Delete account</p>
                    <p className="mt-1 text-xs text-neutral-400">
                      This permanently removes your account, stack items, CVE matches, and notification history.
                    </p>
                  </div>
                  {!deleteConfirm && (
                    <button
                      onClick={() => {
                        setDeleteConfirm(true)
                        setSignOutConfirm(false)
                        setDeletePhrase('')
                      }}
                      className="text-xs text-red-400 hover:text-red-300 transition-colors"
                    >
                      Delete account
                    </button>
                  )}
                </div>

                {deleteConfirm && (
                  <div className="mt-4 space-y-3">
                    <p className="text-xs text-red-300">
                      Type <span className="font-mono">DELETE</span> to confirm permanent account deletion.
                    </p>
                    <input
                      type="text"
                      value={deletePhrase}
                      onChange={e => setDeletePhrase(e.target.value)}
                      placeholder="Type DELETE"
                      className="w-full rounded-lg border border-red-900 bg-neutral-950 px-3 py-2 text-sm text-neutral-200 placeholder-neutral-600 focus:outline-none focus:border-red-700"
                    />
                    <div className="flex items-center gap-2">
                      <button
                        onClick={handleDeleteAccount}
                        disabled={deleting || deletePhrase.trim() !== 'DELETE'}
                        className="rounded bg-red-600 px-3 py-1.5 text-xs text-white disabled:cursor-not-allowed disabled:opacity-50"
                      >
                        {deleting ? 'Deleting…' : 'Permanently delete'}
                      </button>
                      <button
                        onClick={() => {
                          setDeleteConfirm(false)
                          setDeletePhrase('')
                        }}
                        className="text-xs text-neutral-500 hover:text-white transition-colors"
                      >
                        Cancel
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </Layout>
  )
}
