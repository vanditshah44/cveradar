import { useEffect, useState } from 'react'
import type { AppProps } from 'next/app'
import { Rajdhani, JetBrains_Mono } from 'next/font/google'
import '@/styles/globals.css'

const rajdhani = Rajdhani({
  weight: ['400', '500', '600', '700'],
  subsets: ['latin'],
  variable: '--font-rajdhani',
  display: 'swap',
})

const jetbrainsMono = JetBrains_Mono({
  weight: ['400', '500', '700'],
  subsets: ['latin'],
  variable: '--font-mono',
  display: 'swap',
})

function MaintenancePage() {
  return (
    <div style={{
      background: '#0a0a0a', color: '#a3a3a3', minHeight: '100vh',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      fontFamily: 'ui-sans-serif, system-ui, -apple-system, sans-serif',
      padding: '2rem',
    }}>
      <div style={{ maxWidth: 440, width: '100%', textAlign: 'center' }}>
        <div style={{
          width: 64, height: 64, borderRadius: 16, background: '#1a1a1a',
          border: '1px solid #262626', display: 'inline-flex',
          alignItems: 'center', justifyContent: 'center', marginBottom: '1.5rem',
        }}>
          <svg width="28" height="28" fill="none" viewBox="0 0 24 24"
            stroke="#525252" strokeWidth="1.5">
            <path strokeLinecap="round" strokeLinejoin="round"
              d="M20.25 6.375c0 2.278-3.694 4.125-8.25 4.125S3.75 8.653 3.75 6.375m16.5 0c0-2.278-3.694-4.125-8.25-4.125S3.75 4.097 3.75 6.375m16.5 0v11.25c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125V6.375m16.5 5.625c0 2.278-3.694 4.125-8.25 4.125s-8.25-1.847-8.25-4.125" />
          </svg>
        </div>
        <p style={{ fontSize: '0.75rem', fontWeight: 600, letterSpacing: '0.15em',
          textTransform: 'uppercase', color: '#525252', marginBottom: '0.5rem' }}>
          CVE Radar
        </p>
        <h1 style={{ fontSize: '1.5rem', fontWeight: 600, color: '#e5e5e5',
          marginBottom: '0.75rem' }}>
          Temporarily Offline
        </h1>
        <p style={{ fontSize: '0.9375rem', lineHeight: 1.6, color: '#737373',
          marginBottom: '1.5rem' }}>
          The database is currently unreachable.<br />
          We&apos;ll be back online shortly.
        </p>
        <div style={{ height: 1, background: '#1f1f1f', margin: '1.5rem 0' }} />
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem',
          fontSize: '0.8125rem', color: '#525252', justifyContent: 'center' }}>
          <span style={{
            width: 6, height: 6, borderRadius: '50%', background: '#737373',
            display: 'inline-block', animation: 'pulse 2s ease-in-out infinite',
          }} />
          Reconnecting…
        </div>
        <p style={{ marginTop: '2.5rem', fontSize: '0.75rem', color: '#404040' }}>
          Try refreshing in a few minutes.
        </p>
      </div>
      <style>{`@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}`}</style>
    </div>
  )
}

export default function App({ Component, pageProps }: AppProps) {
  const [maintenance, setMaintenance] = useState(false)

  useEffect(() => {
    const handler = () => setMaintenance(true)
    window.addEventListener('cveradar:maintenance', handler)
    return () => window.removeEventListener('cveradar:maintenance', handler)
  }, [])

  if (maintenance) return <MaintenancePage />

  return (
    <div className={`${rajdhani.variable} ${jetbrainsMono.variable}`}>
      <Component {...pageProps} />
    </div>
  )
}
