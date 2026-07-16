/** @type {import('next').NextConfig} */

const securityHeaders = [
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'X-XSS-Protection', value: '1; mode=block' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' },
  // Prevent the browser from following cross-origin redirects that embed credentials
  {
    key: 'Content-Security-Policy',
    value: [
      "default-src 'self'",
      // Next.js Pages Router needs unsafe-inline for inline styles/scripts
      "script-src 'self' 'unsafe-eval' 'unsafe-inline'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data: blob:",
      // Allow API calls back to our own origin only
      "connect-src 'self'",
      "font-src 'self'",
      "frame-ancestors 'none'",
      // External links (NVD, CISA, advisories) open in new tabs — no embedding
      "frame-src 'none'",
    ].join('; '),
  },
]

const nextConfig = {
  reactStrictMode: true,
  output: 'standalone',
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: securityHeaders,
      },
    ]
  },
  // Proxy /api/* to FastAPI backend.
  // INTERNAL_API_URL must be set in your environment:
  //   Docker:       http://api:8000
  //   DirectAdmin:  https://api.yourdomain.com   (your Python/Passenger subdomain)
  //   Local dev:    http://localhost:8000
  async rewrites() {
    if (!process.env.INTERNAL_API_URL) {
      throw new Error('INTERNAL_API_URL is not set. Set it to your backend URL (e.g. https://api.yourdomain.com)')
    }
    return [
      {
        source: '/api/:path*',
        destination: `${process.env.INTERNAL_API_URL}/api/:path*`,
      },
    ]
  },
}

module.exports = nextConfig
