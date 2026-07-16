import React from 'react'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const mockUseUser = vi.fn()
const mockUseSWR = vi.fn()
const mockStackAdd = vi.fn()
const mockSettingsUpdate = vi.fn()
const mockAuthLogout = vi.fn()
const mockMarkDashboardVisited = vi.fn()
const mockRouter = {
  query: {} as Record<string, string>,
  push: vi.fn(),
  replace: vi.fn(),
}

vi.mock('next/head', () => ({
  default: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}))

vi.mock('next/link', () => ({
  default: ({ href, children, ...props }: { href: string; children: React.ReactNode }) => (
    <a href={href} {...props}>{children}</a>
  ),
}))

vi.mock('next/router', () => ({
  useRouter: () => mockRouter,
}))

vi.mock('swr', () => ({
  default: (...args: unknown[]) => mockUseSWR(...args),
}))

vi.mock('@/lib/auth', () => ({
  useUser: (...args: unknown[]) => mockUseUser(...args),
}))

vi.mock('@/components/Layout', () => ({
  Layout: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}))

vi.mock('@/components/ProductSearch', () => ({
  ProductSearch: ({ onSelect }: { onSelect: (product: unknown) => void }) => (
    <button
      type="button"
      onClick={() => onSelect({
        id: 'product-1',
        display_name: 'Nginx',
        vendor: 'nginx',
        cpe_product: 'nginx',
        category: 'web_server',
        popular: true,
      })}
    >
      Pick mock product
    </button>
  ),
}))

vi.mock('@/components/StackItemCard', () => ({
  StackItemCard: () => <div>Stack item card</div>,
}))

vi.mock('@/lib/api', () => ({
  auth: {
    logout: (...args: unknown[]) => mockAuthLogout(...args),
  },
  cves: {
    list: vi.fn(),
    get: vi.fn(),
    markSeen: vi.fn(),
    dismiss: vi.fn(),
  },
  products: {
    popular: vi.fn(),
    search: vi.fn(),
  },
  settings: {
    get: vi.fn(),
    update: (...args: unknown[]) => mockSettingsUpdate(...args),
    deleteAccount: vi.fn(),
  },
  stack: {
    list: vi.fn(),
    add: (...args: unknown[]) => mockStackAdd(...args),
    updateVersion: vi.fn(),
    remove: vi.fn(),
  },
  stats: {
    get: vi.fn(),
    markDashboardVisited: (...args: unknown[]) => mockMarkDashboardVisited(...args),
  },
}))

import DashboardPage from '@/pages/dashboard'
import LoginPage from '@/pages/login'
import SettingsPage from '@/pages/settings'
import StackPage from '@/pages/stack'

describe('frontend smoke flows', () => {
  beforeEach(() => {
    mockUseUser.mockReset()
    mockUseSWR.mockReset()
    mockStackAdd.mockReset()
    mockSettingsUpdate.mockReset()
    mockAuthLogout.mockReset()
    mockMarkDashboardVisited.mockReset()
    mockRouter.query = {}
    mockRouter.push.mockReset()
    mockRouter.replace.mockReset()
    vi.unstubAllGlobals()
  })

  it('renders the login flow and shows the dev magic link state', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      json: async () => ({ dev_link: 'http://example.test/sign-in' }),
    }))

    render(<LoginPage />)

    fireEvent.change(screen.getByPlaceholderText('you@example.com'), {
      target: { value: 'user@example.com' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Send sign-in link' }))

    await screen.findByText('Dev mode — click to sign in')
    expect(screen.getByText('Sign in as user@example.com →')).toBeInTheDocument()
  })

  it('runs the stack add flow and surfaces matching feedback', async () => {
    mockUseUser.mockReturnValue({
      user: { id: 'user-1', email: 'user@example.com', daily_digest: true, instant_alerts: true },
    })
    mockUseSWR.mockImplementation((key: unknown) => {
      if (key === '/api/stack') {
        return { data: [], isLoading: false, mutate: vi.fn() }
      }
      if (key === '/api/products/popular') {
        return {
          data: [{ id: 'product-1', display_name: 'Nginx', vendor: 'nginx', cpe_product: 'nginx', category: 'web_server', popular: true }],
          isLoading: false,
        }
      }
      return { data: undefined, isLoading: false, mutate: vi.fn() }
    })
    mockStackAdd.mockResolvedValue({
      id: 'stack-1',
      product_name: 'Nginx',
      vendor: 'nginx',
      cpe_product: 'nginx',
      version: '1.24.0',
      cpe_string: 'cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*',
      category: 'web_server',
      added_at: '2026-04-06T10:00:00Z',
      matching_queued: true,
      matching_message: 'Saved successfully. CVE matching is now running in the background. Your dashboard should start updating shortly.',
    })

    render(<StackPage />)

    fireEvent.click(screen.getByRole('button', { name: 'Pick mock product' }))
    fireEvent.change(screen.getByPlaceholderText('Version (e.g. 1.24.0)'), {
      target: { value: '1.24.0' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Add' }))

    await screen.findByText(/CVE matching is now running in the background/i)
  })

  it('renders the dashboard with a stack summary and CVE list', async () => {
    mockUseUser.mockReturnValue({
      user: { id: 'user-1', email: 'user@example.com', daily_digest: true, instant_alerts: true },
      isLoading: false,
    })
    mockMarkDashboardVisited.mockResolvedValue({ ok: true, last_seen_at: '2026-04-06T10:00:00Z' })
    mockUseSWR.mockImplementation((key: unknown) => {
      if (key === '/api/stack') {
        return {
          data: [{
            id: 'stack-1',
            product_name: 'Nginx',
            vendor: 'nginx',
            cpe_product: 'nginx',
            version: '1.24.0',
            cpe_string: 'cpe',
            category: 'web_server',
            added_at: '2026-04-06T10:00:00Z',
          }],
          isLoading: false,
          mutate: vi.fn(),
        }
      }
      if (Array.isArray(key) && key[0] === 'cves') {
        return {
          data: {
            items: [{
              cve_id: 'CVE-2026-1111',
              description: 'Important nginx issue',
              cvss_vector: null,
              cvss_score: 9.1,
              epss_score: 0.54,
              kev_flag: true,
              kev_date_added: '2026-04-05',
              published_at: '2026-04-04T12:00:00Z',
              severity: 'Critical',
              priority_score: 92,
              matched_at: '2026-04-06T10:00:00Z',
              seen_at: null,
              dismissed: false,
              primary_product_name: 'Nginx',
              product_names: ['Nginx'],
              product_count: 1,
            }],
            page: 1,
            per_page: 12,
            total_items: 1,
            total_pages: 1,
            sort_by: 'priority',
          },
          isLoading: false,
          mutate: vi.fn(),
        }
      }
      if (key === '/api/stats') {
        return {
          data: {
            total_cves: 1,
            critical_count: 1,
            kev_count: 1,
            new_since_last_visit: 1,
          },
          isLoading: false,
          mutate: vi.fn(),
        }
      }
      return { data: undefined, isLoading: false, mutate: vi.fn() }
    })

    render(<DashboardPage />)

    expect(screen.getByText('Your CVEs')).toBeInTheDocument()
    expect(screen.getByText('Stack summary')).toBeInTheDocument()
    expect(screen.getByText('CVE-2026-1111')).toBeInTheDocument()
  })

  it('updates a settings toggle and shows success feedback', async () => {
    mockUseUser.mockReturnValue({
      user: { id: 'user-1', email: 'user@example.com', daily_digest: true, instant_alerts: true },
      mutate: vi.fn(),
    })
    mockUseSWR.mockImplementation((key: unknown) => {
      if (key === 'settings') {
        return {
          data: { daily_digest: true, instant_alerts: true },
          isLoading: false,
          mutate: vi.fn(),
        }
      }
      return { data: undefined, isLoading: false, mutate: vi.fn() }
    })
    mockSettingsUpdate.mockResolvedValue({ daily_digest: false, instant_alerts: true })

    render(<SettingsPage />)

    fireEvent.click(screen.getAllByRole('button')[0])

    await waitFor(() => {
      expect(screen.getByText('Daily digest preference updated.')).toBeInTheDocument()
    })
  })
})
