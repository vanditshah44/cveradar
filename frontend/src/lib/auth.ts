/**
 * auth.ts — Auth context and hooks.
 *
 * useUser() — get the current user, redirect to /login if not authenticated
 */
import { useRouter } from 'next/router'
import { useEffect } from 'react'
import useSWR from 'swr'
import { auth, type User } from './api'

export function useUser(options: { redirectIfUnauthenticated?: boolean } = {}) {
  const router = useRouter()
  const { data: user, error, isLoading, mutate } = useSWR<User>(
    '/api/auth/me',
    auth.me,
    {
      revalidateOnFocus: true,
      revalidateOnMount: true,
      shouldRetryOnError: false,
    }
  )

  useEffect(() => {
    if (!isLoading && !user && options.redirectIfUnauthenticated !== false) {
      router.replace('/login')
    }
  }, [user, isLoading, options.redirectIfUnauthenticated, router])

  return { user, isLoading, isError: !!error, mutate }
}
