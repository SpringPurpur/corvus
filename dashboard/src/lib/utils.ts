import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'

export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs))
}

export function apiFetch(input: string, init?: RequestInit): Promise<Response> {
  const key = sessionStorage.getItem('corvus_api_key')
  if (!key) return fetch(input, init)
  const headers = new Headers(init?.headers)
  headers.set('X-API-Key', key)
  return fetch(input, { ...init, headers })
}
