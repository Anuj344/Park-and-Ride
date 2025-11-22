// frontend/lib/api.ts
import useSWR, { KeyedMutator } from 'swr'

const API_URL = process.env.NEXT_PUBLIC_API_URL
if (!API_URL) {
  throw new Error('NEXT_PUBLIC_API_URL is not defined')
}

// ---------------- Types ----------------

export type BookingIn = {
  start: string  // ISO format
  hours: number
  days: number
  months: number
  plate: string
}

export type BookingOut = {
  slot: { row: number; col: number }
  start: string
  end: string
  qr: string
}

export type CancelIn = {
  row: number
  col: number
  start: string
  end: string
  plate: string
}

// A single slot in a lot, matching your page code
export type Slot = {
  slot_id: string
  occupied: boolean
}

// A parking lot object, as returned by your backend
export type Lot = {
  _id: string
  name: string
  slots: Slot[]
  // add any other fields your API returns here
}

// ---------------- Shared Fetcher ----------------

async function fetcher<T = any>([url, token]: [string, string]): Promise<T> {
  const res = await fetch(url, {
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
  })

  if (!res.ok) {
    const msg = await res.text()
    throw new Error(msg)
  }
  return res.json()
}

// ---------------- useLots Hook ----------------
// Fetch all lots for the current user
export function useLots(
  token: string | null
): {
  lots?: Lot[]
  isLoading: boolean
  isError?: Error
  mutate: KeyedMutator<Lot[]>
} {
  const key = token ? ([`${API_URL}/lots`, token] as const) : null
  const { data, error, mutate } = useSWR<Lot[]>(key, fetcher)
  return {
    lots: data,
    isLoading: !error && !data,
    isError: error as Error | undefined,
    mutate: mutate as KeyedMutator<Lot[]>,
  }
}

// ---------------- useOccupancy Hook ----------------

export function useOccupancy(
  at: string,
  token: string | null
): {
  occupancy?: { occupied: number; total: number }
  isLoading: boolean
  isError?: Error
  mutate: KeyedMutator<{ occupied: number; total: number }>
} {
  const key = token
    ? ([`${API_URL}/occupancy?at=${encodeURIComponent(at)}`, token] as const)
    : null
  const { data, error, mutate } = useSWR(key, fetcher)
  return {
    occupancy: data,
    isLoading: !error && !data,
    isError: error as Error | undefined,
    mutate: mutate as KeyedMutator<{ occupied: number; total: number }>,
  }
}

// ---------------- Book a Spot ----------------

export async function bookSpot(
  token: string,
  booking: BookingIn
): Promise<BookingOut> {
  const res = await fetch(`${API_URL}/book`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(booking),
  })
  const isJson = res.headers.get('Content-Type')?.includes('application/json')
  if (!res.ok) {
    const err = isJson ? await res.json() : { detail: await res.text() }
    throw new Error(err.detail || 'Booking failed')
  }
  return res.json()
}

// ---------------- Cancel a Spot ----------------

export async function cancelSpot(
  token: string,
  payload: CancelIn
): Promise<{ message: string }> {
  const res = await fetch(`${API_URL}/cancel`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(payload),
  })
  const isJson = res.headers.get('Content-Type')?.includes('application/json')
  if (!res.ok) {
    const err = isJson ? await res.json() : { detail: await res.text() }
    throw new Error(err.detail || 'Cancellation failed')
  }
  return res.json()
}