// frontend/pages/book/[lotId].tsx

import { useRouter } from 'next/router'
import { useEffect, useState } from 'react'
import { useLots, Lot } from '../../lib/api'

interface BookPageProps {
  lotId: string
}

export default function BookPage({ lotId }: BookPageProps) {
  const router = useRouter()
  const [mounted, setMounted] = useState(false)
  const [token, setToken] = useState<string | null>(null)

  // On mount, grab token and redirect if missing
  useEffect(() => {
    setMounted(true)
    const t = localStorage.getItem('token')
    setToken(t)
    if (!t) {
      router.replace('/login')
    }
  }, [router])

  // only pass token into the hook once we're mounted
  const { lots, isLoading, isError } = useLots(mounted ? token : null)

  if (!mounted) return null
  if (!token) return null           // we’ll redirect to /login
  if (isLoading) return <p>Loading lots…</p>
  if (isError) return <p style={{ color: 'red' }}>{isError.message}</p>
  if (!lots || lots.length === 0) return <p>No lots available</p>

  // Find our lot
  const lot = lots.find(l => l._id === lotId)
  if (!lot) return <p>Lot not found</p>

  // Filter free slots
  const freeSlots = lot.slots.filter(s => !s.occupied)

  // Booking handler
  async function book(slotId: string) {
    if (!token || !lot) return
    try {
      const res = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL}/api/bookings`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({ lot_id: lot._id, slot_id: slotId }),
        }
      )
      const data = await res.json().catch(() => null)
      if (!res.ok) {
        alert('Booking failed: ' + (data?.message || res.statusText))
      } else {
        alert('Booked!')
        router.push('/dashboard')
      }
    } catch {
      alert('An error occurred during booking.')
    }
  }

  return (
    <div style={{ maxWidth: 600, margin: '2rem auto', fontFamily: 'sans-serif' }}>
      <h1>Book a Slot in {lot.name}</h1>
      {freeSlots.length === 0 ? (
        <p>Sorry, no free slots right now.</p>
      ) : (
        <ul>
          {freeSlots.map(s => (
            <li key={s.slot_id} style={{ marginBottom: '.5rem' }}>
              Slot <strong>{s.slot_id}</strong>{' '}
              <button onClick={() => book(s.slot_id)}>Book</button>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

// Pull lotId from the URL on the server
export async function getServerSideProps(ctx: {
  params?: { lotId?: string }
}) {
  return {
    props: {
      lotId: ctx.params?.lotId ?? '',
    },
  }
}