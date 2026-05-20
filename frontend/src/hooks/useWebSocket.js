import { useRef, useCallback } from 'react'

const MAX_RETRIES = 8
const BASE_DELAY = 1000
const MAX_DELAY = 30000

/**
 * Custom React hook for managing a WebSocket connection.
 * Includes auto-reconnect with exponential backoff on abnormal close.
 *
 * Usage:
 *   const { connect, disconnect } = useWebSocket(onMessage)
 *   connect('ws://localhost:8000/ws/scan-id')
 *   disconnect()
 */
export default function useWebSocket(onMessage) {
  const wsRef = useRef(null)
  const onMessageRef = useRef(onMessage)
  const retriesRef = useRef(0)
  const reconnectTimerRef = useRef(null)
  const intentionalCloseRef = useRef(false)
  // Keep ref up-to-date without triggering reconnect
  onMessageRef.current = onMessage

  const connect = useCallback((url) => {
    // Clear any pending reconnect timer
    if (reconnectTimerRef.current) {
      clearTimeout(reconnectTimerRef.current)
      reconnectTimerRef.current = null
    }
    intentionalCloseRef.current = false

    // Close existing connection if any
    if (wsRef.current) {
      const prev = wsRef.current
      if (prev.readyState === WebSocket.OPEN || prev.readyState === WebSocket.CONNECTING) {
        intentionalCloseRef.current = true
        prev.close()
      }
    }

    let ws
    try {
      ws = new WebSocket(url)
    } catch (err) {
      console.error('[WS] Failed to create WebSocket:', err)
      return
    }

    ws.addEventListener('open', () => {
      console.log('[WS] Connected:', url)
      retriesRef.current = 0
    })

    ws.addEventListener('message', (event) => {
      try {
        const msg = JSON.parse(event.data)
        // Respond to server-side keepalive pings so 20s timeout resets
        if (msg.type === 'ping') {
          try { ws.send(JSON.stringify({ type: 'pong' })) } catch {}
          return
        }
        onMessageRef.current(msg)
      } catch {
        // Non-JSON frame — ignore
      }
    })

    ws.addEventListener('error', (err) => {
      console.error('[WS] Socket error:', err)
    })

    ws.addEventListener('close', (event) => {
      console.log(`[WS] Closed (code=${event.code}, clean=${event.wasClean})`)
      // Auto-reconnect on abnormal close (not intentional disconnect)
      if (!intentionalCloseRef.current && !event.wasClean && retriesRef.current < MAX_RETRIES) {
        const delay = Math.min(BASE_DELAY * Math.pow(2, retriesRef.current), MAX_DELAY)
        console.log(`[WS] Reconnecting in ${delay}ms (attempt ${retriesRef.current + 1}/${MAX_RETRIES})`)
        reconnectTimerRef.current = setTimeout(() => {
          retriesRef.current++
          connect(url)
        }, delay)
      }
    })

    wsRef.current = ws
  }, [])

  const disconnect = useCallback(() => {
    intentionalCloseRef.current = true
    if (reconnectTimerRef.current) {
      clearTimeout(reconnectTimerRef.current)
      reconnectTimerRef.current = null
    }
    if (wsRef.current) {
      wsRef.current.close(1000, 'Client disconnect')
      wsRef.current = null
    }
  }, [])

  return { connect, disconnect }
}
