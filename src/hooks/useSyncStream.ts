'use client';
import { useEffect, useRef } from 'react';

/**
 * Connects to the SSE sync stream.
 * When the server emits an event whose type is in `watchTypes`, calls `onSync()`.
 * Auto-reconnects silently on disconnect. Zero visible effect for the user.
 *
 * @param watchTypes  e.g. ['purchase', 'payment']
 * @param onSync      The data-reload function of the current page/component
 */
export function useSyncStream(watchTypes: string[], onSync: () => void) {
  // Keep a stable ref so we never need to recreate the EventSource when onSync changes
  const onSyncRef = useRef(onSync);
  useEffect(() => { onSyncRef.current = onSync; }, [onSync]);

  const typesRef = useRef(watchTypes);
  useEffect(() => { typesRef.current = watchTypes; }, [watchTypes]);

  useEffect(() => {
    let es: EventSource | null = null;
    let retryTimer: ReturnType<typeof setTimeout> | null = null;
    let destroyed = false;

    function connect() {
      if (destroyed) return;
      es = new EventSource('/api/sync/stream');

      es.onmessage = (e) => {
        try {
          const { type } = JSON.parse(e.data) as { type: string };
          if (typesRef.current.includes(type)) {
            onSyncRef.current();
          }
        } catch { /* ignore malformed frame */ }
      };

      es.onerror = () => {
        es?.close();
        es = null;
        if (!destroyed) {
          // Back-off: reconnect after 3 s
          retryTimer = setTimeout(connect, 3000);
        }
      };
    }

    connect();

    return () => {
      destroyed = true;
      if (retryTimer) clearTimeout(retryTimer);
      es?.close();
    };
  }, []); // run once on mount — refs handle the rest
}
