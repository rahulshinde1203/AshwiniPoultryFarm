import { NextRequest } from 'next/server';
import { requireAuth } from '@/lib/auth/middleware';
import { syncEmitter } from '@/lib/sync-emitter';

// Force Node.js runtime (EventEmitter is not available in Edge)
export const runtime = 'nodejs';

export async function GET(req: NextRequest) {
  const { error } = await requireAuth(['admin', 'accountant', 'salesperson']);
  if (error) return error;

  let listener: ((type: string) => void) | null = null;

  const stream = new ReadableStream({
    start(controller) {
      const enc = new TextEncoder();

      // Send a heartbeat comment every 20s to keep connection alive through proxies
      const heartbeat = setInterval(() => {
        try { controller.enqueue(enc.encode(': ping\n\n')); } catch { /* closed */ }
      }, 20_000);

      listener = (type: string) => {
        try {
          controller.enqueue(enc.encode(`data: ${JSON.stringify({ type })}\n\n`));
        } catch { /* client disconnected */ }
      };

      syncEmitter.on('sync', listener);

      req.signal.addEventListener('abort', () => {
        clearInterval(heartbeat);
        if (listener) syncEmitter.off('sync', listener);
        try { controller.close(); } catch { /* already closed */ }
      });
    },
    cancel() {
      if (listener) syncEmitter.off('sync', listener);
    },
  });

  return new Response(stream, {
    headers: {
      'Content-Type':  'text/event-stream',
      'Cache-Control': 'no-cache, no-transform',
      'Connection':    'keep-alive',
      'X-Accel-Buffering': 'no', // disable Nginx buffering
    },
  });
}
