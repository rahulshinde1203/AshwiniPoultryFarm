import { EventEmitter } from 'events';

// Global singleton — survives hot-reload in dev; single process in prod
const globalForSync = global as unknown as { _syncEmitter: EventEmitter };

if (!globalForSync._syncEmitter) {
  globalForSync._syncEmitter = new EventEmitter();
  globalForSync._syncEmitter.setMaxListeners(200);
}

export const syncEmitter = globalForSync._syncEmitter;

export type SyncEvent = 'purchase' | 'payment' | 'expense';

/** Call this after any successful DB write that should push to connected clients */
export function emitSync(type: SyncEvent) {
  syncEmitter.emit('sync', type);
}
