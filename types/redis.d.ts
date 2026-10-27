/** Redis-backed shared state store for multi-instance Archx deployments. */
import type { ArchxStateStore } from './server.js';

export const REDIS_STATE_STORE_SCRIPTS: Readonly<Record<string, string>>;

export interface ArchxRedisClient {
  eval?: (...args: unknown[]) => Promise<unknown>;
  call?: (...args: unknown[]) => Promise<unknown>;
  sendCommand?: (args: string[]) => Promise<unknown>;
  [key: string]: unknown;
}

export function createRedisStateStore(options: {
  client: ArchxRedisClient;
  prefix?: string;
  clientFlavor?: 'auto' | 'ioredis' | 'node-redis' | 'generic';
  closeClient?: boolean;
}): ArchxStateStore;

export default createRedisStateStore;
