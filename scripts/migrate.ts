import { loadConfig } from '../src/config.js';
import { PostgresStore } from '../src/db/client.js';
import { createLogger } from '../src/logger.js';

async function main(): Promise<void> {
  const config = loadConfig({ ...process.env, LOCAL_SANDBOX_MODE: 'true' });
  if (!config.database.url) {
    console.error('Error: DATABASE_URL must be set to run Postgres migrations.');
    process.exit(1);
  }
  const log = createLogger(config.logLevel);
  const store = new PostgresStore(config.database.url, config.database.ssl, log);
  await store.init();
  const ok = await store.ping();
  await store.close();
  if (!ok) {
    console.error('Database ping failed after migration.');
    process.exit(1);
  }
  console.log('SpriteGuard Neon Postgres + pgvector migration succeeded.');
}

void main();
