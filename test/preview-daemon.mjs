/**
 * Preview launcher: starts the airlock daemon against a THROWAWAY data dir
 * (never the real %LOCALAPPDATA%\CredentialAirlock) for browser verification.
 */
import os from 'os';
import path from 'path';

process.env.AIRLOCK_HOME = path.join(os.tmpdir(), 'airlock-preview');
process.env.AIRLOCK_NO_OPEN = '1';
process.env.AIRLOCK_ADMIN_PORT = process.env.AIRLOCK_ADMIN_PORT || '7800';
process.env.AIRLOCK_PROXY_PORT = process.env.AIRLOCK_PROXY_PORT || '7788';
process.argv = [process.argv[0], 'airlock', 'start'];
await import('../dist/index.js');
