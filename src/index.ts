import { app } from './app.js';
import { env } from './config/env.js';

// In production behind Render, TRUST_PROXY must be >= 1; otherwise every request looks
// like plain HTTP and is rejected with 426 HTTPS_REQUIRED.
if (env.NODE_ENV === 'production' && env.TRUST_PROXY === 0) {
  console.warn(
    '[connect-backend] WARNING: NODE_ENV=production but TRUST_PROXY=0. Behind Render set TRUST_PROXY=1, or every request will be rejected with 426.',
  );
}

const server = app.listen(env.PORT, () => {
  console.log(
    `[connect-backend] Server listening on port ${env.PORT} (${env.NODE_ENV} mode)`,
  );
});

process.on('SIGTERM', () => {
  server.close(() => {
    process.exit(0);
  });
});
