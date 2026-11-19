import { app } from './app.js';
import { env } from './config/env.js';

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
