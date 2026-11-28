import { configDefaults, defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    // OSP-68: gerçek yerel Supabase isteyen entegrasyon testleri `npm test`te ÇALIŞMAZ;
    // yalnızca `npm run test:integration` (vitest.integration.config.ts) ile çalışır.
    exclude: [...configDefaults.exclude, 'tests/integration/**'],
    globals: false,
  },
});
