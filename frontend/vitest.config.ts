import { defineConfig } from 'vitest/config'

// Configuration de test distincte de vite.config.ts : jsdom + JSX automatique via esbuild.
export default defineConfig({
  esbuild: { jsx: 'automatic' },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    css: false,
  },
})
