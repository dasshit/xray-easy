import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      onwarn(warning, warn) {
        const source = warning.id?.replaceAll('\\', '/')
        const isZodCommentAnnotation = warning.code === 'INVALID_ANNOTATION'
          && source?.includes('/node_modules/zod/v4/core/') === true
          && (warning.message.includes('Wrapped in a `@__PURE__` IIFE')
            || warning.message.includes('Anchors a pattern source.'))

        // Zod's explanatory comments mention @__PURE__; Rollup mistakes the prose for an annotation.
        if (isZodCommentAnnotation) return

        warn(warning)
      },
    },
  },
  test: {
    environment: 'jsdom',
    pool: 'vmThreads',
    fsModuleCache: true,
    include: ['src/**/*.{test,spec}.{ts,tsx}', 'test/**/*.{test,spec}.{ts,tsx}'],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.{ts,vue}'],
      exclude: ['src/**/*.test.ts', 'src/**/*.spec.ts'],
      reporter: ['text', 'html', 'lcov'],
      reportsDirectory: './coverage',
      skipFull: false,
      thresholds: {
        statements: 90,
        lines: 90,
        branches: 85,
        functions: 90,
        perFile: { lines: 90 },
      },
    },
  },
})
