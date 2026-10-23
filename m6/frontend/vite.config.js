import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  return {
    plugins: [react()],
    // Frontend tests run against a live Flask API on :5001 (start it first: python backend/run.py).
    test: { environment: 'jsdom', env: { VITE_API_BASE_URL: 'http://127.0.0.1:5001/api/v1' } },
    server: {
      port: 5173,
      // In development, /api/... is forwarded to Flask, so no CORS setup is needed.
      proxy: {
        '/api': { target: env.VITE_DEV_API_TARGET || 'http://127.0.0.1:5001', changeOrigin: true },
      },
    },
  }
})
