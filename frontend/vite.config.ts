// frontend/vite.config.ts
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const backendTarget =
  (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env?.VITE_DEV_API_TARGET ||
  'http://127.0.0.1:8000'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [
    react(),
    // NO @tailwindcss/vite plugin here for Tailwind CSS v3
  ],
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes('node_modules')) return;

          if (id.includes('recharts') || id.includes('d3-')) {
            return 'vendor-charts';
          }
          if (id.includes('axios') || id.includes('zustand') || id.includes('date-fns')) {
            return 'vendor-data';
          }

          return 'vendor-core';
        },
      },
    },
  },
  server: {
    allowedHosts: true,
    proxy: {
      '/api': {
        target: backendTarget,
        changeOrigin: true,
        ws: true,
      },
      '/health': {
        target: backendTarget,
        changeOrigin: true,
      },
    },
  },
  // Optional: If Vite has trouble finding postcss.config.cjs, you might explicitly define it,
  // but usually, it picks it up automatically if named correctly (postcss.config.cjs or postcss.config.js).
  // css: {
  //   postcss: './postcss.config.cjs' // Or './postcss.config.js' if you didn't rename
  // }
})
