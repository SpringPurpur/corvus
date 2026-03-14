import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    // During development, proxy /ws to the inference engine so the browser
    // can connect to the WebSocket without CORS restrictions
    proxy: {
      '/ws': { target: 'ws://localhost:8765', ws: true },
    },
  },
})
