import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    // Forward API calls to the FastAPI backend during development so the
    // frontend can use same-origin relative URLs (no CORS juggling).
    proxy: {
      // Backend default port. Override with `uvicorn --port N` + this value
      // if 8000 is already in use on your machine.
      '/api': 'http://localhost:8000',
    },
  },
})
