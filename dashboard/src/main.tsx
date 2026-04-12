import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'

// ── API key injection ─────────────────────────────────────────────────────────
// When CORVUS_API_KEY is set on the server, every API call must carry
// X-API-Key. We intercept window.fetch globally so every existing call site
// gets the header automatically without any per-call changes.
// The key is stored in sessionStorage — it persists across navigation but is
// cleared when the tab closes, which is the right security boundary for a
// local analyst tool.
;(function patchFetch() {
  const _native = window.fetch.bind(window)
  window.fetch = (input, init?) => {
    const key = sessionStorage.getItem('corvus_api_key')
    if (!key) return _native(input, init)
    const headers = new Headers((init as RequestInit | undefined)?.headers)
    headers.set('X-API-Key', key)
    return _native(input, { ...(init as RequestInit | undefined), headers })
  }
})()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
