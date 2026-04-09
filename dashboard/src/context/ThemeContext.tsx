import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import { THEMES, DEFAULT_THEME, type ThemeName } from '../themes'

interface ThemeCtx {
  theme: ThemeName
  setTheme: (t: ThemeName) => void
}

const Ctx = createContext<ThemeCtx>({ theme: DEFAULT_THEME, setTheme: () => {} })

const STORAGE_KEY = 'corvus-theme'

function applyTheme(name: ThemeName) {
  const def = THEMES.find((t) => t.name === name)
  if (!def) return
  const root = document.documentElement
  for (const [key, val] of Object.entries(def.vars)) {
    root.style.setProperty(key, val)
  }
  root.dataset.theme = name
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<ThemeName>(() => {
    const stored = localStorage.getItem(STORAGE_KEY) as ThemeName | null
    return stored && THEMES.some((t) => t.name === stored) ? stored : DEFAULT_THEME
  })

  // Apply theme on mount and whenever it changes
  useEffect(() => {
    applyTheme(theme)
  }, [theme])

  const setTheme = (t: ThemeName) => {
    localStorage.setItem(STORAGE_KEY, t)
    setThemeState(t)
  }

  return <Ctx.Provider value={{ theme, setTheme }}>{children}</Ctx.Provider>
}

export const useTheme = () => useContext(Ctx)
