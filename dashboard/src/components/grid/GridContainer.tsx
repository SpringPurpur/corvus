import { createContext, useContext, useEffect, useRef, useState } from 'react'
import { G3 } from './g3'

export const COLS  = 12
export const ROW_H = 84
export const GAP   = 10

interface GridCtxValue { cellW: number }
const GridCtx = createContext<GridCtxValue>({ cellW: 100 })
export const useGridCtx = () => useContext(GridCtx)

interface ModuleSizeCtxValue { w: number; h: number }
const ModuleSizeCtx = createContext<ModuleSizeCtxValue>({ w: 400, h: 200 })
export const useModuleSize = () => useContext(ModuleSizeCtx)
export { ModuleSizeCtx }

export function GridContainer({ children }: { children: React.ReactNode }) {
  const ref = useRef<HTMLDivElement>(null)
  const [cellW, setCellW] = useState(100)

  useEffect(() => {
    if (!ref.current) return
    const ro = new ResizeObserver(entries => {
      const w = entries[0].contentRect.width
      setCellW((w - GAP * (COLS - 1)) / COLS)
    })
    ro.observe(ref.current)
    return () => ro.disconnect()
  }, [])

  return (
    <GridCtx.Provider value={{ cellW }}>
      <div ref={ref} style={{
        display: 'grid',
        gridTemplateColumns: `repeat(${COLS}, 1fr)`,
        gridAutoRows: `${ROW_H}px`,
        gap: GAP,
        minWidth: 0,
        background: G3.bg,
      }}>
        {children}
      </div>
    </GridCtx.Provider>
  )
}