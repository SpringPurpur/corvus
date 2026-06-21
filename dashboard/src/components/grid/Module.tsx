import { useEffect, useRef, useState } from 'react'
import { G3, alpha } from './g3'
import { useGridCtx, ModuleSizeCtx, ROW_H, GAP } from './GridContainer'

export interface ModuleSize       { cols: number; rows: number }
export interface ModuleConstraint { min: ModuleSize; max: ModuleSize }

interface Props {
  id:             string
  title:          string
  subtitle?:      string
  about?:         string
  size:           ModuleSize
  constraint:     ModuleConstraint
  onResize:       (id: string, size: ModuleSize) => void
  onReorderStart: (id: string) => void
  onReorderOver:  (id: string) => void
  onReorderEnd:   () => void
  onRemove?:      () => void
  isDragTarget:   boolean
  isBeingDragged: boolean
  badge?:         React.ReactNode
  hot?:           boolean
  children:       React.ReactNode
}

export function Module({
  id, title, subtitle, about, size, constraint,
  onResize, onReorderStart, onReorderOver, onReorderEnd, onRemove,
  isDragTarget, isBeingDragged,
  badge, hot, children,
}: Props) {
  const { cellW }   = useGridCtx()
  const [resizing, setResizing]   = useState(false)
  const [menuOpen, setMenuOpen]   = useState(false)
  const [showAbout, setShowAbout] = useState(false)
  const bodyRef  = useRef<HTMLDivElement>(null)
  const menuRef  = useRef<HTMLDivElement>(null)
  const [bodySize, setBodySize]   = useState({ w: 400, h: 200 })

  useEffect(() => {
    if (!bodyRef.current) return
    const ro = new ResizeObserver(e => {
      const r = e[0].contentRect
      setBodySize({ w: r.width, h: r.height })
    })
    ro.observe(bodyRef.current)
    return () => ro.disconnect()
  }, [])

  // Close dropdown when clicking outside
  useEffect(() => {
    if (!menuOpen) return
    const handler = (e: MouseEvent) => {
      if (!menuRef.current?.contains(e.target as Node)) setMenuOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [menuOpen])

  const onResizeDown = (e: React.PointerEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setResizing(true)
    const startX = e.clientX
    const startY = e.clientY
    const start  = { ...size }
    const { min, max } = constraint
    const move = (ev: PointerEvent) => {
      const dx      = ev.clientX - startX
      const dy      = ev.clientY - startY
      const newCols = Math.max(min.cols, Math.min(max.cols, Math.round(start.cols + dx / (cellW + GAP))))
      const newRows = Math.max(min.rows, Math.min(max.rows, Math.round(start.rows + dy / (ROW_H + GAP))))
      onResize(id, { cols: newCols, rows: newRows })
    }
    const up = () => {
      setResizing(false)
      window.removeEventListener('pointermove', move)
      window.removeEventListener('pointerup', up)
    }
    window.addEventListener('pointermove', move)
    window.addEventListener('pointerup', up)
  }

  const onHeaderDown = (e: React.PointerEvent) => {
    if (e.button !== 0) return
    e.preventDefault()
    onReorderStart(id)
    const move = (ev: PointerEvent) => {
      const el    = document.elementFromPoint(ev.clientX, ev.clientY)
      const modEl = el?.closest('[data-module-id]') as HTMLElement | null
      if (modEl?.dataset.moduleId) onReorderOver(modEl.dataset.moduleId)
    }
    const up = () => {
      onReorderEnd()
      window.removeEventListener('pointermove', move)
      window.removeEventListener('pointerup', up)
    }
    window.addEventListener('pointermove', move)
    window.addEventListener('pointerup', up)
  }

  const borderColor = resizing || isBeingDragged ? G3.accent
    : isDragTarget ? G3.purple
    : G3.line

  const menuBtnStyle: React.CSSProperties = {
    background: 'transparent', border: 'none', cursor: 'pointer',
    color: G3.mute, fontSize: 15, lineHeight: 1, padding: '0 3px',
    borderRadius: 3, display: 'flex', alignItems: 'center',
  }
  const menuItemStyle: React.CSSProperties = {
    width: '100%', textAlign: 'left', padding: '7px 12px',
    fontSize: 11, background: 'transparent', border: 'none',
    cursor: 'pointer', display: 'block',
  }

  return (
    <div data-module-id={id} style={{
      gridColumn: `span ${size.cols}`,
      gridRow:    `span ${size.rows}`,
      background: G3.card,
      border:     `1px solid ${borderColor}`,
      borderRadius: 10,
      display: 'flex', flexDirection: 'column', overflow: 'hidden',
      position: 'relative', minHeight: 0, minWidth: 0,
      boxShadow: hot
        ? `0 0 0 1px ${alpha(G3.crit, 19)}`
        : isDragTarget ? `0 0 0 2px ${alpha(G3.purple, 33)}`
        : 'none',
      opacity:    isBeingDragged ? 0.55 : 1,
      transition: 'border-color 120ms, box-shadow 120ms, opacity 120ms',
    }}>
      {/* Header */}
      <div onPointerDown={onHeaderDown} style={{
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        padding: '8px 12px', borderBottom: `1px solid ${G3.line}`,
        background: G3.card,
        cursor:     isBeingDragged ? 'grabbing' : 'grab',
        flexShrink: 0, gap: 8, userSelect: 'none', touchAction: 'none',
      }}>
        <div style={{ minWidth: 0, flex: 1 }}>
          <div style={{ fontSize: 11, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6, overflow: 'hidden' }}>
            <span style={{ color: G3.mute, opacity: 0.6, fontSize: 10, letterSpacing: 2 }}>··</span>
            <span style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', color: G3.fg }}>{title}</span>
            {badge}
          </div>
          {subtitle && bodySize.w > 240 && (
            <div style={{ fontSize: 9, color: G3.mute, marginTop: 1, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
              {subtitle}
            </div>
          )}
        </div>

        {/* Size badge + ⋮ menu */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexShrink: 0 }}>
          <span style={{
            padding: '1px 5px', background: G3.card2, borderRadius: 3,
            fontSize: 9, color: G3.mute,
            fontFamily: 'JetBrains Mono, ui-monospace, monospace',
          }}>
            {size.cols}×{size.rows}
          </span>

          <div ref={menuRef} style={{ position: 'relative' }}>
            <button
              onPointerDown={e => e.stopPropagation()}
              onClick={e => { e.stopPropagation(); setMenuOpen(m => !m) }}
              style={menuBtnStyle}
              title="Module options"
            >
              ⋮
            </button>

            {menuOpen && (
              <div style={{
                position: 'absolute', right: 0, top: 'calc(100% + 4px)',
                background: G3.card2, border: `1px solid ${G3.line}`,
                borderRadius: 6, zIndex: 200, minWidth: 130,
                boxShadow: '0 4px 16px rgba(0,0,0,0.5)',
                overflow: 'hidden',
              }}>
                {about && (
                  <button
                    style={{ ...menuItemStyle, color: G3.mute2 }}
                    onClick={() => { setMenuOpen(false); setShowAbout(true) }}
                    onMouseEnter={e => (e.currentTarget.style.background = G3.card)}
                    onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                  >
                    About this module
                  </button>
                )}
                {onRemove && (
                  <>
                    {about && <div style={{ height: 1, background: G3.line, margin: '0 8px' }} />}
                    <button
                      style={{ ...menuItemStyle, color: G3.crit }}
                      onClick={() => { setMenuOpen(false); onRemove() }}
                      onMouseEnter={e => (e.currentTarget.style.background = G3.card)}
                      onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                    >
                      Remove from dashboard
                    </button>
                  </>
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Body */}
      <div ref={bodyRef} style={{ flex: 1, minHeight: 0, minWidth: 0, overflow: 'hidden', position: 'relative' }}>
        <ModuleSizeCtx.Provider value={bodySize}>
          {showAbout ? (
            <div style={{ padding: 16, height: '100%', overflow: 'auto', boxSizing: 'border-box', display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: G3.fg }}>{title}</div>
              <div style={{ fontSize: 11, color: G3.mute2, lineHeight: 1.7 }}>{about}</div>
              <button
                onClick={() => setShowAbout(false)}
                style={{
                  alignSelf: 'flex-start', padding: '5px 12px', fontSize: 10,
                  background: G3.card2, border: `1px solid ${G3.line}`,
                  borderRadius: 4, color: G3.mute2, cursor: 'pointer', marginTop: 4,
                }}
              >
                Close
              </button>
            </div>
          ) : children}
        </ModuleSizeCtx.Provider>
      </div>

      {/* Resize handle */}
      <div onPointerDown={onResizeDown} style={{
        position: 'absolute', right: 0, bottom: 0, width: 18, height: 18,
        cursor: 'nwse-resize', zIndex: 2,
      }}>
        <svg viewBox="0 0 16 16" style={{ position: 'absolute', right: 3, bottom: 3 }}>
          <path
            d="M15 6 L6 15 M15 10 L10 15 M15 14 L14 15"
            stroke={resizing ? G3.accent : G3.mute}
            strokeWidth="1" fill="none"
          />
        </svg>
      </div>
    </div>
  )
}
