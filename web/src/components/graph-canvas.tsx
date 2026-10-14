import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { useCanvasSize } from "@/hooks/use-canvas-size"
import {
  forceCollide,
  forceLink,
  forceManyBody,
  forceSimulation,
  forceX,
  forceY,
  type Simulation,
} from "d3-force"
import { ZoomIn, ZoomOut, Maximize2, Target, Workflow, Network } from "lucide-react"
import type { Framework, GraphNode, GraphData } from "@/lib/types"

const BG = "#0e1620"
const FOCUS_ALPHA = 0.12
const HIT_PX = 14

interface LayoutNode {
  id: string
  group: Framework
  kind: string
  name: string
  x: number
  y: number
  fx: number | null
  fy: number | null
  vx?: number
  vy?: number
}

interface LayoutLink {
  id: string
  source: LayoutNode
  target: LayoutNode
  cross: boolean
}

export interface CanvasProps {
  graph: GraphData
  shownIds: Set<string>
  selectedIds: string[]
  pathNodes: Set<string>
  pathEdges: Set<string>
  expandedIds: Set<string>
  onSelect: (id: string | null, additive: boolean) => void
  onHover: (id: string | null) => void
  onExpand: (id: string) => void
}

const GROUP_COLOR: Record<string, string> = {
  CWE: "#0084d1",
  CAPEC: "#f59e0b",
  "ATT&CK": "#ef4444",
  ATTACK: "#ef4444",
  D3FEND: "#10b981",
  ATLAS: "#d946ef",
}

const SIDES: Record<string, number> = {
  CWE: 24,
  CAPEC: 4,
  "ATT&CK": 3,
  ATTACK: 3,
  D3FEND: 4,
  ATLAS: 6,
}

function shapePath(ctx: CanvasRenderingContext2D, n: LayoutNode, r: number, sides: number) {
  ctx.beginPath()
  if (sides === 4) {
    ctx.rect(n.x - r, n.y - r, r * 2, r * 2)
    return
  }
  if (sides === 3) {
    ctx.moveTo(n.x, n.y - r * 1.3)
    ctx.lineTo(n.x + r * 1.2, n.y + r * 0.9)
    ctx.lineTo(n.x - r * 1.2, n.y + r * 0.9)
    ctx.closePath()
    return
  }
  for (let i = 0; i < sides; i++) {
    const a = (Math.PI * 2 * i) / sides - Math.PI / 2
    const px = n.x + Math.cos(a) * r
    const py = n.y + Math.sin(a) * r
    i ? ctx.lineTo(px, py) : ctx.moveTo(px, py)
  }
  ctx.closePath()
}

function pseudoJitter(str: string, span: number) {
  let hash = 0
  for (let i = 0; i < str.length; i++) hash = (hash << 5) - hash + str.charCodeAt(i)
  return ((Math.abs(hash) % 1000) / 1000 - 0.5) * span
}

export function GraphCanvas(props: CanvasProps) {
  const {
    graph,
    shownIds,
    selectedIds,
    pathNodes,
    pathEdges,
    expandedIds,
    onSelect,
    onHover,
    onExpand,
  } = props

  const [layoutMode, setLayoutMode] = useState<"ontological" | "organic">("ontological")
  const wrapRef = useRef<HTMLDivElement>(null)
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const simRef = useRef<Simulation<LayoutNode, undefined> | null>(null)
  const viewRef = useRef({ x: 0, y: 0, k: 1 })
  const nodesRef = useRef<LayoutNode[]>([])
  const linksRef = useRef<LayoutLink[]>([])
  const degreesRef = useRef<Map<string, number>>(new Map())
  const focusRef = useRef<string[]>(selectedIds)
  const hoverRef = useRef<string | null>(null)
  const hasInitializedRef = useRef(false)
  const prevLayoutModeRef = useRef(layoutMode)
  const { w, h } = useCanvasSize(wrapRef)

  useEffect(() => {
    focusRef.current = selectedIds
  }, [selectedIds])

  const radius = useCallback((n: LayoutNode) => {
    const d = degreesRef.current.get(n.id) ?? 0
    return 6 + Math.min(Math.sqrt(d) * 2.3, 19)
  }, [])

  // Dynamic column spacing based on available screen width (spanning ~78% of width across 4 columns)
  const colSpacing = useMemo(() => {
    const safeW = w || 1400
    return Math.max(220, (safeW * 0.76) / 3)
  }, [w])

  const ontologicalTargets = useMemo<Record<string, number>>(() => {
    return {
      CWE: -colSpacing * 1.5,
      CAPEC: -colSpacing * 0.5,
      "ATT&CK": colSpacing * 0.5,
      ATTACK: colSpacing * 0.5,
      ATLAS: colSpacing * 0.5,
      D3FEND: colSpacing * 1.5,
    }
  }, [colSpacing])

  // --- layout generation ----------------------------------------------------
  const { nodes, links, degrees } = useMemo(() => {
    const byGroup: Record<string, GraphNode[]> = {}
    for (const n of graph.nodes) {
      if (shownIds.has(n.id)) {
        if (!byGroup[n.group]) byGroup[n.group] = []
        byGroup[n.group].push(n)
      }
    }

    const usableH = Math.max(380, (h || 700) * 0.74)
    const ns: LayoutNode[] = []

    for (const [group, groupNodes] of Object.entries(byGroup)) {
      const targetX = ontologicalTargets[group] ?? 0
      const total = groupNodes.length
      groupNodes.forEach((n, idx) => {
        const yRatio = total > 1 ? idx / (total - 1) - 0.5 : 0
        const existing = nodesRef.current.find((old) => old.id === n.id)
        if (existing) {
          ns.push({
            ...existing,
            group: n.group as Framework,
            kind: n.kind,
            name: n.name,
          })
        } else {
          ns.push({
            id: n.id,
            group: n.group as Framework,
            kind: n.kind,
            name: n.name,
            x: targetX + pseudoJitter(n.id + ":x", 36),
            y: yRatio * usableH + pseudoJitter(n.id + ":y", 20),
            fx: null,
            fy: null,
          })
        }
      })
    }

    const kept = new Set(ns.map((n) => n.id))
    const ls = graph.edges
      .filter((e) => kept.has(e.from) && kept.has(e.to))
      .map((e) => ({ id: e.id, source: e.from, target: e.to, cross: e.cross })) as unknown as LayoutLink[]

    const deg = new Map<string, number>()
    for (const e of graph.edges) {
      if (!kept.has(e.from) || !kept.has(e.to)) continue
      deg.set(e.from, (deg.get(e.from) ?? 0) + 1)
      deg.set(e.to, (deg.get(e.to) ?? 0) + 1)
    }

    return { nodes: ns, links: ls, degrees: deg }
  }, [graph, shownIds, ontologicalTargets, h])

  // --- Center & Fit View Helper ---------------------------------------------
  const fitView = useCallback(
    (nodesList?: LayoutNode[]) => {
      const list = nodesList || nodesRef.current
      if (!w || !h || !list.length) return

      const xs = list.map((n) => n.x).sort((a, b) => a - b)
      const ys = list.map((n) => n.y).sort((a, b) => a - b)

      const minX = xs[0]
      const maxX = xs[xs.length - 1]
      const minY = ys[0]
      const maxY = ys[ys.length - 1]

      const spanX = Math.max(maxX - minX, 350)
      const spanY = Math.max(maxY - minY, 280)

      // Fit to comfortably fill 88% of screen width and 82% of screen height
      const targetK = Math.min(
        1.8,
        Math.max(0.55, Math.min((w * 0.88) / spanX, (h * 0.82) / spanY)),
      )

      const centerX = (minX + maxX) / 2
      const centerY = (minY + maxY) / 2

      viewRef.current = {
        k: targetK,
        x: w / 2 - centerX * targetK,
        y: h / 2 - centerY * targetK,
      }
      console.log("[Jev-fitView]", { w, h, spanX, spanY, targetK, minX, maxX, minY, maxY, centerX, centerY, view: { ...viewRef.current } })
      window.dispatchEvent(new Event("jev:redraw"))
    },
    [w, h],
  )

  const centerSelection = useCallback(() => {
    const selId = focusRef.current[0]
    if (!selId) return
    const n = nodesRef.current.find((node) => node.id === selId)
    if (!n || !w || !h) return
    const k = Math.max(viewRef.current.k, 1.2)
    viewRef.current = {
      k,
      x: w / 2 - n.x * k,
      y: h / 2 - n.y * k,
    }
    window.dispatchEvent(new Event("jev:redraw"))
  }, [w, h])

  const zoomIn = useCallback(() => {
    if (!w || !h) return
    const v = viewRef.current
    const newK = Math.min(8, v.k * 1.35)
    v.x = w / 2 - ((w / 2 - v.x) / v.k) * newK
    v.y = h / 2 - ((h / 2 - v.y) / v.k) * newK
    v.k = newK
    window.dispatchEvent(new Event("jev:redraw"))
  }, [w, h])

  const zoomOut = useCallback(() => {
    if (!w || !h) return
    const v = viewRef.current
    const newK = Math.max(0.1, v.k / 1.35)
    v.x = w / 2 - ((w / 2 - v.x) / v.k) * newK
    v.y = h / 2 - ((h / 2 - v.y) / v.k) * newK
    v.k = newK
    window.dispatchEvent(new Event("jev:redraw"))
  }, [w, h])

  // --- simulation setup -----------------------------------------------------
  useEffect(() => {
    if (!w || !h || !nodes.length) return
    degreesRef.current = degrees

    const sim = forceSimulation<LayoutNode>(nodes)

    if (layoutMode === "ontological") {
      const usableH = Math.max(380, (h || 700) * 0.74)
      sim
        .force(
          "link",
          forceLink<LayoutNode, LayoutLink>(links)
            .id((d) => d.id)
            .distance(colSpacing * 0.75)
            .strength(0.04),
        )
        .force(
          "charge",
          forceManyBody<LayoutNode>()
            .strength(-45)
            .distanceMax(220),
        )
        .force(
          "collide",
          forceCollide<LayoutNode>().radius((d) => radius(d) + 7).strength(0.8),
        )
        .force(
          "x",
          forceX<LayoutNode>((d) => ontologicalTargets[d.group] ?? 0).strength(0.75),
        )
        .force("y", forceY<LayoutNode>(0).strength(0.02))
        .alphaDecay(0.03)
        .stop()

      const maxY = usableH * 0.52
      for (let i = 0; i < 140; i++) {
        sim.tick()
        for (const n of nodes) {
          if (n.y > maxY) n.y = maxY
          if (n.y < -maxY) n.y = -maxY
        }
      }
    } else {
      sim
        .force(
          "link",
          forceLink<LayoutNode, LayoutLink>(links)
            .id((d) => d.id)
            .distance(100)
            .strength(0.3),
        )
        .force(
          "charge",
          forceManyBody<LayoutNode>()
            .strength(-280)
            .distanceMax(800),
        )
        .force(
          "collide",
          forceCollide<LayoutNode>().radius((d) => radius(d) + 9),
        )
        .force("x", forceX<LayoutNode>(0).strength(0.015))
        .force("y", forceY<LayoutNode>(0).strength(0.015))
        .alphaDecay(0.025)
        .stop()

      for (let i = 0; i < 180; i++) sim.tick()
    }

    nodesRef.current = nodes
    linksRef.current = links
    simRef.current = sim

    if (!hasInitializedRef.current || prevLayoutModeRef.current !== layoutMode) {
      hasInitializedRef.current = true
      prevLayoutModeRef.current = layoutMode
      fitView(nodes)
    } else {
      window.dispatchEvent(new Event("jev:redraw"))
    }
    return () => {
      sim.stop()
    }
  }, [nodes, links, degrees, w, h, radius, layoutMode, fitView, ontologicalTargets, colSpacing])

  // --- canvas paint loop ----------------------------------------------------
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas || !w || !h) return
    const dpr = window.devicePixelRatio || 1
    canvas.width = Math.floor(w * dpr)
    canvas.height = Math.floor(h * dpr)
    canvas.style.width = `${w}px`
    canvas.style.height = `${h}px`
    const ctx = canvas.getContext("2d")!
    let frame = 0

    const draw = () => {
      cancelAnimationFrame(frame)
      frame = requestAnimationFrame(() => {
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
        ctx.fillStyle = BG
        ctx.fillRect(0, 0, w, h)

        const { x, y, k } = viewRef.current
        const ns = nodesRef.current
        const ls = linksRef.current
        const sel = focusRef.current
        const hov = hoverRef.current

        const anchor = hov || sel[0] || null
        let near: Set<string> | null = null
        if (anchor) {
          near = new Set([anchor])
          for (const l of ls) {
            if (l.source.id === anchor) near.add(l.target.id)
            if (l.target.id === anchor) near.add(l.source.id)
          }
        }

        ctx.save()
        ctx.translate(x, y)
        ctx.scale(k, k)

        // 1. Draw subtle background column guides in Ontological Mode
        if (layoutMode === "ontological") {
          const dividers = [-colSpacing, 0, colSpacing]
          ctx.strokeStyle = "rgba(43, 58, 77, 0.45)"
          ctx.lineWidth = 1 / k
          ctx.setLineDash([6, 6])
          for (const divX of dividers) {
            ctx.beginPath()
            ctx.moveTo(divX, -1200)
            ctx.lineTo(divX, 1200)
            ctx.stroke()
          }
          ctx.setLineDash([])

          const colBands = [
            { label: "1. CWE · FRAQUEZAS", x: -colSpacing * 1.5, color: "#0084d1" },
            { label: "2. CAPEC · ATAQUES", x: -colSpacing * 0.5, color: "#f59e0b" },
            { label: "3. ATT&CK / ATLAS · TTPs", x: colSpacing * 0.5, color: "#ef4444" },
            { label: "4. D3FEND · DEFESAS", x: colSpacing * 1.5, color: "#10b981" },
          ]

          const minYVal = ns.length ? Math.min(...ns.map((n) => n.y)) : -250
          const topY = Math.min(minYVal - 35, -180)

          ctx.font = "bold 11px system-ui, sans-serif"
          ctx.textAlign = "center"
          ctx.textBaseline = "middle"

          for (const band of colBands) {
            const textW = ctx.measureText(band.label).width
            const badgeW = textW + 18
            const badgeH = 22
            ctx.fillStyle = "rgba(14, 22, 32, 0.92)"
            ctx.strokeStyle = band.color
            ctx.lineWidth = 1.2 / k
            ctx.beginPath()
            ctx.roundRect(band.x - badgeW / 2, topY - badgeH / 2, badgeW, badgeH, 6)
            ctx.fill()
            ctx.stroke()

            ctx.fillStyle = band.color
            ctx.fillText(band.label, band.x, topY)
          }
        }

        // 2. Draw Edges
        // Intra-framework edges
        ctx.strokeStyle = "rgba(160, 180, 210, 0.16)"
        ctx.lineWidth = 0.85 / k
        ctx.beginPath()
        for (const l of ls) {
          if (l.cross) continue
          ctx.moveTo(l.source.x, l.source.y)
          ctx.lineTo(l.target.x, l.target.y)
        }
        ctx.stroke()

        // Cross-framework edges (higher visual importance)
        ctx.strokeStyle = "rgba(124, 196, 255, 0.45)"
        ctx.lineWidth = 1.3 / k
        ctx.beginPath()
        for (const l of ls) {
          if (!l.cross) continue
          ctx.moveTo(l.source.x, l.source.y)
          ctx.lineTo(l.target.x, l.target.y)
        }
        ctx.stroke()

        // Focused edges (connected to hovered or selected node)
        if (anchor) {
          ctx.strokeStyle = "rgba(255, 255, 255, 0.8)"
          ctx.lineWidth = 2.2 / k
          ctx.beginPath()
          for (const l of ls) {
            if (l.source.id === anchor || l.target.id === anchor) {
              ctx.moveTo(l.source.x, l.source.y)
              ctx.lineTo(l.target.x, l.target.y)
            }
          }
          ctx.stroke()
        }

        // Traced path edges (illuminated cyan)
        if (pathEdges.size) {
          ctx.strokeStyle = "#38bdf8"
          ctx.lineWidth = 3.2 / k
          ctx.shadowColor = "#38bdf8"
          ctx.shadowBlur = 10
          ctx.beginPath()
          for (const l of ls) {
            if (!pathEdges.has(l.id)) continue
            ctx.moveTo(l.source.x, l.source.y)
            ctx.lineTo(l.target.x, l.target.y)
          }
          ctx.stroke()
          ctx.shadowBlur = 0
        }

        // 3. Draw Nodes
        for (const n of ns) {
          const isSel = sel.includes(n.id)
          const isPath = pathNodes.has(n.id)
          const isExp = expandedIds.has(n.id)
          const isHov = n.id === hov
          const dim = near && !near.has(n.id) && !isPath
          const r = radius(n)

          ctx.globalAlpha = dim ? FOCUS_ALPHA : 1
          ctx.fillStyle = GROUP_COLOR[n.group] ?? "#64748b"

          shapePath(ctx, n, r, SIDES[n.group] ?? 24)
          ctx.fill()

          ctx.strokeStyle = "rgba(255, 255, 255, 0.3)"
          ctx.lineWidth = 1.0 / k
          ctx.stroke()

          if (isSel || isHov || isExp || isPath) {
            ctx.beginPath()
            ctx.arc(n.x, n.y, r + 4 / k, 0, 2 * Math.PI)
            ctx.strokeStyle = isPath
              ? "#38bdf8"
              : isSel
                ? "#ffffff"
                : isHov
                  ? "rgba(255, 255, 255, 0.85)"
                  : "rgba(245, 158, 11, 0.9)"
            ctx.lineWidth = (isSel || isPath ? 2.5 : 1.6) / k
            if (isSel || isPath) {
              ctx.shadowColor = isPath ? "#38bdf8" : "#ffffff"
              ctx.shadowBlur = 12
            }
            ctx.stroke()
            ctx.shadowBlur = 0
          }
        }

        ctx.restore()
        ctx.globalAlpha = 1

        drawLabels(ctx, ns, degreesRef.current, viewRef.current, near, sel, pathNodes, hov)
      })
    }

    const onResize = () => draw()
    window.addEventListener("jev:redraw", draw)
    window.addEventListener("resize", onResize)
    draw()
    return () => {
      window.removeEventListener("jev:redraw", draw)
      window.removeEventListener("resize", onResize)
      cancelAnimationFrame(frame)
    }
  }, [w, h, selectedIds, pathNodes, pathEdges, expandedIds, radius, layoutMode, colSpacing])

  // --- interaction ----------------------------------------------------------
  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    const view = () => viewRef.current
    const toGraph = (ev: PointerEvent | MouseEvent) => {
      const r = canvas.getBoundingClientRect()
      const v = view()
      return { x: (ev.clientX - r.left - v.x) / v.k, y: (ev.clientY - r.top - v.y) / v.k }
    }

    const hit = (ev: PointerEvent | MouseEvent) => {
      const p = toGraph(ev)
      const v = view()
      let best: LayoutNode | null = null
      let bestD = Infinity
      for (const n of nodesRef.current) {
        const r = radius(n) + HIT_PX / v.k
        const d = (n.x - p.x) ** 2 + (n.y - p.y) ** 2
        if (d < r * r && d < bestD) {
          best = n
          bestD = d
        }
      }
      return best
    }

    let panning = false
    let draggingNode: LayoutNode | null = null
    let moved = 0
    let last = { x: 0, y: 0 }
    let downAt = 0

    const onDown = (ev: PointerEvent) => {
      const n = hit(ev)
      moved = 0
      downAt = performance.now()
      last = { x: ev.clientX, y: ev.clientY }
      if (n) {
        draggingNode = n
        canvas.style.cursor = "grabbing"
      } else {
        panning = true
      }
      try {
        canvas.setPointerCapture(ev.pointerId)
      } catch {
        /* no-op */
      }
    }

    const onMove = (ev: PointerEvent) => {
      if (draggingNode) {
        moved += Math.abs(ev.clientX - last.x) + Math.abs(ev.clientY - last.y)
        const p = toGraph(ev)
        draggingNode.fx = p.x
        draggingNode.fy = p.y
        last = { x: ev.clientX, y: ev.clientY }
        simRef.current?.alpha(0.18).restart()
        window.dispatchEvent(new Event("jev:redraw"))
        return
      }
      if (panning) {
        const dx = ev.clientX - last.x
        const dy = ev.clientY - last.y
        moved += Math.abs(dx) + Math.abs(dy)
        const v = view()
        v.x += dx
        v.y += dy
        last = { x: ev.clientX, y: ev.clientY }
        window.dispatchEvent(new Event("jev:redraw"))
        return
      }
      const n = hit(ev)
      const id = n ? n.id : null
      canvas.style.cursor = n ? "pointer" : "grab"
      if (id !== hoverRef.current) {
        hoverRef.current = id
        window.dispatchEvent(new Event("jev:redraw"))
        onHover(id)
      }
    }

    const onUp = (ev: PointerEvent) => {
      const grabbedNode = draggingNode
      panning = false
      draggingNode = null
      canvas.style.cursor = "grab"
      try {
        canvas.releasePointerCapture(ev.pointerId)
      } catch {
        /* no-op */
      }
      if (grabbedNode) {
        grabbedNode.fx = null
        grabbedNode.fy = null
        if (moved <= 12) {
          onSelect(grabbedNode.id, ev.shiftKey || ev.metaKey || ev.ctrlKey)
          if (ev.altKey) onExpand(grabbedNode.id)
        }
        return
      }
      if (moved <= 12) {
        const n = hit(ev)
        onSelect(n ? n.id : null, ev.shiftKey || ev.metaKey || ev.ctrlKey)
        if (n && ev.altKey) onExpand(n.id)
      }
    }

    const onDblClick = (ev: MouseEvent) => {
      const n = hit(ev)
      if (n) {
        onExpand(n.id)
      } else {
        fitView()
      }
    }

    const onLeave = () => {
      if (hoverRef.current) {
        hoverRef.current = null
        onHover(null)
      }
    }

    const onWheel = (ev: WheelEvent) => {
      ev.preventDefault()
      const r = canvas.getBoundingClientRect()
      const mx = ev.clientX - r.left
      const my = ev.clientY - r.top
      const v = view()
      const k = Math.min(10, Math.max(0.1, v.k * Math.exp(-ev.deltaY * 0.0015)))
      v.x = mx - ((mx - v.x) / v.k) * k
      v.y = my - ((my - v.y) / v.k) * k
      v.k = k
      window.dispatchEvent(new Event("jev:redraw"))
    }

    canvas.addEventListener("pointerdown", onDown)
    canvas.addEventListener("pointermove", onMove)
    canvas.addEventListener("pointerup", onUp)
    canvas.addEventListener("pointerleave", onLeave)
    canvas.addEventListener("dblclick", onDblClick)
    canvas.addEventListener("wheel", onWheel, { passive: false })
    return () => {
      canvas.removeEventListener("pointerdown", onDown)
      canvas.removeEventListener("pointermove", onMove)
      canvas.removeEventListener("pointerup", onUp)
      canvas.removeEventListener("pointerleave", onLeave)
      canvas.removeEventListener("dblclick", onDblClick)
      canvas.removeEventListener("wheel", onWheel)
    }
  }, [w, h, onSelect, onHover, onExpand, radius])

  return (
    <div ref={wrapRef} className="relative h-full w-full overflow-hidden select-none">
      <canvas
        ref={canvasRef}
        role="img"
        tabIndex={0}
        className="block touch-none"
        aria-label={`Knowledge graph of ${nodes.length} entities.`}
      />

      {/* Floating Canvas Controls Toolbar */}
      <div className="absolute top-3 right-3 flex items-center gap-2 z-20">
        <div className="flex items-center gap-1 rounded-xl bg-card/90 backdrop-blur border border-border p-1 shadow-lg">
          <button
            type="button"
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
              layoutMode === "ontological"
                ? "bg-primary text-primary-foreground shadow-sm"
                : "text-muted-foreground hover:text-foreground hover:bg-popover"
            }`}
            onClick={() => setLayoutMode("ontological")}
            title="Alinha nós pelo ciclo causal: CWE ➔ CAPEC ➔ ATT&CK ➔ D3FEND"
          >
            <Workflow className="w-3.5 h-3.5" />
            <span>Fluxo Ontológico</span>
          </button>
          <button
            type="button"
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
              layoutMode === "organic"
                ? "bg-primary text-primary-foreground shadow-sm"
                : "text-muted-foreground hover:text-foreground hover:bg-popover"
            }`}
            onClick={() => setLayoutMode("organic")}
            title="Dispersão orgânica livre via Force-Directed"
          >
            <Network className="w-3.5 h-3.5" />
            <span>Rede Orgânica</span>
          </button>
        </div>

        <div className="flex items-center gap-1 rounded-xl bg-card/90 backdrop-blur border border-border p-1 shadow-lg">
          <button
            type="button"
            className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-popover transition-colors cursor-pointer"
            onClick={zoomIn}
            title="Aproximar Zoom (+)"
          >
            <ZoomIn className="w-4 h-4" />
          </button>
          <button
            type="button"
            className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-popover transition-colors cursor-pointer"
            onClick={zoomOut}
            title="Afastar Zoom (-)"
          >
            <ZoomOut className="w-4 h-4" />
          </button>
          <div className="w-px h-4 bg-border my-auto" />
          <button
            type="button"
            className="p-1.5 rounded-lg text-muted-foreground hover:text-foreground hover:bg-popover transition-colors cursor-pointer"
            onClick={() => fitView()}
            title="Enquadrar Grafo no Ecrã"
          >
            <Maximize2 className="w-4 h-4" />
          </button>
          {selectedIds.length > 0 && (
            <button
              type="button"
              className="p-1.5 rounded-lg text-primary hover:bg-primary/20 transition-colors cursor-pointer"
              onClick={centerSelection}
              title="Centralizar no Nó Selecionado"
            >
              <Target className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>

      {/* Floating Status Pill on Top-Left */}
      <div className="pointer-events-none absolute top-3 left-3 z-10 flex items-center gap-2 rounded-full border border-border/80 bg-card/85 backdrop-blur px-3 py-1 text-xs text-muted-foreground shadow-sm">
        <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
        <span>
          {layoutMode === "ontological"
            ? "CWE ➔ CAPEC ➔ ATT&CK / ATLAS ➔ D3FEND"
            : "Rede Semântica Force-Directed"}
        </span>
      </div>
    </div>
  )
}

function drawLabels(
  ctx: CanvasRenderingContext2D,
  nodes: LayoutNode[],
  degrees: Map<string, number>,
  view: { x: number; y: number; k: number },
  near: Set<string> | null,
  selected: string[],
  pathNodes: Set<string>,
  hoveredId: string | null,
) {
  const { x, y, k } = view
  const dpr = window.devicePixelRatio || 1

  ctx.save()
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
  ctx.font = "600 11px system-ui, sans-serif"
  ctx.textBaseline = "middle"

  const priorityNodes = nodes.filter(
    (n) => selected.includes(n.id) || pathNodes.has(n.id) || n.id === hoveredId || (near && near.has(n.id)),
  )

  const rankedOthers = nodes
    .filter((n) => !priorityNodes.includes(n))
    .sort((a, b) => (degrees.get(b.id) ?? 0) - (degrees.get(a.id) ?? 0))
    .slice(0, 45)

  const nodesToLabel = [...priorityNodes, ...rankedOthers]
  const placed: number[][] = []

  for (const n of nodesToLabel) {
    const isSpecial = selected.includes(n.id) || pathNodes.has(n.id) || n.id === hoveredId
    const deg = degrees.get(n.id) ?? 0
    const r = 6 + Math.min(Math.sqrt(deg) * 2.3, 19)

    const sx = n.x * k + x
    const sy = n.y * k + y - (r * k + 10)

    if (sx < -80 || sx > ctx.canvas.width / dpr + 80 || sy < -40 || sy > ctx.canvas.height / dpr + 40) {
      continue
    }

    const text = n.id
    const textWidth = ctx.measureText(text).width
    const boxW = textWidth + 12
    const boxH = 18
    const boxX = sx - boxW / 2
    const boxY = sy - boxH / 2

    const clash = placed.some(
      (p) => !(boxX > p[0] + p[2] || boxX + boxW < p[0] || boxY > p[1] + p[3] || boxY + boxH < p[1]),
    )

    if (clash && !isSpecial) continue
    placed.push([boxX, boxY, boxW, boxH])

    ctx.beginPath()
    ctx.roundRect(boxX, boxY, boxW, boxH, 4)

    if (isSpecial) {
      ctx.fillStyle = "rgba(14, 22, 32, 0.95)"
      ctx.strokeStyle = pathNodes.has(n.id) ? "#38bdf8" : "#ffffff"
      ctx.lineWidth = 1.5
    } else {
      ctx.fillStyle = "rgba(14, 22, 32, 0.88)"
      ctx.strokeStyle = "rgba(255, 255, 255, 0.16)"
      ctx.lineWidth = 1
    }

    ctx.fill()
    ctx.stroke()

    ctx.textAlign = "center"
    ctx.fillStyle = isSpecial ? "#ffffff" : "#cbd5e1"
    ctx.fillText(text, sx, sy)
  }

  ctx.restore()
}