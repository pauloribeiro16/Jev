import { useCallback, useMemo, useRef, useState } from "react"
import { GraphCanvas } from "@/components/graph-canvas"
import { InspectorPanel } from "@/components/inspector-panel"
import { GraphControls } from "@/components/graph-controls"
import { useGraph } from "@/hooks/use-graph"
import { useUrlState } from "@/hooks/use-url-state"
import { searchNodes } from "@/lib/graph"
import { BUDGETS, DEFAULT_BUDGET } from "@/config/constants"
import { X, Sparkles } from "lucide-react"

/** Full-screen immersive graph explorer with balanced ontological sampling and floating drawer inspector. */
export default function GraphPage() {
  const [nodeParam, setNodeParam] = useUrlState("node", "")
  const [from, setFrom] = useUrlState("from", "")
  const [to, setTo] = useUrlState("to", "")
  const [budgetParam, setBudgetParam] = useUrlState("n", String(DEFAULT_BUDGET))
  const [query, setQuery] = useUrlState("q", "")
  const budget = Number(budgetParam)

  const g = useGraph({ pathFrom: from || null, pathTo: to || null })
  const [hoverId, setHoverId] = useState<string | null>(null)

  const { graph } = g
  const selectedIds = useMemo(() => nodeParam.split(",").filter(Boolean), [nodeParam])

  const handleSelect = useCallback(
    (id: string | null, additive = false) => {
      if (!id) {
        setNodeParam(null)
        return
      }
      if (additive) {
        const next = selectedIds.includes(id)
          ? selectedIds.filter((x) => x !== id)
          : [...selectedIds, id]
        setNodeParam(next.length ? next.join(",") : null)
      } else {
        setNodeParam(id)
      }
    },
    [selectedIds, setNodeParam],
  )

  // Balanced framework sampling with guaranteed cross-framework bridges so the 4 columns
  // (CWE -> CAPEC -> ATT&CK -> D3FEND) form continuous causal webs spanning the entire screen
  const shownIds = useMemo(() => {
    if (!graph) return new Set<string>()
    const enabled = g.enabledFrameworks
    if (!enabled.size) return new Set<string>()

    const perFw = Math.max(4, Math.floor(budget / enabled.size))
    const ids = new Set<string>()

    // Cross-framework edges between adjacent pairs
    const capecToAtt = graph.edges.filter((e) => {
      const s = graph.byId.get(e.from)
      const t = graph.byId.get(e.to)
      return s?.group === "CAPEC" && t?.group === "ATT&CK"
    })

    const cweToCapec = graph.edges.filter((e) => {
      const s = graph.byId.get(e.from)
      const t = graph.byId.get(e.to)
      return s?.group === "CWE" && t?.group === "CAPEC"
    })

    const attToD3f = graph.edges.filter((e) => {
      const s = graph.byId.get(e.from)
      const t = graph.byId.get(e.to)
      return s?.group === "ATT&CK" && t?.group === "D3FEND"
    })

    // Seed bridge 2: CAPEC -> ATT&CK
    const bridgeCapecs = new Set<string>()
    const bridgeAtts = new Set<string>()
    for (const e of capecToAtt.slice(0, Math.min(25, perFw))) {
      if (enabled.has("CAPEC")) {
        ids.add(e.from)
        bridgeCapecs.add(e.from)
      }
      if (enabled.has("ATT&CK")) {
        ids.add(e.to)
        bridgeAtts.add(e.to)
      }
    }

    // Seed bridge 1: CWE -> CAPEC (preferring links to already selected CAPECs)
    let cweCount = 0
    for (const e of cweToCapec) {
      if (!enabled.has("CWE")) break
      if (bridgeCapecs.has(e.to)) {
        ids.add(e.from)
        cweCount++
        if (cweCount >= perFw) break
      }
    }

    // Seed bridge 3: ATT&CK -> D3FEND (preferring links from already selected ATT&CKs)
    let d3fCount = 0
    for (const e of attToD3f) {
      if (!enabled.has("D3FEND")) break
      if (bridgeAtts.has(e.from)) {
        ids.add(e.to)
        d3fCount++
        if (d3fCount >= perFw) break
      }
    }

    // Backfill each framework to meet the budget using crossDegree + degree
    const crossDegree = new Map<string, number>()
    for (const e of graph.edges) {
      if (e.cross) {
        crossDegree.set(e.from, (crossDegree.get(e.from) ?? 0) + 1)
        crossDegree.set(e.to, (crossDegree.get(e.to) ?? 0) + 1)
      }
    }

    for (const fw of enabled) {
      const fwNodes = graph.nodes
        .filter((n) => n.group === fw)
        .sort((a, b) => {
          const crossA = crossDegree.get(a.id) ?? 0
          const crossB = crossDegree.get(b.id) ?? 0
          if (crossB !== crossA) return crossB - crossA
          return (
            (graph.degrees.get(b.id) ?? 0) - (graph.degrees.get(a.id) ?? 0) ||
            a.id.localeCompare(b.id)
          )
        })

      for (const n of fwNodes) {
        const count = Array.from(ids).filter((id) => graph.byId.get(id)?.group === fw).length
        if (count >= perFw) break
        ids.add(n.id)
      }
    }

    for (const id of g.expanded) {
      ids.add(id)
      for (const nb of g.neighbours(id)) ids.add(nb.id)
    }
    for (const id of selectedIds) ids.add(id)
    for (const id of g.pathNodes) ids.add(id)
    if (from) ids.add(from)
    if (to) ids.add(to)
    return ids
  }, [graph, g.enabledFrameworks, budget, g.expanded, g, selectedIds, g.pathNodes, from, to])

  const prevShownIdsRef = useRef<Set<string>>(new Set())
  const stableShownIds = useMemo(() => {
    const prev = prevShownIdsRef.current
    if (prev.size === shownIds.size) {
      let same = true
      for (const id of shownIds) {
        if (!prev.has(id)) {
          same = false
          break
        }
      }
      if (same) return prev
    }
    prevShownIdsRef.current = shownIds
    return shownIds
  }, [shownIds])

  const canvasGraph = useMemo(
    () => (graph ? { ...graph, edges: g.allowedEdges } : null),
    [graph, g.allowedEdges],
  )

  const hits = useMemo(() => (graph ? searchNodes(graph.nodes, query) : []), [graph, query])
  const counts = useMemo(() => {
    const c: Record<string, number> = {}
    for (const n of graph?.nodes ?? []) c[n.group] = (c[n.group] ?? 0) + 1
    return c
  }, [graph])

  if (g.error) {
    return (
      <div className="space-y-4 p-6">
        <header>
          <h1 className="text-xl font-semibold">Grafo</h1>
        </header>
        <p className="text-sm text-muted-foreground">{g.error.message}</p>
        <p className="text-sm text-muted-foreground">
          Os dados são gerados: corre <code>scripts/fetch_official_data.py</code> e{" "}
          <code>scripts/export_canonical_graph.py</code>.
        </p>
      </div>
    )
  }

  if (!graph || !canvasGraph) {
    return (
      <div className="space-y-4 p-6">
        <header>
          <h1 className="text-xl font-semibold">Grafo</h1>
          <p className="text-sm text-muted-foreground">A carregar as ontologias…</p>
        </header>
        <div className="h-[75vh] animate-pulse rounded-lg border bg-muted/30" />
      </div>
    )
  }

  const selected = selectedIds.length === 1 ? graph.byId.get(selectedIds[0]) ?? null : null
  const neighbours = selected ? g.neighbours(selected.id) : []

  return (
    <div className="flex h-full w-full flex-col overflow-hidden relative">
      {/* Sleek, compact top control bar */}
      <div className="flex flex-col gap-2 border-b border-border bg-card/90 backdrop-blur px-4 py-2.5 z-20 shrink-0">
        <div className="flex flex-wrap items-center justify-between gap-3">
          {/* Controls & Frameworks */}
          <div className="flex flex-wrap items-center gap-2 flex-1 min-w-0">
            <GraphControls
              query={query}
              onQuery={setQuery}
              onPick={(id) => {
                handleSelect(id, false)
                setQuery(null)
              }}
              hits={hits}
              counts={counts}
              enabled={g.enabledFrameworks}
              onToggleFramework={g.toggleFramework}
              onShowAll={g.showAllFrameworks}
              relations={g.relations}
              allRelations={g.allRelations}
              onToggleRelation={g.toggleRelation}
              budget={budget}
              budgets={BUDGETS}
              onBudget={setBudgetParam}
            />
          </div>

          {/* Quick Metrics Badge */}
          <div className="hidden lg:flex items-center gap-2 text-xs font-mono text-muted-foreground bg-popover/80 px-3 py-1 rounded-full border border-border">
            <span>
              <strong>{stableShownIds.size}</strong> nós
            </span>
            <span>·</span>
            <span>
              <strong>{g.allowedEdges.length}</strong> arestas
            </span>
            {g.pathNodes.size > 1 && (
              <>
                <span>·</span>
                <span className="text-primary font-bold">
                  Caminho: {g.pathNodes.size - 1} saltos
                </span>
              </>
            )}
          </div>
        </div>

        {/* Quick incident chain presets strip */}
        <div className="flex items-center gap-2 flex-wrap text-xs pt-0.5">
          <span className="text-muted-foreground font-semibold text-[11px] uppercase tracking-wider flex items-center gap-1">
            <Sparkles className="w-3 h-3 text-primary" />
            Caminhos Causa-Efeito:
          </span>
          <button
            type="button"
            className={`rounded-full border px-2.5 py-0.5 text-xs font-medium cursor-pointer transition-colors ${
              from === "CWE-285" && to === "D3-AZET"
                ? "bg-primary text-primary-foreground border-primary font-bold shadow-sm"
                : "bg-primary/10 border-primary/30 text-primary hover:bg-primary/20"
            }`}
            onClick={() => {
              if (from === "CWE-285" && to === "D3-AZET") {
                setFrom(null)
                setTo(null)
              } else {
                setFrom("CWE-285")
                setTo("D3-AZET")
              }
            }}
          >
            TinyTask IDOR: CWE-285 ➔ D3-AZET
          </button>
          <button
            type="button"
            className={`rounded-full border px-2.5 py-0.5 text-xs font-medium cursor-pointer transition-colors ${
              from === "CWE-918" && to === "D3-ITF"
                ? "bg-amber-500 text-amber-950 border-amber-500 font-bold shadow-sm"
                : "bg-amber-500/10 border-amber-500/30 text-amber-300 hover:bg-amber-500/20"
            }`}
            onClick={() => {
              if (from === "CWE-918" && to === "D3-ITF") {
                setFrom(null)
                setTo(null)
              } else {
                setFrom("CWE-918")
                setTo("D3-ITF")
              }
            }}
          >
            SSRF Cloud: CWE-918 ➔ D3-ITF
          </button>
          <button
            type="button"
            className={`rounded-full border px-2.5 py-0.5 text-xs font-medium cursor-pointer transition-colors ${
              from === "CWE-494" && to === "D3-SWI"
                ? "bg-emerald-500 text-emerald-950 border-emerald-500 font-bold shadow-sm"
                : "bg-emerald-500/10 border-emerald-500/30 text-emerald-300 hover:bg-emerald-500/20"
            }`}
            onClick={() => {
              if (from === "CWE-494" && to === "D3-SWI") {
                setFrom(null)
                setTo(null)
              } else {
                setFrom("CWE-494")
                setTo("D3-SWI")
              }
            }}
          >
            Supply Chain: CWE-494 ➔ D3-SWI
          </button>

          {(from || to) && (
            <button
              type="button"
              className="text-muted-foreground hover:text-foreground text-xs underline cursor-pointer ml-1"
              onClick={() => {
                setFrom(null)
                setTo(null)
              }}
            >
              Limpar caminho iluminado
            </button>
          )}
        </div>
      </div>

      {/* Main Fullscreen Canvas Container */}
      <div className="relative min-h-0 flex-1 w-full overflow-hidden">
        <GraphCanvas
          graph={canvasGraph}
          shownIds={stableShownIds}
          selectedIds={selectedIds}
          pathNodes={g.pathNodes}
          pathEdges={g.pathEdges}
          expandedIds={g.expanded}
          onSelect={handleSelect}
          onHover={setHoverId}
          onExpand={g.toggleExpanded}
        />

        {/* Floating Node Hover Tooltip Card */}
        {hoverId && (
          <div className="pointer-events-none absolute bottom-4 left-4 z-20 flex max-w-sm flex-col gap-1 rounded-xl border border-border bg-popover/90 backdrop-blur px-3.5 py-2.5 shadow-xl">
            <div className="flex items-center justify-between gap-2">
              <strong className="font-mono text-xs font-bold text-primary">{hoverId}</strong>
              <span className="text-[10px] font-mono text-muted-foreground uppercase bg-background px-1.5 py-0.5 rounded border border-border">
                {graph.byId.get(hoverId)?.group}
              </span>
            </div>
            <span className="text-xs text-foreground font-medium leading-snug">
              {graph.byId.get(hoverId)?.name}
            </span>
            <span className="text-[10px] text-muted-foreground pt-0.5">
              Clique para selecionar · Duplo clique para expandir vizinhos
            </span>
          </div>
        )}

        {/* Floating Slide-In Inspector Drawer (ONLY opens when a node is selected!) */}
        {selected && (
          <div className="absolute right-0 top-0 bottom-0 z-30 w-[380px] max-w-[90vw] bg-card/95 backdrop-blur-md border-l border-border shadow-2xl flex flex-col animate-in slide-in-from-right duration-200">
            <div className="flex items-center justify-between border-b border-border p-3.5">
              <span className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
                Inspecionar Entidade
              </span>
              <button
                type="button"
                className="p-1 rounded-lg text-muted-foreground hover:text-foreground hover:bg-popover transition-colors cursor-pointer"
                onClick={() => handleSelect(null, false)}
                aria-label="Fechar Inspetor"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="flex-1 overflow-y-auto">
              <InspectorPanel
                node={selected}
                neighbours={neighbours}
                byId={graph.byId}
                onPick={(id) => handleSelect(id, false)}
                onClear={() => handleSelect(null, false)}
                expanded={selected ? g.expanded.has(selected.id) : false}
                onExpand={() => selected && g.toggleExpanded(selected.id)}
                pathFrom={from || null}
                pathTo={to || null}
                onSetFrom={() => setFrom(selected && from !== selected.id ? selected.id : null)}
                onSetTo={() => setTo(selected && to !== selected.id ? selected.id : null)}
                pathLength={g.pathNodes.size ? g.pathNodes.size - 1 : 0}
                pathComplete={Boolean(from && to)}
                onClearPath={() => {
                  setFrom(null)
                  setTo(null)
                }}
                multiCount={selectedIds.length}
              />
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
