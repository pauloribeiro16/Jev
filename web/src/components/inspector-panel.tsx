import { Route, X } from "lucide-react"
import type { GraphNode, Neighbour } from "@/lib/types"
import { colorOf } from "@/lib/palette"
import { cn } from "@/lib/utils"

export function InspectorPanel({
  node,
  neighbours,
  byId,
  onPick,
  onClear,
  expanded,
  onExpand,
  pathFrom,
  pathTo,
  onSetFrom,
  onSetTo,
  pathLength,
  pathComplete,
  onClearPath,
  multiCount,
}: {
  node: GraphNode | null
  neighbours: Neighbour[]
  byId: Map<string, GraphNode>
  onPick: (id: string) => void
  onClear: () => void
  expanded: boolean
  onExpand: () => void
  pathFrom: string | null
  pathTo: string | null
  onSetFrom: () => void
  onSetTo: () => void
  pathLength: number
  pathComplete: boolean
  onClearPath: () => void
  multiCount: number
}) {
  if (multiCount > 1) {
    return (
      <aside className="w-full h-full overflow-y-auto bg-transparent p-4">
        <h2 className="mb-3 text-xs font-semibold tracking-wider text-dim uppercase">Inspector</h2>
        <p className="leading-relaxed text-dim">
          {multiCount} nodes selected. Shift-click to add or remove one.
        </p>
      </aside>
    )
  }

  if (!node) {
    return (
      <aside className="w-full h-full overflow-y-auto bg-transparent p-4">
        <h2 className="mb-3 text-xs font-semibold tracking-wider text-dim uppercase">Inspector</h2>
        <p className="leading-relaxed text-dim">
          Click a node to inspect it. Shift-click for several, Alt-click or double-click to pull its
          neighbours into the graph.
          <br />
          <br />
          Nothing selected yet — search{" "}
          <code className="rounded bg-raised px-1.5 py-0.5 font-mono text-xs">CWE-79</code> to walk
          the weakness → attack → defence chain.
        </p>
      </aside>
    )
  }

  const meta = Object.entries(node.metadata ?? {}).filter(([, v]) => {
    const s = Array.isArray(v) ? v.join(", ") : JSON.stringify(v)
    return s && s !== '""' && s.length < 600
  })

  return (
    <aside className="w-full h-full overflow-y-auto bg-transparent p-4">
      <header className="mb-2.5 flex items-center gap-2">
        <span
          className="rounded bg-bg px-1.5 py-0.5 text-[11px] font-semibold"
          style={{ background: colorOf(node.group), color: "#0e1620" }}
        >
          {node.group}
        </span>
        <h2 className="flex-1 font-mono text-[15px] font-semibold">{node.id}</h2>
        <button
          onClick={onClear}
          aria-label="Clear selection"
          className="min-w-6 text-xl leading-none text-faint hover:text-ink"
        >
          ×
        </button>
      </header>

      <div className="mb-4 flex flex-wrap gap-1.5">
        <button onClick={onExpand} className={cn("linkbtn", expanded && "border-focus text-ink")}>
          {expanded ? "Collapse neighbours" : "Expand neighbours"}
        </button>
        <button
          onClick={onSetFrom}
          className={cn("linkbtn", pathFrom === node.id && "border-focus text-ink")}
        >
          <Route size={13} aria-hidden />
          {pathFrom === node.id ? "Path start" : "Set as start"}
        </button>
        <button
          onClick={onSetTo}
          className={cn("linkbtn", pathTo === node.id && "border-focus text-ink")}
        >
          {pathTo === node.id ? "Path end" : "Set as end"}
        </button>
      </div>

      {(pathFrom || pathTo) && (
        <p className="mb-4 flex items-center gap-2 rounded border border-line px-2.5 py-1.5 text-xs text-dim">
          <Route size={13} aria-hidden className="text-focus" />
          {pathFrom ?? "…"} → {pathTo ?? "…"}
          {pathComplete && pathLength > 0 && <strong className="text-ink">{pathLength} hops</strong>}
          {pathComplete && pathLength === 0 && <span className="text-faint">no path</span>}
          <button onClick={onClearPath} aria-label="Clear path" className="ml-auto text-faint hover:text-ink">
            <X size={12} />
          </button>
        </p>
      )}

      <h3 className="mb-1 text-sm leading-snug font-medium">{node.name}</h3>
      {node.category && <p className="mb-3 text-xs text-faint">{node.category}</p>}
      <p className="mb-5 text-dim">
        {node.description || "No description published for this node."}
      </p>

      {meta.length > 0 && (
        <section className="mb-5">
          <h4 className="mb-2 text-[11px] font-semibold tracking-wider text-dim uppercase">
            Metadata
          </h4>
          <dl className="m-0">
            {meta.map(([k, v]) => (
              <div key={k} className="grid grid-cols-[92px_1fr] gap-2.5 py-1">
                <dt className="text-xs text-faint">
                  {k.replace(/^x_|^x_migrate_/, "").replace(/_/g, " ")}
                </dt>
                <dd className="m-0 text-xs break-words">
                  {Array.isArray(v) ? v.join(", ") : String(v)}
                </dd>
              </div>
            ))}
          </dl>
        </section>
      )}

      <section>
        <h4 className="mb-2 text-[11px] font-semibold tracking-wider text-dim uppercase">
          Neighbours ({neighbours.length})
        </h4>
        {neighbours.length === 0 ? (
          <p className="leading-relaxed text-dim">
            This node has no crosswalk edges — it is a leaf.
          </p>
        ) : (
          <ul className="list-none p-0">
            {neighbours
              .slice()
              .sort((a, b) => a.rel.localeCompare(b.rel) || a.id.localeCompare(b.id))
              .map((nb) => (
                <li key={`${nb.id}-${nb.rel}-${nb.dir}`}>
                  <button
                    onClick={() => onPick(nb.id)}
                    className="flex h-6 w-full items-center gap-2 rounded px-1.5 text-left text-xs hover:bg-raised"
                  >
                    <span
                      className="h-2 w-2 shrink-0 rounded-full"
                      style={{ background: byId.get(nb.id) ? colorOf(byId.get(nb.id)!.group) : "#64748B" }}
                    />
                    <span className="font-mono">{nb.id}</span>
                    <span className="ml-auto text-[11px] text-faint">
                      {nb.rel.replace(/_REV$/, "")}
                      {nb.dir === "in" && <em> incoming</em>}
                    </span>
                  </button>
                </li>
              ))}
          </ul>
        )}
      </section>
    </aside>
  )
}