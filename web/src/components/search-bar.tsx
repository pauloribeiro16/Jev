import { Search } from "lucide-react"
import type { Hit } from "@/lib/graph"
import { colorOf } from "@/lib/palette"

export function SearchBar({
  query,
  hits,
  onQuery,
  onPick,
}: {
  query: string
  hits: Hit[]
  onQuery: (q: string) => void
  onPick: (id: string) => void
}) {
  return (
    <div className="relative max-w-xl flex-1">
      <Search
        size={14}
        aria-hidden
        className="absolute left-3 top-1/2 -translate-y-1/2 text-faint"
      />
      <input
        type="search"
        value={query}
        onChange={(e) => onQuery(e.target.value)}
        placeholder="Search nodes — try CWE-79, xss, or command injection"
        aria-label="Search nodes"
        className="w-full rounded-md border border-line bg-bg py-1.5 pl-9 pr-3 text-sm text-ink placeholder:text-faint focus:border-focus focus:outline-none"
      />
      {query && (
        <>
          <span className="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-dim">
            {hits.length ? `${hits.length}${hits.length >= 60 ? "+" : ""} matches` : "no matches"}
          </span>
          <ul className="absolute z-30 left-0 right-0 top-[calc(100%+6px)] max-h-[60vh] overflow-y-auto rounded-md border border-line bg-raised p-1 shadow-2xl">
            {hits.map(({ node, field }) => (
              <li key={node.id}>
                <button
                  onClick={() => onPick(node.id)}
                  className="grid w-full grid-cols-[10px_92px_1fr_auto] items-center gap-2.5 rounded px-2 py-1.5 text-left text-sm hover:bg-accent"
                >
                  <span
                    className="h-2.5 w-2.5 rounded-full"
                    style={{ background: colorOf(node.group) }}
                  />
                  <span className="font-mono text-xs">{node.id}</span>
                  <span className="truncate text-dim">{node.name}</span>
                  <span className="text-[11px] text-faint">{field}</span>
                </button>
              </li>
            ))}
            {!hits.length && (
              <li className="px-3 py-2.5 leading-relaxed text-dim">
                Nothing matches <strong>{query}</strong>. Try an identifier like{" "}
                <code>CWE-79</code>, or a concept like <code>injection</code>.
              </li>
            )}
          </ul>
        </>
      )}
    </div>
  )
}