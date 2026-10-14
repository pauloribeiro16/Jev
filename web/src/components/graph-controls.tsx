import { ChevronDown, Search, X } from "lucide-react"
import { DropdownMenu, DropdownMenuCheckboxItem, DropdownMenuContent, DropdownMenuLabel, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Shape } from "@/components/ontology-shape"
import { cn } from "@/lib/utils"
import type { Hit } from "@/lib/graph"

type Props = {
  query: string
  onQuery: (q: string | null) => void
  onPick: (id: string) => void
  hits: Hit[]
  counts: Record<string, number>
  enabled: Set<string>
  onToggleFramework: (fw: string) => void
  onShowAll: () => void
  relations: Set<string>
  allRelations: string[]
  onToggleRelation: (rel: string) => void
  budget: number
  budgets: readonly number[]
  onBudget: (n: string) => void
}

const FRAMEWORK_LIST = ["CWE", "CAPEC", "ATT&CK", "D3FEND", "ATLAS"] as const

export function GraphControls(p: Props) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      {/* frameworks as filter chips */}
      <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Filtrar frameworks">
        {FRAMEWORK_LIST.map((fw) => {
          const on = p.enabled.has(fw)
          return (
            <button
              key={fw}
              type="button"
              onClick={() => p.onToggleFramework(fw)}
              aria-pressed={on}
              className={cn(
                "flex h-7 items-center gap-1.5 rounded-full border px-2.5 text-xs",
                on ? "border-border bg-muted/60 text-foreground" : "text-muted-foreground hover:bg-muted/40",
              )}
            >
              <span className={on ? undefined : "opacity-40 grayscale"}>
                <Shape fw={fw} size={11} />
              </span>
              {fw}
              <span className="font-mono text-[10px] text-muted-foreground tabular-nums">
                {p.counts[fw] ?? 0}
              </span>
            </button>
          )
        })}
        <Button variant="ghost" size="sm" className="h-7 px-2 text-xs" onClick={p.onShowAll}>
          Todas
        </Button>
      </div>

      <div className="ml-auto flex items-center gap-2">
        {/* relations dropdown */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="outline" size="sm" className="h-7 text-xs">
              Relações ({p.relations.size})
              <ChevronDown className="size-3" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="max-h-72 overflow-y-auto">
            <DropdownMenuLabel>Arestas mostradas</DropdownMenuLabel>
            {p.allRelations.map((rel) => (
              <DropdownMenuCheckboxItem
                key={rel}
                checked={p.relations.has(rel)}
                onCheckedChange={() => p.onToggleRelation(rel)}
                className="font-mono text-xs"
              >
                {rel}
              </DropdownMenuCheckboxItem>
            ))}
          </DropdownMenuContent>
        </DropdownMenu>

        {/* budget */}
        <div className="flex items-center gap-1" role="group" aria-label="Nós renderizados">
          {p.budgets.map((n) => (
            <button
              key={n}
              type="button"
              onClick={() => p.onBudget(String(n))}
              aria-pressed={p.budget === n}
              className={cn(
                "h-7 rounded-full border px-2.5 text-xs",
                p.budget === n
                  ? "border-transparent bg-primary font-medium text-primary-foreground"
                  : "text-muted-foreground hover:bg-muted/40",
              )}
            >
              {n}
            </button>
          ))}
        </div>

        {/* search, with inline results */}
        <div className="relative w-64">
          <Search className="absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            type="search"
            value={p.query}
            onChange={(e) => p.onQuery(e.target.value)}
            placeholder="CWE-79, xss, injection…"
            aria-label="Pesquisar nós"
            className="h-7 pl-8 text-xs"
          />
          {p.query && (
            <>
              {p.hits.length > 0 && (
                <button
                  type="button"
                  aria-label="Limpar pesquisa"
                  onClick={() => p.onQuery(null)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                >
                  <X className="size-3" />
                </button>
              )}
              <ul className="absolute z-30 left-0 right-0 top-[calc(100%+6px)] max-h-72 overflow-y-auto rounded-md border bg-popover p-1 shadow-lg">
                {p.hits.map(({ node, field }) => (
                  <li key={node.id}>
                    <button
                      type="button"
                      onClick={() => {
                        p.onPick(node.id)
                        p.onQuery("")
                      }}
                      className="grid w-full grid-cols-[92px_1fr_auto] items-center gap-2 rounded px-2 py-1.5 text-left text-xs hover:bg-muted/60"
                    >
                      <span className="font-mono">{node.id}</span>
                      <span className="truncate text-muted-foreground">{node.name}</span>
                      <span className="text-[10px] text-muted-foreground">{field}</span>
                    </button>
                  </li>
                ))}
                {!p.hits.length && (
                  <li className="px-2 py-2 text-xs text-muted-foreground">Sem resultados.</li>
                )}
              </ul>
            </>
          )}
        </div>
      </div>
    </div>
  )
}
