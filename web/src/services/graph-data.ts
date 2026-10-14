import { useQuery } from "@tanstack/react-query"
import { neighboursOf } from "@/lib/graph"
import { KIND_OF, normalizeFramework, type GraphData, type GraphNode, type Neighbour } from "@/lib/types"

export { neighboursOf }

export const graphKeys = {
  all: ["graph"] as const,
}

async function fetchGraph(): Promise<GraphData> {
  const [graph, provenance] = await Promise.all([
    fetch("/graph.json").then((r) => {
      if (!r.ok) throw new Error(`graph.json returned ${r.status}`)
      return r.json()
    }),
    fetch("/provenance.json")
      .then((r) => (r.ok ? r.json() : null))
      .catch(() => null),
  ])

  const nodes: GraphNode[] = []
  for (const raw of graph.nodes) {
    const group = normalizeFramework(raw.group)
    if (!group) continue
    nodes.push({ ...raw, group, kind: KIND_OF[group] })
  }

  const kept = new Set(nodes.map((n) => n.id))
  const byId = new Map(nodes.map((n) => [n.id, n]))
  const adjacency = new Map<string, Neighbour[]>()
  const degrees = new Map<string, number>()
  const edges = graph.edges
    .filter((e: { from: string; to: string }) => kept.has(e.from) && kept.has(e.to))
    .map((e: { id: string; from: string; to: string; label: string }) => ({
      id: e.id,
      from: e.from,
      to: e.to,
      label: e.label,
      cross: byId.get(e.from)!.group !== byId.get(e.to)!.group,
    }))

  for (const e of edges) {
    if (!adjacency.has(e.from)) adjacency.set(e.from, [])
    if (!adjacency.has(e.to)) adjacency.set(e.to, [])
    adjacency.get(e.from)!.push({ id: e.to, rel: e.label, dir: "out" })
    adjacency.get(e.to)!.push({ id: e.from, rel: e.label, dir: "in" })
    degrees.set(e.from, (degrees.get(e.from) ?? 0) + 1)
    degrees.set(e.to, (degrees.get(e.to) ?? 0) + 1)
  }

  return {
    nodes,
    edges,
    byId,
    adjacency,
    degrees,
    provenance,
    totalNodes: nodes.length,
    generatedAt: graph.generatedAt as string,
  }
}

export function useGraphData() {
  return useQuery({ queryKey: graphKeys.all, queryFn: fetchGraph, staleTime: Infinity })
}

export function useProvenanceData() {
  return useQuery({
    queryKey: ["provenance"],
    queryFn: () => fetch("/provenance.json").then((r) => (r.ok ? r.json() : null)),
    staleTime: Infinity,
  })
}