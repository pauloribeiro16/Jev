import type { GraphData, GraphNode, Neighbour } from "@/lib/types"

export interface Hit {
  node: GraphNode
  field: "id" | "name" | "description"
}

export function searchNodes(nodes: GraphNode[], query: string, limit = 60): Hit[] {
  const q = query.trim().toLowerCase()
  if (!q) return []
  const hits: Hit[] = []
  for (const n of nodes) {
    if (n.id.toLowerCase().includes(q)) hits.push({ node: n, field: "id" })
    else if ((n.name || "").toLowerCase().includes(q)) hits.push({ node: n, field: "name" })
    else if ((n.description || "").toLowerCase().includes(q)) hits.push({ node: n, field: "description" })
    if (hits.length >= limit) break
  }
  return hits
}

export function neighboursOf(graph: GraphData, id: string): Neighbour[] {
  return graph.adjacency.get(id) ?? []
}

export function relationLabels(edges: { label: string }[]): string[] {
  return [...new Set(edges.map((e) => e.label))].sort()
}

/** BFS shortest path over the currently allowed relations. */
export function tracePath(
  graph: GraphData,
  fromId: string,
  toId: string,
  allowed: Set<string>,
): { nodes: string[]; edges: string[] } | null {
  if (fromId === toId) return { nodes: [fromId], edges: [] }
  const queue: string[][] = [[fromId]]
  const seen = new Set([fromId])
  while (queue.length) {
    const path = queue.shift()!
    for (const n of graph.adjacency.get(path[path.length - 1]) ?? []) {
      if (!allowed.has(n.rel) || seen.has(n.id)) continue
      const next = [...path, n.id]
      if (n.id === toId) {
        return {
          nodes: next,
          edges: next.slice(0, -1).map((id, i) => `${id}->${next[i + 1]}`),
        }
      }
      seen.add(n.id)
      queue.push(next)
    }
  }
  return null
}
