/**
 * Ontology types.
 *
 * The framework label is a closed union on purpose. The crosswalk emits both
 * "ATT&CK" and "ATTACK" for the same framework, and a plain `string` let that
 * mismatch reach TEMPLATES lookup where it silently fell back to the wrong
 * template. Normalising at the boundary makes that class of bug a type error.
 */
export const FRAMEWORKS = ["CWE", "CAPEC", "ATT&CK", "D3FEND", "ATLAS"] as const
export type Framework = (typeof FRAMEWORKS)[number]

/** Accepts either spelling and returns the canonical one. */
export function normalizeFramework(raw: string): Framework | null {
  const key = raw.replace("&", "").toUpperCase()
  const match = FRAMEWORKS.find((f) => f.replace("&", "").toUpperCase() === key)
  return match ?? null
}

export type NodeKind = "weakness" | "attack" | "technique" | "countermeasure" | "adversary"

export const KIND_OF: Record<Framework, NodeKind> = {
  CWE: "weakness",
  CAPEC: "attack",
  "ATT&CK": "technique",
  D3FEND: "countermeasure",
  ATLAS: "adversary",
}

export interface GraphNode {
  id: string
  name: string
  group: Framework
  /** Present on the wire; mapped onto KIND_OF so the canvas never branches on id text. */
  color?: string
  category?: string
  description?: string
  metadata?: Record<string, unknown>
  kind: NodeKind
}

export interface GraphEdge {
  id: string
  from: string
  to: string
  label: string
  /** True when the edge crosses frameworks — the meaningful ones here. */
  cross: boolean
}

export interface DatasetRevision {
  key: string
  filename: string
  sha256: string
  bytes: number
  fetchedAt: string
  url: string
}

export interface Provenance {
  generatedAt: string
  generationTimeMs: number
  totalNodes: number
  totalEdges: number
  frameworks: Record<string, number>
  datasets: DatasetRevision[]
}

export interface Neighbour {
  id: string
  rel: string
  dir: "in" | "out"
}

export interface GraphData {
  nodes: GraphNode[]
  edges: GraphEdge[]
  byId: Map<string, GraphNode>
  adjacency: Map<string, Neighbour[]>
  degrees: Map<string, number>
  provenance: Provenance | null
  totalNodes: number
  generatedAt: string
}

/** A resolved path between two nodes, as an ordered id list. */
export interface TracedPath {
  nodes: string[]
  edges: string[]
}