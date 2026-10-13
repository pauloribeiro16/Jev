"""Synchronize Threat Modeling KG changes into the Template_React fullstack repository."""

import shutil
from pathlib import Path

JEV_DIR = Path(r"c:\Users\paulo.ribeiro\OneDrive - Instituto CCG ZGDV\Documentos\Repositorios\Jev")
REACT_DIR = Path(r"c:\Users\paulo.ribeiro\OneDrive - Instituto CCG ZGDV\Documentos\Repositorios\Template_React")

def sync():
    print("[1/4] Atualizar backend: services/graph.ts...")
    backend_graph_file = REACT_DIR / "backend" / "src" / "services" / "graph.ts"
    
    new_backend_graph_code = '''import type { Record as Neo4jRecord } from "neo4j-driver"
import { neo4jDriver } from "../lib/neo4j.js"

// Único sítio com queries Cypher — mesmo contrato que `services/users.ts` tem
// com o Prisma. Os controllers nunca importam o driver directamente.
// Suporta tanto nós de Threat Intelligence (CAPEC, CWE, ATTACK, D3FEND, SubDomain)
// como nós com propriedade genérica .id.

export type GraphNode = {
  id: string
  label: string
  title: string
  group: string
}

export type GraphEdge = {
  from: string
  to: string
  label: string
}

export type NeighborRecord = {
  direction: "OUTGOING" | "INCOMING"
  relType: string
  neighborLabel: string
  neighborId: string
  neighborName: string
  neighborDesc: string
}

const truncate = (value: unknown, max: number) => {
  const text = String(value ?? "")
  return text.length > max ? `${text.slice(0, max)}...` : text
}

export async function fetchEntireGraph(): Promise<{
  nodes: GraphNode[]
  edges: GraphEdge[]
}> {
  const nodes: GraphNode[] = []
  const edges: GraphEdge[] = []
  const seenNodes = new Set<string>()
  const seenEdges = new Set<string>()

  const { records } = await neo4jDriver.executeQuery(`
    MATCH (n)
    OPTIONAL MATCH (n)-[r]->(m)
    RETURN
        coalesce(n.capecId, n.cweId, n.attackId, n.d3fendId, n.subDomainId, n.domainId, n.id, elementId(n)) AS n_code,
        coalesce(n.name, n.title, n.id, n.capecId, n.cweId, n.attackId, n.d3fendId) AS n_label,
        labels(n)[0] AS n_type,
        coalesce(m.capecId, m.cweId, m.attackId, m.d3fendId, m.subDomainId, m.domainId, m.id, elementId(m)) AS m_code,
        type(r) AS rel_type
  `)

  for (const record of records) {
    const nodeId = String(record.get("n_code") ?? "")
    if (nodeId && !seenNodes.has(nodeId)) {
      seenNodes.add(nodeId)
      const nodeType = String(record.get("n_type") ?? "DEFAULT")
      const rawLabel = String(record.get("n_label") ?? nodeId)
      const nodeLabelText = truncate(rawLabel, 26)

      nodes.push({
        id: nodeId,
        label: nodeLabelText,
        title: `<b>${nodeType}</b> (${nodeId}):<br>${rawLabel}`,
        group: nodeType,
      })
    }

    const targetId = record.get("m_code")
    const relType = record.get("rel_type")
    if (nodeId && targetId && relType) {
      const edgeKey = `${nodeId}->${String(targetId)}:${String(relType)}`
      if (!seenEdges.has(edgeKey)) {
        seenEdges.add(edgeKey)
        edges.push({ from: nodeId, to: String(targetId), label: String(relType) })
      }
    }
  }

  return { nodes, edges }
}

const NEIGHBORS_CYPHER = `
    MATCH (curr)
    WHERE coalesce(curr.capecId, curr.cweId, curr.attackId, curr.d3fendId, curr.subDomainId, curr.domainId, curr.id) = $curr_id
    MATCH (curr)-[r]-(neighbor)
    WHERE NOT coalesce(neighbor.capecId, neighbor.cweId, neighbor.attackId, neighbor.d3fendId, neighbor.subDomainId, neighbor.domainId, neighbor.id) IN $visited_ids
    RETURN
        CASE WHEN startNode(r) = curr THEN 'OUTGOING' ELSE 'INCOMING' END AS direction,
        type(r) AS rel_type,
        labels(neighbor)[0] AS neighbor_label,
        coalesce(neighbor.capecId, neighbor.cweId, neighbor.attackId, neighbor.d3fendId, neighbor.subDomainId, neighbor.domainId, neighbor.id) AS neighbor_id,
        coalesce(neighbor.name, neighbor.title, neighbor.text, neighbor.id) AS neighbor_name,
        coalesce(neighbor.description, neighbor.definition, neighbor.solutions, '') AS neighbor_desc
    LIMIT 25`

export async function queryNeighbors(
  currentNodeId: string,
  visitedIds: string[],
): Promise<{ neighbors: NeighborRecord[]; cypher: string; params: Record<string, unknown> }> {
  const params = { curr_id: currentNodeId, visited_ids: visitedIds }
  const { records } = await neo4jDriver.executeQuery(NEIGHBORS_CYPHER, params)

  const neighbors = records.map((record: Neo4jRecord) => ({
    direction: record.get("direction") as NeighborRecord["direction"],
    relType: String(record.get("rel_type")),
    neighborLabel: String(record.get("neighbor_label") ?? "DEFAULT"),
    neighborId: String(record.get("neighbor_id") ?? ""),
    neighborName: String(record.get("neighbor_name") ?? ""),
    neighborDesc: String(record.get("neighbor_desc") ?? ""),
  }))

  return { neighbors, cypher: NEIGHBORS_CYPHER.trim(), params }
}
'''
    backend_graph_file.write_text(new_backend_graph_code, encoding="utf-8")
    print(f"      -> {backend_graph_file} atualizado com sucesso!")

    print("[2/4] Atualizar frontend: services/Explorer/explorer.ts...")
    frontend_explorer_file = REACT_DIR / "frontend" / "src" / "services" / "Explorer" / "explorer.ts"
    
    new_frontend_explorer_code = '''import { api } from "@/services/api"
import { useMutation, useQuery } from "@tanstack/react-query"
import type {
  GraphSnapshot,
  Manuscript,
  TraversalHopBody,
  TraversalHopResult,
} from "./types"

// Nós de partida de inteligência de ameaças (CAPEC, CWE, ATT&CK).
export const START_NODES = [
  { id: "CAPEC-1", label: "CAPEC-1 — Access Control Bypass (High)" },
  { id: "CAPEC-98", label: "CAPEC-98 — Phishing Attack Pattern (High)" },
  { id: "CWE-89", label: "CWE-89 — SQL Injection Vulnerability (Critical)" },
  { id: "T1574.010", label: "T1574.010 — Services File Permissions Weakness (High)" },
  { id: "CWE-287", label: "CWE-287 — Improper Authentication (High)" },
  { id: "CAPEC-112", label: "CAPEC-112 — Brute Force (Medium)" },
] as const

export const DEFAULT_GOAL =
  "Find the D3FEND defensive countermeasure or verification technique that mitigates software file permissions or access control weaknesses."

// Limiar de confiança (Noul) a partir do qual o objetivo dá por alcançado —
// igual ao usado pelo backend e pelo app Streamlit original.
export const GOAL_THRESHOLD = 0.7

const explorerKeys = {
  all: ["explorer"] as const,
  graph: () => [...explorerKeys.all, "graph"] as const,
  manuscripts: () => [...explorerKeys.all, "manuscripts"] as const,
  manuscript: (name: string) => [...explorerKeys.all, "manuscripts", name] as const,
}

export const useFetchGraph = () =>
  useQuery({
    queryKey: explorerKeys.graph(),
    queryFn: async () => api.get("graph").json<GraphSnapshot>(),
    // O grafo só muda quando o Neo4j é recarregado fora da app.
    staleTime: Number.POSITIVE_INFINITY,
  })

export const useExecuteHop = () =>
  useMutation({
    mutationFn: async (body: TraversalHopBody) =>
      api.post("graph/hop", { json: body }).json<TraversalHopResult>(),
  })

export const useFetchManuscripts = () =>
  useQuery({
    queryKey: explorerKeys.manuscripts(),
    queryFn: async () => api.get("manuscripts").json<string[]>(),
    staleTime: Number.POSITIVE_INFINITY,
  })

export const useFetchManuscript = (name: string | null) =>
  useQuery({
    queryKey: explorerKeys.manuscript(name ?? ""),
    queryFn: async () => api.get(`manuscripts/${name}`).json<Manuscript>(),
    enabled: name !== null,
    staleTime: Number.POSITIVE_INFINITY,
  })
'''
    frontend_explorer_file.write_text(new_frontend_explorer_code, encoding="utf-8")
    print(f"      -> {frontend_explorer_file} atualizado com sucesso!")

    print("[3/4] Atualizar frontend: lib/graph-visuals.ts (Cores e Labels)...")
    frontend_visuals_file = REACT_DIR / "frontend" / "src" / "lib" / "graph-visuals.ts"

    new_frontend_visuals_code = '''import type {
  GraphEdge,
  GraphNode,
  GraphSnapshot,
} from "@/services/Explorer/types"

// Paleta de cores por tipo de nó do grafo semântico de cibersegurança.
// Constantes de renderização do vis-network (canvas).
export const NODE_COLOR_MAP: Record<string, string> = {
  CAPEC: "#F97316",      // Laranja Vívido (Padrões de Ataque)
  CWE: "#8B5CF6",        // Roxo Vívido (Fraquezas de Código)
  ATTACK: "#EF4444",     // Vermelho Carmesim (Técnicas Adversárias)
  D3FEND: "#10B981",     // Verde Esmeralda (Contramedidas Defensivas)
  SubDomain: "#06B6D4",  // Ciano (Pontes AEGIS Taxonomy)
  Domain: "#3B82F6",     // Azul Royal (Domínios de Segurança)
  DEFAULT: "#64748B",    // Ardósia Neutro
}

const PATH_COLOR = { background: "#10B981", border: "#34D399" }
const CURRENT_COLOR = { background: "#F59E0B", border: "#FDE68A" }
const DEFAULT_NODE_COLOR = { background: "", border: "#334155" }
const EDGE_COLOR = "#475569"
const EDGE_PATH_COLOR = "#10B981"
const LABEL_COLOR = "#E2E8F0"
const EDGE_LABEL_COLOR = "#94A3B8"

export type VisNode = {
  id: string
  label: string
  title: string
  shape: "dot"
  size: number
  color: { background: string; border: string }
  borderWidth: number
  font: { color: string; size: number }
}

export type VisEdge = {
  id: string
  from: string
  to: string
  label: string
  arrows: "to"
  color: { color: string }
  width?: number
  font: { color: string; size: number; align: "middle" }
}

// Subgrafo visível: caminho percorrido + nó atual + vizinhos diretos (ramos candidatos).
export function extractLocalSubgraph(
  graph: GraphSnapshot,
  traversedPath: string[],
  currentNode: string,
): GraphSnapshot {
  const keep = new Set(traversedPath)
  keep.add(currentNode)

  graph.edges.forEach((edge) => {
    if (edge.from === currentNode) keep.add(edge.to)
    if (edge.to === currentNode) keep.add(edge.from)
  })

  return {
    nodes: graph.nodes.filter((node) => keep.has(node.id)),
    edges: graph.edges.filter(
      (edge) => keep.has(edge.from) && keep.has(edge.to),
    ),
  }
}

// Constrói os nós do vis-network: o caminho percorrido fica verde-esmeralda, o
// nó atual fica âmbar e maior.
export function buildVisNodes(
  nodes: GraphNode[],
  traversedPath: string[],
  currentNode: string,
): VisNode[] {
  const traversedSet = new Set(traversedPath)

  return nodes.map((node) => {
    const baseColor = NODE_COLOR_MAP[node.group] ?? NODE_COLOR_MAP.DEFAULT
    const visNode: VisNode = {
      id: node.id,
      label: `${node.id}\\n(${node.group})`,
      title: node.title,
      shape: "dot",
      size: 20,
      color: { ...DEFAULT_NODE_COLOR, background: baseColor },
      borderWidth: 1,
      font: { color: LABEL_COLOR, size: 12 },
    }

    if (traversedSet.has(node.id)) {
      visNode.size = 32
      visNode.color = { ...PATH_COLOR }
      visNode.borderWidth = 3
    }

    if (node.id === currentNode) {
      visNode.size = 44
      visNode.color = { ...CURRENT_COLOR }
      visNode.borderWidth = 5
    }

    return visNode
  })
}

export function buildVisEdges(
  edges: GraphEdge[],
  traversedPath: string[],
): VisEdge[] {
  const traversedSet = new Set(traversedPath)

  return edges.map((edge, index) => {
    const isTraversed =
      traversedSet.has(edge.from) && traversedSet.has(edge.to)

    return {
      id: `${edge.from}->${edge.to}[${index}]`,
      from: edge.from,
      to: edge.to,
      label: edge.label,
      arrows: "to",
      color: { color: isTraversed ? EDGE_PATH_COLOR : EDGE_COLOR },
      width: isTraversed ? 4 : undefined,
      font: { color: EDGE_LABEL_COLOR, size: 10, align: "middle" },
    }
  })
}
'''
    frontend_visuals_file.write_text(new_frontend_visuals_code, encoding="utf-8")
    print(f"      -> {frontend_visuals_file} atualizado com sucesso!")

    print("[4/4] Sincronizar Manuscrito #02 para o backend...")
    src_m2 = JEV_DIR / "manuscritos" / "02_threat_modeling_cwe_capec_mitre.md"
    dst_m2 = REACT_DIR / "backend" / "content" / "manuscritos" / "02_threat_modeling_cwe_capec_mitre.md"
    if src_m2.exists():
        dst_m2.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src_m2, dst_m2)
        print(f"      -> {dst_m2} sincronizado com sucesso!")

    print("\n✅ Todas as alterações foram sincronizadas para o Template_React!")

if __name__ == "__main__":
    sync()
