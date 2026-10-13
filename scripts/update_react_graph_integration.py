"""Updates Template_React backend graph service with high-speed in-memory indexing and no Neo4j timeout hangs."""

from pathlib import Path

REACT_DIR = Path(r"c:\Users\paulo.ribeiro\OneDrive - Instituto CCG ZGDV\Documentos\Repositorios\Template_React")


def update():
    backend_graph_file = REACT_DIR / "backend" / "src" / "services" / "graph.ts"
    
    code = '''import fs from "fs"
import type { Record as Neo4jRecord } from "neo4j-driver"
import { neo4jDriver } from "../lib/neo4j.js"

export type GraphNode = {
  id: string
  label: string
  title: string
  group: string
  name?: string
  category?: string
  description?: string
  metadata?: Record<string, unknown>
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

const CANONICAL_SNAPSHOT_PATH = "C:\\\\Users\\\\paulo.ribeiro\\\\OneDrive - Instituto CCG ZGDV\\\\Documentos\\\\Repositorios\\\\Jev\\\\data\\\\canonical_graph_snapshot.json"

// In-memory cache structures
let cachedGraph: { nodes: GraphNode[]; edges: GraphEdge[] } | null = null
let nodeIndex: Map<string, any> | null = null
let outgoingIndex: Map<string, { to: string; label: string }[]> | null = null
let incomingIndex: Map<string, { from: string; label: string }[]> | null = null

function ensureSnapshotLoaded() {
  if (cachedGraph !== null) return

  if (fs.existsSync(CANONICAL_SNAPSHOT_PATH)) {
    try {
      const raw = fs.readFileSync(CANONICAL_SNAPSHOT_PATH, "utf-8")
      const parsed = JSON.parse(raw)
      
      cachedGraph = {
        nodes: parsed.nodes,
        edges: parsed.edges,
      }
      nodeIndex = new Map()
      outgoingIndex = new Map()
      incomingIndex = new Map()

      for (const n of parsed.nodes) {
        nodeIndex.set(n.id.toUpperCase(), n)
      }

      for (const e of parsed.edges) {
        const from = e.from.toUpperCase()
        const to = e.to.toUpperCase()

        if (!outgoingIndex.has(from)) outgoingIndex.set(from, [])
        outgoingIndex.get(from)!.push({ to, label: e.label })

        if (!incomingIndex.has(to)) incomingIndex.set(to, [])
        incomingIndex.get(to)!.push({ from, label: e.label })
      }
      console.log(`[GraphService] In-memory index built: ${nodeIndex.size} nodes, ${parsed.edges.length} edges`)
    } catch (e) {
      console.warn("[GraphService] Failed to load canonical snapshot:", e)
    }
  }
}

export function detectNodeFramework(nodeId: string): string {
  const norm = nodeId.trim().toUpperCase()
  if (norm.startsWith("CAPEC-")) return "CAPEC"
  if (norm.startsWith("CWE-") || (/^\\d{1,4}$/.test(norm))) return "CWE"
  if (norm.startsWith("AML.T")) return "ATLAS"
  if (norm.startsWith("D3-") || norm.startsWith("D3A-")) return "D3FEND"
  if (norm.startsWith("T") || norm.startsWith("TA")) return "ATTACK"
  if (norm.startsWith("D-")) return "SubDomain"
  return "UNKNOWN"
}

export async function fetchEntireGraph(): Promise<{
  nodes: GraphNode[]
  edges: GraphEdge[]
}> {
  ensureSnapshotLoaded()
  if (cachedGraph) {
    return cachedGraph
  }

  // Fallback to Neo4j if snapshot is missing
  const nodes: GraphNode[] = []
  const edges: GraphEdge[] = []
  const seenNodes = new Set<string>()
  const seenEdges = new Set<string>()

  try {
    const { records } = await neo4jDriver.executeQuery(`
      MATCH (n)
      OPTIONAL MATCH (n)-[r]->(m)
      RETURN
          coalesce(n.capecId, n.cweId, n.attackId, n.d3fendId, n.atlasId, n.subDomainId, n.domainId, n.id, elementId(n)) AS n_code,
          coalesce(n.name, n.title, n.id, n.capecId, n.cweId, n.attackId, n.d3fendId) AS n_label,
          labels(n)[0] AS n_type,
          coalesce(m.capecId, m.cweId, m.attackId, m.d3fendId, m.atlasId, m.subDomainId, m.domainId, m.id, elementId(m)) AS m_code,
          type(r) AS rel_type
    `)

    for (const record of records) {
      const nodeId = String(record.get("n_code") ?? "")
      if (nodeId && !seenNodes.has(nodeId)) {
        seenNodes.add(nodeId)
        const nodeType = String(record.get("n_type") ?? "DEFAULT")
        const rawLabel = String(record.get("n_label") ?? nodeId)

        nodes.push({
          id: nodeId,
          label: rawLabel.length > 26 ? `${rawLabel.slice(0, 26)}...` : rawLabel,
          title: `${nodeType} (${nodeId})\\n${rawLabel}`,
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
  } catch (err) {
    console.warn("[GraphService] Neo4j query failed:", err)
  }

  return { nodes, edges }
}

export async function queryCandidateFrameworks(
  currentNodeId: string,
  currentFramework: string,
): Promise<Record<string, string>> {
  const FRAMEWORK_DESCRIPTIONS: Record<string, string> = {
    CAPEC: "Examine high-level attacker strategy and attack patterns (MITRE CAPEC)",
    CWE: "Inspect root-cause software bugs and code-level weaknesses (MITRE CWE)",
    ATTACK: "Trace concrete operational adversary execution techniques (MITRE ATT&CK)",
    ATLAS: "Investigate AI/ML-specific threats like prompt injection and model evasion (MITRE ATLAS)",
    D3FEND: "Consult defensive countermeasures and mitigation techniques (MITRE D3FEND)",
    STAY_LOCAL: `Continue refining within ${currentFramework}`,
  }

  const candidates: Record<string, string> = {
    STAY_LOCAL: `Continue refining within ${currentFramework}`,
  }

  ensureSnapshotLoaded()
  if (outgoingIndex && nodeIndex) {
    const norm = currentNodeId.trim().toUpperCase()
    const outEdges = outgoingIndex.get(norm) || []
    for (const e of outEdges) {
      const tgt = nodeIndex.get(e.to)
      if (tgt && tgt.group !== currentFramework) {
        candidates[tgt.group] = FRAMEWORK_DESCRIPTIONS[tgt.group] ?? `Consult ${tgt.group} framework`
      }
    }

    const inEdges = incomingIndex?.get(norm) || []
    for (const e of inEdges) {
      const src = nodeIndex.get(e.from)
      if (src && src.group !== currentFramework) {
        candidates[src.group] = FRAMEWORK_DESCRIPTIONS[src.group] ?? `Consult ${src.group} framework`
      }
    }

    // Heuristic transitions based on domain
    if (currentFramework === "CWE") candidates["CAPEC"] = FRAMEWORK_DESCRIPTIONS.CAPEC
    if (currentFramework === "CAPEC") candidates["ATTACK"] = FRAMEWORK_DESCRIPTIONS.ATTACK
    if (currentFramework === "ATTACK") candidates["D3FEND"] = "Consult D3FEND defensive countermeasures (Primary Mitigation Target)"
    if (currentFramework === "ATLAS") candidates["ATTACK"] = FRAMEWORK_DESCRIPTIONS.ATTACK

    if (candidates.D3FEND) {
      candidates.D3FEND = "Consult D3FEND defensive countermeasures (Primary Mitigation Target)"
    }
    return candidates
  }

  // Heuristic defaults
  if (currentFramework === "CWE") candidates["CAPEC"] = FRAMEWORK_DESCRIPTIONS.CAPEC
  if (currentFramework === "CAPEC") candidates["ATTACK"] = FRAMEWORK_DESCRIPTIONS.ATTACK
  if (currentFramework === "ATTACK") candidates["D3FEND"] = "Consult D3FEND defensive countermeasures (Primary Mitigation Target)"
  return candidates
}

export async function queryScopedNeighbors(
  currentNodeId: string,
  targetFramework: string,
  visitedIds: string[],
): Promise<{ neighbors: NeighborRecord[]; cypher: string; params: Record<string, unknown> }> {
  ensureSnapshotLoaded()
  const normCurr = currentNodeId.trim().toUpperCase()
  const visited = new Set(visitedIds.map(v => v.trim().toUpperCase()))

  if (nodeIndex && outgoingIndex && incomingIndex) {
    const neighbors: NeighborRecord[] = []
    const seenNeighborIds = new Set<string>()

    // Check outgoing edges
    const outEdges = outgoingIndex.get(normCurr) || []
    for (const e of outEdges) {
      if (visited.has(e.to) || seenNeighborIds.has(e.to)) continue
      const tgt = nodeIndex.get(e.to)
      if (tgt && (targetFramework === "ALL" || tgt.group === targetFramework)) {
        seenNeighborIds.add(e.to)
        neighbors.push({
          direction: "OUTGOING",
          relType: e.label,
          neighborLabel: tgt.group,
          neighborId: tgt.id,
          neighborName: tgt.name || tgt.id,
          neighborDesc: tgt.description || "",
        })
        if (neighbors.length >= 12) break
      }
    }

    // Check incoming edges
    if (neighbors.length < 12) {
      const inEdges = incomingIndex.get(normCurr) || []
      for (const e of inEdges) {
        if (visited.has(e.from) || seenNeighborIds.has(e.from)) continue
        const src = nodeIndex.get(e.from)
        if (src && (targetFramework === "ALL" || src.group === targetFramework)) {
          seenNeighborIds.add(e.from)
          neighbors.push({
            direction: "INCOMING",
            relType: e.label,
            neighborLabel: src.group,
            neighborId: src.id,
            neighborName: src.name || src.id,
            neighborDesc: src.description || "",
          })
          if (neighbors.length >= 12) break
        }
      }
    }

    return {
      neighbors,
      cypher: `Decoupled Canonical Index Lookup (${normCurr} -> ${targetFramework})`,
      params: { currentNodeId, targetFramework }
    }
  }

  return {
    neighbors: [],
    cypher: "No index available",
    params: { currentNodeId, targetFramework }
  }
}

export async function queryNeighbors(
  currentNodeId: string,
  visitedIds: string[],
): Promise<{ neighbors: NeighborRecord[]; cypher: string; params: Record<string, unknown> }> {
  return queryScopedNeighbors(currentNodeId, "ALL", visitedIds)
}
'''
    backend_graph_file.write_text(code, encoding="utf-8")
    print(f"Updated {backend_graph_file} with sub-millisecond in-memory indexed graph service!")


if __name__ == "__main__":
    update()
