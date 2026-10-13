"""Updates Template_React backend and frontend graph integration to use the decoupled canonical snapshot."""

from pathlib import Path

REACT_DIR = Path(r"c:\Users\paulo.ribeiro\OneDrive - Instituto CCG ZGDV\Documentos\Repositorios\Template_React")
JEV_DIR = Path(r"c:\Users\paulo.ribeiro\OneDrive - Instituto CCG ZGDV\Documentos\Repositorios\Jev")


def update():
    # 1. Update frontend/src/lib/graph-visuals.ts to include ATLAS color
    visuals_file = REACT_DIR / "frontend" / "src" / "lib" / "graph-visuals.ts"
    if visuals_file.exists():
        content = visuals_file.read_text(encoding="utf-8")
        if 'ATLAS: "#E11D48"' not in content:
            new_content = content.replace(
                '  D3FEND: "#10B981",     // Verde Esmeralda (Contramedidas Defensivas)\n',
                '  D3FEND: "#10B981",     // Verde Esmeralda (Contramedidas Defensivas)\n  ATLAS: "#E11D48",      // Rosa Carmim (Ameaças AI/ML)\n'
            )
            visuals_file.write_text(new_content, encoding="utf-8")
            print(f"[1/2] Added ATLAS color to {visuals_file}")

    # 2. Update backend/src/services/graph.ts to use canonical_graph_snapshot.json
    backend_graph_file = REACT_DIR / "backend" / "src" / "services" / "graph.ts"
    if backend_graph_file.exists():
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
  // 1. Prioritize Decoupled Canonical Snapshot (Fast, Sub-millisecond, Complete descriptions)
  if (fs.existsSync(CANONICAL_SNAPSHOT_PATH)) {
    try {
      const raw = fs.readFileSync(CANONICAL_SNAPSHOT_PATH, "utf-8")
      const parsed = JSON.parse(raw)
      if (parsed.nodes && parsed.edges) {
        return {
          nodes: parsed.nodes.map((n: any) => ({
            id: n.id,
            label: n.label,
            title: n.title,
            group: n.group,
            name: n.name,
            category: n.category,
            description: n.description,
            metadata: n.metadata,
          })),
          edges: parsed.edges.map((e: any) => ({
            from: e.from,
            to: e.to,
            label: e.label,
          })),
        }
      }
    } catch (e) {
      console.warn("[GraphService] Error reading canonical snapshot, falling back to Neo4j:", e)
    }
  }

  // 2. Fallback to Neo4j database
  const nodes: GraphNode[] = []
  const edges: GraphEdge[] = []
  const seenNodes = new Set<string>()
  const seenEdges = new Set<string>()

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

  return { nodes, edges }
}

const CANDIDATE_FRAMEWORKS_CYPHER = `
  MATCH (curr)
  WHERE coalesce(curr.capecId, curr.cweId, curr.attackId, curr.d3fendId, curr.atlasId, curr.subDomainId, curr.domainId, curr.id) = $curr_id
  MATCH (curr)-[r]-(neighbor)
  WITH DISTINCT labels(neighbor)[0] AS n_lbl
  WHERE n_lbl IN ['CAPEC', 'CWE', 'ATTACK', 'ATLAS', 'D3FEND'] AND n_lbl <> $cur_lbl
  RETURN collect(n_lbl) AS bridge_frameworks
`

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

  try {
    const { records } = await neo4jDriver.executeQuery(CANDIDATE_FRAMEWORKS_CYPHER, {
      curr_id: currentNodeId,
      cur_lbl: currentFramework,
    })

    if (records.length > 0) {
      const rawBridges = records[0].get("bridge_frameworks") as string[] | undefined
      if (rawBridges && Array.isArray(rawBridges)) {
        for (const fw of rawBridges) {
          if (fw && fw !== currentFramework) {
            candidates[fw] = FRAMEWORK_DESCRIPTIONS[fw] ?? `Consult ${fw} framework`
          }
        }
      }
    }
  } catch {
    // If Neo4j is offline, provide standard strategic bridge options
    if (currentFramework === "CWE") candidates["CAPEC"] = FRAMEWORK_DESCRIPTIONS.CAPEC
    if (currentFramework === "CAPEC") candidates["ATTACK"] = FRAMEWORK_DESCRIPTIONS.ATTACK
    if (currentFramework === "ATTACK") candidates["D3FEND"] = FRAMEWORK_DESCRIPTIONS.D3FEND
  }

  if (candidates.D3FEND) {
    candidates.D3FEND = "Consult D3FEND defensive countermeasures (Primary Mitigation Target)"
  }

  return candidates
}

const SCOPED_NEIGHBORS_CYPHER = `
    MATCH (curr)
    WHERE coalesce(curr.capecId, curr.cweId, curr.attackId, curr.d3fendId, curr.atlasId, curr.subDomainId, curr.domainId, curr.id) = $curr_id
    MATCH (curr)-[r]-(neighbor)
    WHERE (labels(neighbor)[0] = $target_fw OR $target_fw = 'ALL')
      AND NOT coalesce(neighbor.capecId, neighbor.cweId, neighbor.attackId, neighbor.d3fendId, neighbor.atlasId, neighbor.subDomainId, neighbor.domainId, neighbor.id) IN $visited_ids
    RETURN
        CASE WHEN startNode(r) = curr THEN 'OUTGOING' ELSE 'INCOMING' END AS direction,
        type(r) AS rel_type,
        labels(neighbor)[0] AS neighbor_label,
        coalesce(neighbor.capecId, neighbor.cweId, neighbor.attackId, neighbor.d3fendId, neighbor.atlasId, neighbor.subDomainId, neighbor.domainId, neighbor.id) AS neighbor_id,
        coalesce(neighbor.name, neighbor.title, neighbor.text, neighbor.id) AS neighbor_name,
        coalesce(neighbor.description, neighbor.definition, neighbor.solutions, '') AS neighbor_desc
    LIMIT 12`

export async function queryScopedNeighbors(
  currentNodeId: string,
  targetFramework: string,
  visitedIds: string[],
): Promise<{ neighbors: NeighborRecord[]; cypher: string; params: Record<string, unknown> }> {
  // If snapshot is present, query directly from in-memory index
  if (fs.existsSync(CANONICAL_SNAPSHOT_PATH)) {
    try {
      const raw = fs.readFileSync(CANONICAL_SNAPSHOT_PATH, "utf-8")
      const parsed = JSON.parse(raw)
      const normCurr = currentNodeId.trim().toUpperCase()
      const visited = new Set(visitedIds.map(v => v.trim().toUpperCase()))
      
      const nodeMap = new Map<string, any>()
      for (const n of parsed.nodes) {
        nodeMap.set(n.id.toUpperCase(), n)
      }

      const neighbors: NeighborRecord[] = []
      for (const e of parsed.edges) {
        const from = e.from.toUpperCase()
        const to = e.to.toUpperCase()
        if (from === normCurr && !visited.has(to)) {
          const tgt = nodeMap.get(to)
          if (tgt && (targetFramework === "ALL" || tgt.group === targetFramework)) {
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
        } else if (to === normCurr && !visited.has(from)) {
          const src = nodeMap.get(from)
          if (src && (targetFramework === "ALL" || src.group === targetFramework)) {
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

      if (neighbors.length > 0) {
        return {
          neighbors,
          cypher: `Decoupled Canonical Index Lookup (${normCurr} -> ${targetFramework})`,
          params: { currentNodeId, targetFramework }
        }
      }
    } catch (e) {
      console.warn("[GraphService] Error querying snapshot, falling back to Neo4j:", e)
    }
  }

  // Fallback to Neo4j
  const params = { curr_id: currentNodeId, target_fw: targetFramework, visited_ids: visitedIds }
  let { records } = await neo4jDriver.executeQuery(SCOPED_NEIGHBORS_CYPHER, params)

  if (records.length === 0 && targetFramework !== "ALL") {
    const fallbackParams = { curr_id: currentNodeId, target_fw: "ALL", visited_ids: visitedIds }
    const fallbackRes = await neo4jDriver.executeQuery(SCOPED_NEIGHBORS_CYPHER, fallbackParams)
    records = fallbackRes.records
  }

  const neighbors = records.map((record: Neo4jRecord) => ({
    direction: record.get("direction") as NeighborRecord["direction"],
    relType: String(record.get("rel_type")),
    neighborLabel: String(record.get("neighbor_label") ?? "DEFAULT"),
    neighborId: String(record.get("neighbor_id") ?? ""),
    neighborName: String(record.get("neighbor_name") ?? ""),
    neighborDesc: String(record.get("neighbor_desc") ?? ""),
  }))

  return { neighbors, cypher: SCOPED_NEIGHBORS_CYPHER.trim(), params }
}

export async function queryNeighbors(
  currentNodeId: string,
  visitedIds: string[],
): Promise<{ neighbors: NeighborRecord[]; cypher: string; params: Record<string, unknown> }> {
  return queryScopedNeighbors(currentNodeId, "ALL", visitedIds)
}
'''
        backend_graph_file.write_text(code, encoding="utf-8")
        print(f"[2/2] Updated {backend_graph_file} with canonical snapshot support!")


if __name__ == "__main__":
    update()
