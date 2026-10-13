"""Synchronize Modular Threat Modeling & Jev System 1 Architecture into Template_React."""

import sys
import shutil
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

JEV_DIR = Path(r"c:\Users\paulo.ribeiro\OneDrive - Instituto CCG ZGDV\Documentos\Repositorios\Jev")
REACT_DIR = Path(r"c:\Users\paulo.ribeiro\OneDrive - Instituto CCG ZGDV\Documentos\Repositorios\Template_React")


def sync():
    print("=" * 60)
    print("🔄 SINCRONIZAÇÃO DA ARQUITETURA MODULAR PARA TEMPLATE_REACT")
    print("=" * 60)

    # 1. Update backend/src/services/graph.ts
    print("\n[1/6] Atualizar backend: services/graph.ts...")
    backend_graph_file = REACT_DIR / "backend" / "src" / "services" / "graph.ts"
    backend_graph_code = '''import type { Record as Neo4jRecord } from "neo4j-driver"
import { neo4jDriver } from "../lib/neo4j.js"

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

export function detectNodeFramework(nodeId: string): string {
  if (nodeId.startsWith("CAPEC-")) return "CAPEC"
  if (nodeId.startsWith("CWE-")) return "CWE"
  if (nodeId.startsWith("AML.T")) return "ATLAS"
  if (nodeId.startsWith("T") && /\\d/.test(nodeId)) return "ATTACK"
  if (nodeId.startsWith("D3-") || nodeId.startsWith("D3A-")) return "D3FEND"
  if (nodeId.startsWith("D-")) return "SubDomain"
  return "UNKNOWN"
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
    backend_graph_file.write_text(backend_graph_code, encoding="utf-8")
    print(f"      -> {backend_graph_file} atualizado!")

    # 2. Update backend/src/services/traversal.ts
    print("\n[2/6] Atualizar backend: services/traversal.ts com templates modulares e Meta-Router...")
    backend_traversal_file = REACT_DIR / "backend" / "src" / "services" / "traversal.ts"
    backend_traversal_code = '''import {
  systemOne,
  type ChoiceQuestion,
  type JevAnswer,
  type NoulQuestion,
  type ScoreQuestion,
} from "../lib/jev.js"
import {
  detectNodeFramework,
  queryCandidateFrameworks,
  queryScopedNeighbors,
  type NeighborRecord,
} from "./graph.js"

export const GOAL_THRESHOLD = 0.7

interface DomainTemplate {
  name: string
  buildGoalQuestion: (nodeId: string, goal: string) => string
  buildChoiceQuestion: (goal: string) => string
  buildScoreQuestion: (goal: string) => string
}

const TEMPLATES: Record<string, DomainTemplate> = {
  CAPEC: {
    name: "CAPECTemplate",
    buildGoalQuestion: (nodeId, goal) =>
      `Does the current attack pattern '${nodeId}' represent the terminal compromise or exploit described in: '${goal}'?`,
    buildChoiceQuestion: (goal) =>
      `Given the threat objective '${goal}', which attack branch represents the most critical progression?`,
    buildScoreQuestion: (goal) =>
      `Evaluate how aggressively this attack state exploits the target relative to: '${goal}'.`,
  },
  CWE: {
    name: "CWETemplate",
    buildGoalQuestion: (nodeId, goal) =>
      `Is software weakness '${nodeId}' the exact root cause flaw described in: '${goal}'?`,
    buildChoiceQuestion: (goal) =>
      `Given the goal '${goal}', which weakness or flaw branch leads closer to resolving or verifying the root cause?`,
    buildScoreQuestion: (goal) =>
      `Evaluate how closely this software weakness relates to the root cause of: '${goal}'.`,
  },
  ATTACK: {
    name: "AttackTemplate",
    buildGoalQuestion: (nodeId, goal) =>
      `Does adversary technique '${nodeId}' fulfill the operational objective: '${goal}'?`,
    buildChoiceQuestion: (goal) =>
      `Given the goal '${goal}', which adversary technique branch advances the attack chain towards the target?`,
    buildScoreQuestion: (goal) =>
      `Rate how effectively this technique executes the adversarial objective: '${goal}'.`,
  },
  ATLAS: {
    name: "AtlasTemplate",
    buildGoalQuestion: (nodeId, goal) =>
      `Does AI/ML threat '${nodeId}' satisfy the adversarial goal: '${goal}'?`,
    buildChoiceQuestion: (goal) =>
      `Given the goal '${goal}', which AI/ML attack technique branch represents the best vector?`,
    buildScoreQuestion: (goal) =>
      `Evaluate how well this AI/ML threat aligns with: '${goal}'.`,
  },
  D3FEND: {
    name: "D3FENDTemplate",
    buildGoalQuestion: (nodeId, goal) =>
      `Does defensive countermeasure '${nodeId}' effectively mitigate, verify, or neutralize: '${goal}'?`,
    buildChoiceQuestion: (goal) =>
      `Given the security goal '${goal}', which defensive countermeasure provides the strongest protection?`,
    buildScoreQuestion: (goal) =>
      `Evaluate how directly this defensive measure mitigates the threat in: '${goal}'.`,
  },
}

export type TraversalHopInput = {
  currentNode: string
  traversedPath: string[]
  goal: string
}

export type TraversalStep = {
  hop: number
  currentNode: string
  jevSource: "api" | "mock"
  level1Router?: {
    currentFramework: string
    targetFramework: string
    routerDecision: string
    latencyMs: number
    candidates: Record<string, string>
    phaseScore?: number
  }
  level2Explorer?: {
    templateUsed: string
    activeFramework: string
    latencyMs: number
  }
  cypher: {
    query: string
    params: Record<string, unknown>
    neighbors: NeighborRecord[]
    timeMs: number
  }
  jevQuestions: {
    goalReached: NoulQuestion["instructions"]
    bestNextStep: ChoiceQuestion["instructions"]
    bestNextStepCriteria: Record<string, string>
    heuristicScore: ScoreQuestion["instructions"]
  }
  jevResponse: {
    noulGoal: number
    choiceStep: string
    scoreHeuristic: number
    latencyMs: number
    model: string
  }
}

export type TraversalHopResult =
  | { status: "dead-end"; currentNode: string; message: string }
  | {
      status: "moved"
      step: TraversalStep
      goalAchieved: boolean
      currentNode: string
      traversedPath: string[]
    }

export async function executeTraversalHop(
  input: TraversalHopInput,
): Promise<TraversalHopResult> {
  // --- LEVEL 1: META-ROUTER ---
  const currentFw = detectNodeFramework(input.currentNode)
  const candidateFws = await queryCandidateFrameworks(input.currentNode, currentFw)

  let targetFramework = currentFw
  let routerDecision = "STAY_LOCAL"
  let routerLatencyMs = 0
  let phaseScore = 0

  const candidateKeys = Object.keys(candidateFws)
  if (candidateKeys.length > 1) {
    const routerState = {
      user_goal: input.goal,
      current_node: input.currentNode,
      current_framework: currentFw,
      traversed_path: input.traversedPath.join(" -> "),
      candidate_frameworks: candidateFws,
    }
    const routerQuestions = {
      next_framework: {
        type: "choice",
        instructions: `Given the user goal '${input.goal}', which framework domain should be queried next?`,
        criteria: candidateFws,
      } satisfies ChoiceQuestion,
      phase_progress: {
        type: "score",
        instructions: `Rate the progression towards completing '${input.goal}' in current phase (${currentFw}).`,
        criteria: ["initial exploration", "intermediate bridge", "near target", "target domain reached"],
      } satisfies ScoreQuestion,
    }

    const routerResult = await systemOne(routerState, routerQuestions)
    routerLatencyMs = routerResult.latencyMs
    routerDecision = extractChoice(routerResult.answers.next_framework)
    phaseScore = extractScore(routerResult.answers.phase_progress)
    targetFramework = routerDecision === "STAY_LOCAL" ? currentFw : routerDecision
  }

  // --- LEVEL 2: SCOPED EXPLORER COM TEMPLATE DE DOMÍNIO ---
  const template = TEMPLATES[targetFramework] ?? TEMPLATES.D3FEND
  const cypherStartedAt = performance.now()
  const { neighbors, cypher, params } = await queryScopedNeighbors(
    input.currentNode,
    targetFramework,
    input.traversedPath,
  )
  const cypherTimeMs = performance.now() - cypherStartedAt

  if (neighbors.length === 0) {
    return {
      status: "dead-end",
      currentNode: input.currentNode,
      message: `Sem ramos por visitar em ${targetFramework} a partir de '${input.currentNode}'. Travessia terminada.`,
    }
  }

  const criteriaOptions: Record<string, string> = {}
  const optionMap = new Map<string, NeighborRecord>()
  neighbors.forEach((neighbor, index) => {
    const optionKey = `branch_${index + 1}`
    const arrow = neighbor.direction === "OUTGOING" ? "->" : "<-"
    let relLabel = neighbor.relType
    if (relLabel === "MITIGATES" && neighbor.direction === "INCOMING") {
      relLabel = "DEFENDED_BY"
    }

    criteriaOptions[optionKey] =
      `[${relLabel}] ${arrow} [${neighbor.neighborLabel}] ` +
      `'${neighbor.neighborName}' (${neighbor.neighborId}): ${neighbor.neighborDesc.slice(0, 120)}`
    optionMap.set(optionKey, neighbor)
  })

  const scopedState = {
    user_goal: input.goal,
    current_node: input.currentNode,
    active_framework: targetFramework,
    scoped_branches: criteriaOptions,
  }

  const scopedQuestions = {
    goal_reached: {
      type: "noul",
      instructions: template.buildGoalQuestion(input.currentNode, input.goal),
    } satisfies NoulQuestion,
    best_next_step: {
      type: "choice",
      instructions: template.buildChoiceQuestion(input.goal),
      criteria: criteriaOptions,
    } satisfies ChoiceQuestion,
    heuristic_score: {
      type: "score",
      instructions: template.buildScoreQuestion(input.goal),
      criteria: ["not aligned", "moderately aligned", "highly aligned", "critically aligned"],
    } satisfies ScoreQuestion,
  }

  const jevResult = await systemOne(scopedState, scopedQuestions)
  const noulGoal = extractNoul(jevResult.answers.goal_reached)
  const choiceStep = extractChoice(jevResult.answers.best_next_step)
  const scoreHeuristic = extractScore(jevResult.answers.heuristic_score)

  const goalAchieved = noulGoal >= GOAL_THRESHOLD
  const totalLatency = routerLatencyMs + jevResult.latencyMs

  const step: TraversalStep = {
    hop: input.traversedPath.length,
    currentNode: input.currentNode,
    jevSource: jevResult.source,
    level1Router: {
      currentFramework: currentFw,
      targetFramework,
      routerDecision,
      latencyMs: routerLatencyMs,
      candidates: candidateFws,
      phaseScore,
    },
    level2Explorer: {
      templateUsed: template.name,
      activeFramework: targetFramework,
      latencyMs: jevResult.latencyMs,
    },
    cypher: { query: cypher, params, neighbors, timeMs: cypherTimeMs },
    jevQuestions: {
      goalReached: scopedQuestions.goal_reached.instructions,
      bestNextStep: scopedQuestions.best_next_step.instructions,
      bestNextStepCriteria: criteriaOptions,
      heuristicScore: scopedQuestions.heuristic_score.instructions,
    },
    jevResponse: {
      noulGoal,
      choiceStep,
      scoreHeuristic,
      latencyMs: totalLatency,
      model: jevResult.model,
    },
  }

  let nextPath = input.traversedPath
  let currentNode = input.currentNode
  if (!goalAchieved) {
    const chosen = optionMap.get(choiceStep) ?? neighbors[0]
    if (chosen && chosen.neighborId) {
      currentNode = chosen.neighborId
      nextPath = [...input.traversedPath, chosen.neighborId]
    }
  }

  return { status: "moved", step, goalAchieved, currentNode, traversedPath: nextPath }
}

function extractNoul(answer: JevAnswer | undefined): number {
  if (!answer || answer.type !== "noul") {
    throw new Error("Resposta do Jev sem o noul 'goal_reached'")
  }
  return answer.noul
}

function extractChoice(answer: JevAnswer | undefined): string {
  if (!answer || answer.type !== "choice") {
    throw new Error("Resposta do Jev sem o choice 'best_next_step'")
  }
  return answer.choice
}

function extractScore(answer: JevAnswer | undefined): number {
  if (!answer || answer.type !== "score") {
    throw new Error("Resposta do Jev sem o score 'heuristic_score'")
  }
  return answer.score
}
'''
    backend_traversal_file.write_text(backend_traversal_code, encoding="utf-8")
    print(f"      -> {backend_traversal_file} atualizado!")

    # 3. Update frontend/src/services/Explorer/types.ts
    print("\n[3/6] Atualizar frontend: services/Explorer/types.ts...")
    frontend_types_file = REACT_DIR / "frontend" / "src" / "services" / "Explorer" / "types.ts"
    frontend_types_code = '''export type GraphNode = {
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

export type GraphSnapshot = {
  nodes: GraphNode[]
  edges: GraphEdge[]
}

export type NeighborRecord = {
  direction: "OUTGOING" | "INCOMING"
  relType: string
  neighborLabel: string
  neighborId: string
  neighborName: string
  neighborDesc: string
}

export type TraversalStep = {
  hop: number
  currentNode: string
  jevSource: "api" | "mock"
  level1Router?: {
    currentFramework: string
    targetFramework: string
    routerDecision: string
    latencyMs: number
    candidates: Record<string, string>
    phaseScore?: number
  }
  level2Explorer?: {
    templateUsed: string
    activeFramework: string
    latencyMs: number
  }
  cypher: {
    query: string
    params: Record<string, unknown>
    neighbors: NeighborRecord[]
    timeMs: number
  }
  jevQuestions: {
    goalReached: string
    bestNextStep: string
    bestNextStepCriteria: Record<string, string>
    heuristicScore: string
  }
  jevResponse: {
    noulGoal: number
    choiceStep: string
    scoreHeuristic: number
    latencyMs: number
    model: string
  }
}

export type TraversalHopResult =
  | { status: "dead-end"; currentNode: string; message: string }
  | {
      status: "moved"
      step: TraversalStep
      goalAchieved: boolean
      currentNode: string
      traversedPath: string[]
    }

export type TraversalHopBody = {
  currentNode: string
  traversedPath: string[]
  goal: string
}

export type Manuscript = {
  name: string
  content: string
}
'''
    frontend_types_file.write_text(frontend_types_code, encoding="utf-8")
    print(f"      -> {frontend_types_file} atualizado!")

    # 4. Update frontend/src/pages/Explorer/hop-inspector.tsx
    print("\n[4/6] Atualizar frontend: pages/Explorer/hop-inspector.tsx com visualização de dois níveis...")
    frontend_inspector_file = REACT_DIR / "frontend" / "src" / "pages" / "Explorer" / "hop-inspector.tsx"
    frontend_inspector_code = '''import { Badge } from "@/components/ui/badge"
import { Progress } from "@/components/ui/progress"
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs"
import { GOAL_THRESHOLD } from "@/services"
import type { TraversalStep } from "@/services"
import { CheckCircle2, CircleArrowLeft, CircleArrowRight, Layers } from "lucide-react"

export function HopInspector({ step }: { step: TraversalStep }) {
  const { noulGoal, choiceStep, scoreHeuristic, latencyMs } = step.jevResponse
  const l1 = step.level1Router
  const l2 = step.level2Explorer

  return (
    <div className="flex flex-col gap-3">
      {l1 && (
        <div className="flex items-center justify-between rounded-md border border-emerald-500/30 bg-emerald-500/10 p-2.5 text-xs">
          <div className="flex items-center gap-2">
            <Layers className="size-4 text-emerald-400" />
            <span>
              <b className="text-emerald-400">Hierarquia Modular:</b>{" "}
              {l1.currentFramework} ➔{" "}
              <span className="font-semibold text-emerald-300">{l1.targetFramework}</span>
            </span>
          </div>
          <Badge variant="outline" className="border-emerald-500/40 text-[10px] text-emerald-300">
            {l2?.templateUsed ?? "DomainTemplate"}
          </Badge>
        </div>
      )}

      <Tabs defaultValue={l1 ? "router" : "cypher"}>
        <TabsList className="flex w-full flex-wrap">
          {l1 && <TabsTrigger value="router">1. Meta-Router</TabsTrigger>}
          <TabsTrigger value="cypher">{l1 ? "2. Template Scoped" : "1. Cypher"}</TabsTrigger>
          <TabsTrigger value="state">{l1 ? "3. Questões" : "2. Estado"}</TabsTrigger>
          <TabsTrigger value="decision">{l1 ? "4. Decisão" : "3. Decisão"}</TabsTrigger>
        </TabsList>

        {l1 && (
          <TabsContent value="router" className="flex flex-col gap-3">
            <p className="text-sm">
              <span className="font-medium">Nível 1 — Meta-Router de Decisão</span>{" "}
              <span className="text-muted-foreground">({l1.latencyMs.toFixed(1)}ms)</span>
            </p>
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="rounded-md border p-2">
                <span className="text-muted-foreground">Framework Origem:</span>{" "}
                <b>{l1.currentFramework}</b>
              </div>
              <div className="rounded-md border p-2">
                <span className="text-muted-foreground">Framework Alvo:</span>{" "}
                <b className="text-emerald-400">{l1.targetFramework}</b>
              </div>
            </div>
            <p className="text-sm font-medium">Candidatos de Roteamento Avaliados:</p>
            <pre className="max-h-40 overflow-auto rounded-md bg-muted p-2 text-xs">
              {JSON.stringify(l1.candidates, null, 2)}
            </pre>
          </TabsContent>
        )}

        <TabsContent value="cypher" className="flex flex-col gap-3">
          <p className="text-sm">
            <span className="font-medium">Query Cypher Scoped</span>{" "}
            <span className="text-muted-foreground">
              ({step.cypher.timeMs.toFixed(1)}ms · {step.cypher.neighbors.length} vizinhos)
            </span>
          </p>
          <pre className="max-h-48 overflow-auto rounded-md bg-muted p-3 text-xs leading-relaxed">
            {step.cypher.query}
          </pre>
          <p className="text-sm">
            <span className="font-medium">Parâmetros:</span>{" "}
            <code className="text-xs">{JSON.stringify(step.cypher.params)}</code>
          </p>
          <p className="text-sm font-medium">Vizinhos no Escopo ({step.cypher.neighbors.length}):</p>
          <ol className="flex flex-col gap-1">
            {step.cypher.neighbors.map((neighbor, index) => (
              <li key={`${neighbor.neighborId}-${index}`} className="text-sm">
                <span className="font-medium">[{index + 1}]</span>{" "}
                {neighbor.direction === "OUTGOING" ? (
                  <CircleArrowRight className="inline size-4" />
                ) : (
                  <CircleArrowLeft className="inline size-4" />
                )}{" "}
                <code className="text-xs">:{neighbor.relType}</code> ➜{" "}
                <span className="font-medium">{neighbor.neighborLabel}</span> (
                <code className="text-xs">{neighbor.neighborId}</code>):{" "}
                <em>{neighbor.neighborName}</em>
              </li>
            ))}
          </ol>
        </TabsContent>

        <TabsContent value="state" className="flex flex-col gap-3">
          <p className="text-sm font-medium">Questões formuladas pelo Template de Domínio:</p>
          <ul className="flex flex-col gap-1 text-sm">
            <li>
              <Badge variant="secondary">Noul</Badge>{" "}
              <span className="font-medium">Verificação de objetivo:</span>{" "}
              {step.jevQuestions.goalReached}
            </li>
            <li>
              <Badge variant="secondary">Choice</Badge>{" "}
              <span className="font-medium">Encaminhamento no Domínio:</span>{" "}
              {step.jevQuestions.bestNextStep}
            </li>
            <li>
              <Badge variant="secondary">Score</Badge>{" "}
              <span className="font-medium">Heurística:</span>{" "}
              {step.jevQuestions.heuristicScore}
            </li>
          </ul>
          <p className="text-sm font-medium">Critérios de Ramos Scoped:</p>
          <ul className="flex flex-col gap-1 text-xs">
            {Object.entries(step.jevQuestions.bestNextStepCriteria).map(
              ([key, description]) => (
                <li key={key}>
                  <code className="font-medium text-emerald-400">{key}</code>: {description}
                </li>
              ),
            )}
          </ul>
        </TabsContent>

        <TabsContent value="decision" className="flex flex-col gap-4">
          <div className="grid grid-cols-3 gap-2 text-center">
            <div className="rounded-lg border p-3">
              <p className="text-xs text-muted-foreground">
                Confiança no objetivo (Noul)
              </p>
              <p className="text-xl font-bold">{Math.round(noulGoal * 100)}%</p>
            </div>
            <div className="rounded-lg border p-3">
              <p className="text-xs text-muted-foreground">Ramo escolhido</p>
              <p className="truncate text-xl font-bold" title={choiceStep}>
                {choiceStep}
              </p>
            </div>
            <div className="rounded-lg border p-3">
              <p className="text-xs text-muted-foreground">Pontuação</p>
              <p className="text-xl font-bold">{scoreHeuristic.toFixed(2)}</p>
            </div>
          </div>

          <div className="flex flex-col gap-2">
            <p className="text-sm font-medium">
              Probabilidade de objetivo alcançado:
            </p>
            <Progress value={Math.min(100, noulGoal * 100)} />
          </div>

          {noulGoal >= GOAL_THRESHOLD ? (
            <p className="flex items-center gap-2 text-sm text-emerald-600 dark:text-emerald-400">
              <CheckCircle2 className="size-4" />
              Objetivo alcançado! Nó alvo: <code>{step.currentNode}</code>
            </p>
          ) : (
            <p className="text-sm text-muted-foreground">
              Decisão: seguir <code>{choiceStep}</code> para o próximo nó.
            </p>
          )}

          <p className="text-xs text-muted-foreground">
            Modelo: <code>{step.jevResponse.model}</code> ·{" "}
            {latencyMs.toFixed(1)}ms total ·{" "}
            <Badge variant={step.jevSource === "mock" ? "outline" : "secondary"}>
              {step.jevSource === "mock" ? "modo mock" : "API Jev"}
            </Badge>
          </p>
        </TabsContent>
      </Tabs>
    </div>
  )
}
'''
    frontend_inspector_file.write_text(frontend_inspector_code, encoding="utf-8")
    print(f"      -> {frontend_inspector_file} atualizado!")

    # 5. Update frontend/src/pages/Explorer/traversal-timeline.tsx
    print("\n[5/6] Atualizar frontend: pages/Explorer/traversal-timeline.tsx com coluna de Framework...")
    frontend_timeline_file = REACT_DIR / "frontend" / "src" / "pages" / "Explorer" / "traversal-timeline.tsx"
    frontend_timeline_code = '''import { Badge } from "@/components/ui/badge"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { GOAL_THRESHOLD } from "@/services"
import type { TraversalStep } from "@/services"
import { CheckCircle2, ChevronRight } from "lucide-react"

export function TraversalTimeline({
  steps,
  selectedIdx,
  onSelect,
}: {
  steps: TraversalStep[]
  selectedIdx: number
  onSelect: (idx: number) => void
}) {
  if (steps.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">
        Ainda não foram executados hops nesta sessão.
      </p>
    )
  }

  return (
    <div className="rounded-md border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-16">Hop #</TableHead>
            <TableHead>Nó Atual</TableHead>
            <TableHead>Framework / Template</TableHead>
            <TableHead>Confiança (Noul)</TableHead>
            <TableHead>Ramo Escolhido</TableHead>
            <TableHead>Heurística</TableHead>
            <TableHead>Latência</TableHead>
            <TableHead className="w-32">Estado</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {steps.map((step, index) => {
            const isGoal = step.jevResponse.noulGoal >= GOAL_THRESHOLD
            const fwLabel = step.level1Router
              ? `${step.level1Router.targetFramework} (${step.level2Explorer?.templateUsed ?? ""})`
              : "Direct"
            const isSelected = index === selectedIdx

            return (
              <TableRow
                key={`${step.currentNode}-${index}`}
                className={`cursor-pointer hover:bg-muted/50 ${isSelected ? "bg-muted/80 font-medium" : ""}`}
                onClick={() => onSelect(index)}
              >
                <TableCell className="font-medium">{step.hop}</TableCell>
                <TableCell>
                  <code>{step.currentNode}</code>
                </TableCell>
                <TableCell>
                  <Badge variant="outline" className="border-emerald-500/30 text-xs">
                    {fwLabel}
                  </Badge>
                </TableCell>
                <TableCell>
                  <span className="font-semibold">
                    {Math.round(step.jevResponse.noulGoal * 100)}%
                  </span>
                </TableCell>
                <TableCell className="text-xs">
                  <code>{step.jevResponse.choiceStep}</code>
                </TableCell>
                <TableCell>{step.jevResponse.scoreHeuristic.toFixed(2)}</TableCell>
                <TableCell className="text-xs text-muted-foreground">
                  {step.jevResponse.latencyMs.toFixed(1)}ms
                </TableCell>
                <TableCell>
                  {isGoal ? (
                    <Badge className="bg-emerald-600 text-white hover:bg-emerald-700">
                      <CheckCircle2 className="mr-1 size-3" /> Alvo
                    </Badge>
                  ) : (
                    <Badge variant="secondary">
                      <ChevronRight className="mr-1 size-3" /> Avançar
                    </Badge>
                  )}
                </TableCell>
              </TableRow>
            )
          })}
        </TableBody>
      </Table>
    </div>
  )
}
'''
    frontend_timeline_file.write_text(frontend_timeline_code, encoding="utf-8")
    print(f"      -> {frontend_timeline_file} atualizado!")

    # 6. Sincronizar todos os manuscritos para Template_React/backend/content/manuscritos/
    print("\n[6/6] Sincronizar todos os Manuscritos de Investigação...")
    src_manuscripts = JEV_DIR / "manuscritos"
    dst_manuscripts = REACT_DIR / "backend" / "content" / "manuscritos"
    dst_manuscripts.mkdir(parents=True, exist_ok=True)
    for m in src_manuscripts.glob("*.md"):
        shutil.copy2(m, dst_manuscripts / m.name)
        print(f"      -> {m.name} sincronizado!")

    print("\n" + "=" * 60)
    print("✅ TODAS AS ALTERAÇÕES MODULARES FORAM SINCRONIZADAS COM SUCESSO!")
    print("=" * 60)


if __name__ == "__main__":
    sync()
