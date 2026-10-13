"""Full-Stack Synchronization of Complete Meta-Router, Templates Catalog, and Multi-KG Explorer."""

import sys
import shutil
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8")

JEV_DIR = Path(r"c:\Users\paulo.ribeiro\OneDrive - Instituto CCG ZGDV\Documentos\Repositorios\Jev")
REACT_DIR = Path(r"c:\Users\paulo.ribeiro\OneDrive - Instituto CCG ZGDV\Documentos\Repositorios\Template_React")


def sync():
    print("=" * 65)
    print("🚀 SINCRONIZANDO META-ROUTER COMPLETO, TEMPLATES E MULTI-KG")
    print("=" * 65)

    # 1. Update backend/src/schemas/traversal.ts
    print("\n[1/8] Atualizar backend/src/schemas/traversal.ts...")
    backend_schema_file = REACT_DIR / "backend" / "src" / "schemas" / "traversal.ts"
    backend_schema_code = '''import { z } from "zod"

export const strategyEnum = z.enum(["canonical", "fast_defense", "threat_hunting", "free"])

export const traversalHopSchema = z.object({
  currentNode: z.string().min(1, "Nó atual é obrigatório"),
  traversedPath: z.array(z.string().min(1)).min(1, "Caminho percorrido é obrigatório"),
  goal: z.string().min(1, "Objetivo de pesquisa é obrigatório").max(2000),
  strategy: strategyEnum.optional().default("canonical"),
})

export const directQuerySchema = z.object({
  currentNode: z.string().min(1, "Nó é obrigatório"),
  frameworks: z.array(z.string().min(1)).min(1, "Pelo menos um framework é obrigatório"),
  goal: z.string().min(1, "Pergunta ou objetivo é obrigatório").max(2000),
})

export const manuscriptNameSchema = z
  .string()
  .regex(/^[\\w.-]+\\.md$/, "Nome de manuscrito inválido")

export type TraversalHopBody = z.infer<typeof traversalHopSchema>
export type DirectQueryBody = z.infer<typeof directQuerySchema>
'''
    backend_schema_file.write_text(backend_schema_code, encoding="utf-8")
    print(f"      -> {backend_schema_file} atualizado!")

    # 2. Update backend/src/services/traversal.ts
    print("\n[2/8] Atualizar backend/src/services/traversal.ts com estratégias e catálogo...")
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

export type TraversalStrategy = "canonical" | "fast_defense" | "threat_hunting" | "free"

export interface TemplateDefinition {
  framework: string
  name: string
  label: string
  icon: string
  color: string
  description: string
  goalQuestion: string
  choiceQuestion: string
  scoreQuestion: string
  criteriaScale: string[]
}

const TEMPLATES_CATALOG: TemplateDefinition[] = [
  {
    framework: "CAPEC",
    name: "CAPECTemplate",
    label: "Attack Pattern",
    icon: "Crosshair",
    color: "#F97316",
    description: "Explora padrões de ataque, pré-requisitos, fluxo de execução e escalada de privilégios.",
    goalQuestion: "Is the current entity '{node}' already the final desired answer or countermeasure for the user goal: '{goal}'?",
    choiceQuestion: "Given the threat objective '{goal}', which attack branch represents the most critical progression or intermediate bridge?",
    scoreQuestion: "How relevant is this attack pattern to the overall threat investigation '{goal}'?",
    criteriaScale: ["Low relevance attack", "Moderate prerequisite attack", "Direct primary attack vector"],
  },
  {
    framework: "CWE",
    name: "CWETemplate",
    label: "Software Weakness",
    icon: "Bug",
    color: "#8B5CF6",
    description: "Explora fraquezas a nível de código, falhas de arquitetura e causas-raiz fundamentais.",
    goalQuestion: "Does the software weakness '{node}' constitute the definitive solution to the goal: '{goal}'?",
    choiceQuestion: "Given the goal '{goal}', which branch represents the core programming or architectural root-cause flaw?",
    scoreQuestion: "Rate the severity of this software weakness in relation to '{goal}':",
    criteriaScale: ["Peripheral code defect", "Significant security flaw", "Critical exploitable vulnerability"],
  },
  {
    framework: "ATTACK",
    name: "AttackTemplate",
    label: "Adversary Technique",
    icon: "Flame",
    color: "#EF4444",
    description: "Explora técnicas táticas e procedimentos operacionais (TTPs) do MITRE Enterprise ATT&CK.",
    goalQuestion: "Does adversary technique '{node}' directly satisfy the goal: '{goal}'?",
    choiceQuestion: "Given the goal '{goal}', which adversary technique branch advances the operational attack chain towards the target?",
    scoreQuestion: "How critical is this adversary technique to achieving the objective '{goal}'?",
    criteriaScale: ["Incidental technique", "Core enabling technique", "Direct impact technique"],
  },
  {
    framework: "ATLAS",
    name: "AtlasTemplate",
    label: "AI/ML Threat",
    icon: "Cpu",
    color: "#E11D48",
    description: "Explora ameaças específicas a sistemas de Inteligência Artificial e Machine Learning (prompt injection, model evasion, data poisoning).",
    goalQuestion: "Does AI/ML threat technique '{node}' satisfy the adversarial goal: '{goal}'?",
    choiceQuestion: "Given the goal '{goal}', which branch captures the specific AI attack vector (prompt manipulation, data evasion, or model theft)?",
    scoreQuestion: "Rate the specificity of this AI attack technique for '{goal}':",
    criteriaScale: ["Generic IT threat", "Indirect ML effect", "Direct adversarial AI exploit"],
  },
  {
    framework: "D3FEND",
    name: "D3FENDTemplate",
    label: "Defensive Countermeasure",
    icon: "ShieldCheck",
    color: "#10B981",
    description: "Explora contramedidas defensivas de engenharia do MITRE D3FEND (Harden, Detect, Isolate, Evict, Model, Verify).",
    goalQuestion: "Does this defensive countermeasure '{node}' directly satisfy, neutralize, or answer the user's defensive security goal: '{goal}'?",
    choiceQuestion: "Given the security goal '{goal}', which D3FEND technique offers the most effective and direct mitigation for the identified threat?",
    scoreQuestion: "Rate the mitigation effectiveness of this defensive countermeasure against '{goal}':",
    criteriaScale: ["Marginal defense", "Partial hardening/detection", "Complete primary mitigation"],
  },
  {
    framework: "META_ROUTER",
    name: "MetaRouterTemplate",
    label: "Ontology Meta-Router",
    icon: "Compass",
    color: "#06B6D4",
    description: "Avalia transições entre taxonomias e seleciona os especialistas de domínio mais adequados (CWE, CAPEC, ATT&CK, ATLAS, D3FEND).",
    goalQuestion: "Is current domain investigation phase concluding the user goal: '{goal}'?",
    choiceQuestion: "Given the investigation goal '{goal}', which cybersecurity domain/framework should be navigated to next?",
    scoreQuestion: "How close is the current phase to concluding the defensive investigation for '{goal}'?",
    criteriaScale: ["Phase 1: Attack surface", "Phase 2: Technical flaw", "Phase 3: Adversary action", "Phase 4: Defensive mitigation"],
  },
]

export function getTemplateCatalog(): TemplateDefinition[] {
  return TEMPLATES_CATALOG
}

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
      `Is the current entity '${nodeId}' already the final desired answer or countermeasure for the user goal: '${goal}'? (Note: CAPEC represents offensive attacks, not defense).`,
    buildChoiceQuestion: (goal) =>
      `Given the threat objective '${goal}', which attack branch represents the most critical progression or intermediate bridge?`,
    buildScoreQuestion: (goal) =>
      `How relevant is this attack pattern to the overall threat investigation '${goal}'?`,
  },
  CWE: {
    name: "CWETemplate",
    buildGoalQuestion: (nodeId, goal) =>
      `Does software weakness '${nodeId}' constitute the definitive solution to the goal: '${goal}'? (Weaknesses represent flaws to patch, not solutions).`,
    buildChoiceQuestion: (goal) =>
      `Given the goal '${goal}', which branch represents the core programming or architectural root-cause flaw?`,
    buildScoreQuestion: (goal) =>
      `Rate the severity of this software weakness in relation to '${goal}':`,
  },
  ATTACK: {
    name: "AttackTemplate",
    buildGoalQuestion: (nodeId, goal) =>
      `Does adversary technique '${nodeId}' directly satisfy the goal: '${goal}'? (ATT&CK represents adversary actions, not defense).`,
    buildChoiceQuestion: (goal) =>
      `Given the goal '${goal}', which adversary technique branch advances the operational attack chain towards the target?`,
    buildScoreQuestion: (goal) =>
      `How critical is this adversary technique to achieving the objective '${goal}'?`,
  },
  ATLAS: {
    name: "AtlasTemplate",
    buildGoalQuestion: (nodeId, goal) =>
      `Does AI/ML threat technique '${nodeId}' satisfy the adversarial goal: '${goal}'?`,
    buildChoiceQuestion: (goal) =>
      `Given the goal '${goal}', which branch captures the specific AI attack vector (prompt manipulation, data evasion, or model theft)?`,
    buildScoreQuestion: (goal) =>
      `Rate the specificity of this AI attack technique for '${goal}':`,
  },
  D3FEND: {
    name: "D3FENDTemplate",
    buildGoalQuestion: (nodeId, goal) =>
      `Does this defensive countermeasure '${nodeId}' directly satisfy, neutralize, or answer the user's defensive security goal: '${goal}'?`,
    buildChoiceQuestion: (goal) =>
      `Given the security goal '${goal}', which D3FEND technique offers the most effective and direct mitigation for the identified threat?`,
    buildScoreQuestion: (goal) =>
      `Rate the mitigation effectiveness of this defensive countermeasure against '${goal}':`,
  },
}

export type TraversalHopInput = {
  currentNode: string
  traversedPath: string[]
  goal: string
  strategy?: TraversalStrategy
}

export type TraversalStep = {
  hop: number
  currentNode: string
  strategy?: TraversalStrategy
  jevSource: "api" | "mock"
  level1Router?: {
    currentFramework: string
    targetFramework: string
    routerDecision: string
    strategyApplied?: string
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
  const strategy: TraversalStrategy = input.strategy ?? "canonical"

  // --- LEVEL 1: META-ROUTER ---
  const currentFw = detectNodeFramework(input.currentNode)
  const candidateFws = await queryCandidateFrameworks(input.currentNode, currentFw)

  let targetFramework = currentFw
  let routerDecision = "STAY_LOCAL"
  let routerLatencyMs = 0
  let phaseScore = 0
  let strategyApplied: string = strategy

  // Fast Defense Shortcut: se D3FEND estiver diretamente ao alcance, salta imediatamente
  if (strategy === "fast_defense" && candidateFws.D3FEND) {
    targetFramework = "D3FEND"
    routerDecision = "D3FEND"
    strategyApplied = "fast_defense_shortcut"
    phaseScore = 1.0
  } else if (Object.keys(candidateFws).length > 1) {
    let strategyDesc = "Canonical Threat Modeling Pipeline (CWE -> CAPEC -> ATT&CK -> D3FEND)"
    if (strategy === "threat_hunting") {
      strategyDesc = "Threat Hunting Investigation (ATT&CK -> CAPEC -> CWE -> D3FEND)"
    } else if (strategy === "free") {
      strategyDesc = "Free Semantic Navigation"
    }

    const routerState = {
      user_goal: input.goal,
      strategy: strategyDesc,
      current_node: input.currentNode,
      current_framework: currentFw,
      traversed_path: input.traversedPath.join(" -> "),
      candidate_frameworks: candidateFws,
    }
    const routerQuestions = {
      next_framework: {
        type: "choice",
        instructions: `Strategy: '${strategyDesc}'. User Goal: '${input.goal}'. Which framework domain should be queried next?`,
        criteria: candidateFws,
      } satisfies ChoiceQuestion,
      phase_progress: {
        type: "score",
        instructions: `Rate the progression towards fulfilling '${input.goal}' in current phase (${currentFw}).`,
        criteria: ["Phase 1: Attack surface", "Phase 2: Technical flaw", "Phase 3: Adversary action", "Phase 4: Defensive mitigation"],
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
    strategy,
    jevSource: jevResult.source,
    level1Router: {
      currentFramework: currentFw,
      targetFramework,
      routerDecision,
      strategyApplied,
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

export type DirectQueryInput = {
  currentNode: string
  frameworks: string[]
  goal: string
}

export type DirectQueryFrameworkResult = {
  framework: string
  templateUsed: string
  neighborsCount: number
  branches: Record<string, string>
  chosenBranch: string
  chosenTarget: {
    id: string
    name: string
    label: string
  }
  noulGoal: number
  heuristicScore: number
  latencyMs: number
  jevQuestions: {
    goalReached: string
    bestBranch: string
    heuristicScore: string
  }
}

export type DirectQueryResult = {
  currentNode: string
  goal: string
  results: DirectQueryFrameworkResult[]
  totalLatencyMs: number
}

export async function executeDirectQuery(
  input: DirectQueryInput,
): Promise<DirectQueryResult> {
  const startedAt = performance.now()
  const results: DirectQueryFrameworkResult[] = []

  for (const fw of input.frameworks) {
    const template = TEMPLATES[fw] ?? TEMPLATES.D3FEND
    const { neighbors } = await queryScopedNeighbors(input.currentNode, fw, [])

    if (neighbors.length === 0) {
      continue
    }

    const branches: Record<string, string> = {}
    const optMap = new Map<string, NeighborRecord>()
    neighbors.slice(0, 8).forEach((n, idx) => {
      const key = `branch_${idx + 1}`
      const arrow = n.direction === "OUTGOING" ? "->" : "<-"
      branches[key] = `[${n.relType}] ${arrow} [${n.neighborLabel}] '${n.neighborName}' (${n.neighborId})`
      optMap.set(key, n)
    })

    const state = {
      user_goal: input.goal,
      current_node: input.currentNode,
      framework: fw,
      branches,
    }

    const questions = {
      goal_reached: {
        type: "noul",
        instructions: template.buildGoalQuestion(input.currentNode, input.goal),
      } satisfies NoulQuestion,
      best_branch: {
        type: "choice",
        instructions: template.buildChoiceQuestion(input.goal),
        criteria: branches,
      } satisfies ChoiceQuestion,
      heuristic_score: {
        type: "score",
        instructions: template.buildScoreQuestion(input.goal),
        criteria: ["not aligned", "moderately aligned", "highly aligned", "critically aligned"],
      } satisfies ScoreQuestion,
    }

    const res = await systemOne(state, questions)
    const noulGoal = extractNoul(res.answers.goal_reached)
    const chosenBranch = extractChoice(res.answers.best_branch)
    const heuristicScore = extractScore(res.answers.heuristic_score)
    const chosenObj = optMap.get(chosenBranch) ?? neighbors[0]

    results.push({
      framework: fw,
      templateUsed: template.name,
      neighborsCount: neighbors.length,
      branches,
      chosenBranch,
      chosenTarget: {
        id: chosenObj.neighborId,
        name: chosenObj.neighborName,
        label: chosenObj.neighborLabel,
      },
      noulGoal,
      heuristicScore,
      latencyMs: res.latencyMs,
      jevQuestions: {
        goalReached: questions.goal_reached.instructions,
        bestBranch: questions.best_branch.instructions,
        heuristicScore: questions.heuristic_score.instructions,
      },
    })
  }

  const totalLatencyMs = performance.now() - startedAt

  return {
    currentNode: input.currentNode,
    goal: input.goal,
    results,
    totalLatencyMs,
  }
}

function extractNoul(answer: JevAnswer | undefined): number {
  if (!answer || answer.type !== "noul") {
    throw new Error("Resposta do Jev sem o noul 'goal_reached'")
  }
  return answer.noul
}

function extractChoice(answer: JevAnswer | undefined): string {
  if (!answer || answer.type !== "choice") {
    throw new Error("Resposta do Jev sem o choice")
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

    # 3. Update backend/src/controllers/traversal.ts
    print("\n[3/8] Atualizar backend/src/controllers/traversal.ts com getTemplates e postDirectQuery...")
    backend_controller_file = REACT_DIR / "backend" / "src" / "controllers" / "traversal.ts"
    backend_controller_code = '''import type { NextFunction, Request, Response } from "express"
import type { DirectQueryBody, TraversalHopBody } from "../schemas/traversal.js"
import * as traversalService from "../services/traversal.js"

export async function postTraversalHop(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  try {
    const body = req.body as TraversalHopBody
    const result = await traversalService.executeTraversalHop(body)
    res.json(result)
  } catch (error) {
    next(error)
  }
}

export function getTemplates(
  _req: Request,
  res: Response,
) {
  const templates = traversalService.getTemplateCatalog()
  res.json(templates)
}

export async function postDirectQuery(
  req: Request,
  res: Response,
  next: NextFunction,
) {
  try {
    const body = req.body as DirectQueryBody
    const result = await traversalService.executeDirectQuery(body)
    res.json(result)
  } catch (error) {
    next(error)
  }
}
'''
    backend_controller_file.write_text(backend_controller_code, encoding="utf-8")
    print(f"      -> {backend_controller_file} atualizado!")

    # 4. Update backend/src/routes/graph.ts
    print("\n[4/8] Atualizar backend/src/routes/graph.ts...")
    backend_routes_file = REACT_DIR / "backend" / "src" / "routes" / "graph.ts"
    backend_routes_code = '''import { Router } from "express"
import { getGraph } from "../controllers/graph.js"
import { validate } from "../middleware/validate.js"
import { directQuerySchema, traversalHopSchema } from "../schemas/traversal.js"
import {
  getTemplates,
  postDirectQuery,
  postTraversalHop,
} from "../controllers/traversal.js"

export const graphRouter = Router()

graphRouter.get("/", getGraph)
graphRouter.post("/hop", validate(traversalHopSchema), postTraversalHop)
graphRouter.get("/templates", getTemplates)
graphRouter.post("/direct-query", validate(directQuerySchema), postDirectQuery)
'''
    backend_routes_file.write_text(backend_routes_code, encoding="utf-8")
    print(f"      -> {backend_routes_file} atualizado!")

    # 5. Update frontend/src/services/Explorer/types.ts
    print("\n[5/8] Atualizar frontend/src/services/Explorer/types.ts...")
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

export type TraversalStrategy = "canonical" | "fast_defense" | "threat_hunting" | "free"

export type TemplateDefinition = {
  framework: string
  name: string
  label: string
  icon: string
  color: string
  description: string
  goalQuestion: string
  choiceQuestion: string
  scoreQuestion: string
  criteriaScale: string[]
}

export type TraversalStep = {
  hop: number
  currentNode: string
  strategy?: TraversalStrategy
  jevSource: "api" | "mock"
  level1Router?: {
    currentFramework: string
    targetFramework: string
    routerDecision: string
    strategyApplied?: string
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
  strategy?: TraversalStrategy
}

export type DirectQueryBody = {
  currentNode: string
  frameworks: string[]
  goal: string
}

export type DirectQueryFrameworkResult = {
  framework: string
  templateUsed: string
  neighborsCount: number
  branches: Record<string, string>
  chosenBranch: string
  chosenTarget: {
    id: string
    name: string
    label: string
  }
  noulGoal: number
  heuristicScore: number
  latencyMs: number
  jevQuestions: {
    goalReached: string
    bestBranch: string
    heuristicScore: string
  }
}

export type DirectQueryResult = {
  currentNode: string
  goal: string
  results: DirectQueryFrameworkResult[]
  totalLatencyMs: number
}

export type Manuscript = {
  name: string
  content: string
}
'''
    frontend_types_file.write_text(frontend_types_code, encoding="utf-8")
    print(f"      -> {frontend_types_file} atualizado!")

    # 6. Update frontend/src/services/Explorer/explorer.ts
    print("\n[6/8] Atualizar frontend/src/services/Explorer/explorer.ts...")
    frontend_explorer_file = REACT_DIR / "frontend" / "src" / "services" / "Explorer" / "explorer.ts"
    frontend_explorer_code = '''import { api } from "@/services/api"
import { useMutation, useQuery } from "@tanstack/react-query"
import type {
  DirectQueryBody,
  DirectQueryResult,
  GraphSnapshot,
  Manuscript,
  TemplateDefinition,
  TraversalHopBody,
  TraversalHopResult,
} from "./types"

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

export const GOAL_THRESHOLD = 0.7

const explorerKeys = {
  all: ["explorer"] as const,
  graph: () => [...explorerKeys.all, "graph"] as const,
  templates: () => [...explorerKeys.all, "templates"] as const,
  manuscripts: () => [...explorerKeys.all, "manuscripts"] as const,
  manuscript: (name: string) => [...explorerKeys.all, "manuscripts", name] as const,
}

export const useFetchGraph = () =>
  useQuery({
    queryKey: explorerKeys.graph(),
    queryFn: async () => api.get("graph").json<GraphSnapshot>(),
    staleTime: Number.POSITIVE_INFINITY,
  })

export const useFetchTemplates = () =>
  useQuery({
    queryKey: explorerKeys.templates(),
    queryFn: async () => api.get("graph/templates").json<TemplateDefinition[]>(),
    staleTime: Number.POSITIVE_INFINITY,
  })

export const useExecuteHop = () =>
  useMutation({
    mutationFn: async (body: TraversalHopBody) =>
      api.post("graph/hop", { json: body }).json<TraversalHopResult>(),
  })

export const useExecuteDirectQuery = () =>
  useMutation({
    mutationFn: async (body: DirectQueryBody) =>
      api.post("graph/direct-query", { json: body }).json<DirectQueryResult>(),
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
    frontend_explorer_file.write_text(frontend_explorer_code, encoding="utf-8")
    print(f"      -> {frontend_explorer_file} atualizado!")

    # 7. Create templates-catalog.tsx and direct-query-playground.tsx
    print("\n[7/8] Criar componentes frontend: templates-catalog.tsx e direct-query-playground.tsx...")
    catalog_comp_file = REACT_DIR / "frontend" / "src" / "pages" / "Explorer" / "templates-catalog.tsx"
    catalog_comp_code = '''import { Badge } from "@/components/ui/badge"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { useFetchTemplates } from "@/services"
import { Bug, Compass, Cpu, Crosshair, Flame, ShieldCheck } from "lucide-react"

const ICON_MAP: Record<string, React.ReactNode> = {
  Crosshair: <Crosshair className="size-4" />,
  Bug: <Bug className="size-4" />,
  Flame: <Flame className="size-4" />,
  Cpu: <Cpu className="size-4" />,
  ShieldCheck: <ShieldCheck className="size-4" />,
  Compass: <Compass className="size-4" />,
}

export function TemplatesCatalog() {
  const { data: templates, isPending } = useFetchTemplates()

  if (isPending) {
    return (
      <div className="flex flex-col gap-3">
        <Skeleton className="h-28 w-full" />
        <Skeleton className="h-28 w-full" />
        <Skeleton className="h-28 w-full" />
      </div>
    )
  }

  return (
    <div className="flex max-h-[600px] flex-col gap-4 overflow-y-auto pr-1">
      <div className="rounded-md border border-cyan-500/30 bg-cyan-500/10 p-3 text-xs leading-relaxed text-cyan-200">
        <b>📚 Dicionário de Templates Jev (System 1)</b>
        <p className="mt-1 text-muted-foreground text-[11px]">
          Cada domínio ontológico (CWE, CAPEC, ATT&CK, ATLAS, D3FEND) possui perguntas
          tipadas (Noul, Choice, Score) calibradas para garantir micro-decisões semânticas precisas.
        </p>
      </div>

      {templates?.map((t) => (
        <Card key={t.framework} className="overflow-hidden border-l-4" style={{ borderLeftColor: t.color }}>
          <CardHeader className="p-3 pb-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span style={{ color: t.color }}>{ICON_MAP[t.icon] ?? <ShieldCheck className="size-4" />}</span>
                <CardTitle className="text-sm font-semibold">{t.name}</CardTitle>
              </div>
              <Badge variant="outline" className="text-xs" style={{ borderColor: t.color, color: t.color }}>
                {t.framework}
              </Badge>
            </div>
            <CardDescription className="text-xs">{t.description}</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-2 p-3 pt-0 text-xs">
            <div className="rounded bg-muted/60 p-2">
              <span className="font-semibold text-emerald-400">🎯 Noul (Meta / Solução):</span>
              <p className="mt-0.5 italic text-muted-foreground">{t.goalQuestion}</p>
            </div>
            <div className="rounded bg-muted/60 p-2">
              <span className="font-semibold text-amber-400">🔀 Choice (Seleção de Ramo):</span>
              <p className="mt-0.5 italic text-muted-foreground">{t.choiceQuestion}</p>
            </div>
            <div className="rounded bg-muted/60 p-2">
              <span className="font-semibold text-purple-400">📊 Score (Heurística):</span>
              <p className="mt-0.5 italic text-muted-foreground">{t.scoreQuestion}</p>
              <div className="mt-1 flex flex-wrap gap-1">
                {t.criteriaScale.map((scale, i) => (
                  <Badge key={i} variant="secondary" className="text-[10px]">
                    {scale}
                  </Badge>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  )
}
'''
    catalog_comp_file.write_text(catalog_comp_code, encoding="utf-8")
    print(f"      -> {catalog_comp_file} criado!")

    playground_comp_file = REACT_DIR / "frontend" / "src" / "pages" / "Explorer" / "direct-query-playground.tsx"
    playground_comp_code = '''import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Progress } from "@/components/ui/progress"
import { Textarea } from "@/components/ui/textarea"
import { useExecuteDirectQuery } from "@/services"
import type { DirectQueryResult } from "@/services"
import { Loader2, Sparkles } from "lucide-react"
import { useState } from "react"
import { toast } from "sonner"

const FRAMEWORK_OPTIONS = [
  { id: "CWE", label: "CWE (Vulnerabilidade)", color: "#8B5CF6" },
  { id: "CAPEC", label: "CAPEC (Ataque)", color: "#F97316" },
  { id: "ATTACK", label: "ATT&CK (Técnica)", color: "#EF4444" },
  { id: "D3FEND", label: "D3FEND (Defesa)", color: "#10B981" },
  { id: "ATLAS", label: "ATLAS (AI/ML)", color: "#E11D48" },
]

export function DirectQueryPlayground({
  currentNode,
  goal,
}: {
  currentNode: string
  goal: string
}) {
  const [targetNode, setTargetNode] = useState(currentNode)
  const [customGoal, setCustomGoal] = useState(goal)
  const [selectedFws, setSelectedFws] = useState<string[]>(["CWE", "D3FEND"])
  const [result, setResult] = useState<DirectQueryResult | null>(null)

  const directQuery = useExecuteDirectQuery()

  const toggleFw = (fw: string) => {
    setSelectedFws((prev) =>
      prev.includes(fw) ? (prev.length > 1 ? prev.filter((f) => f !== fw) : prev) : [...prev, fw],
    )
  }

  const handleExecute = async () => {
    if (!targetNode.trim()) {
      toast.error("Por favor indica um nó válido.")
      return
    }

    try {
      const res = await directQuery.mutateAsync({
        currentNode: targetNode.trim(),
        frameworks: selectedFws,
        goal: customGoal.trim(),
      })
      setResult(res)
      toast.success("Avaliação Jev concluída com sucesso!")
    } catch (e) {
      toast.error("Erro na consulta direta: " + String(e))
    }
  }

  return (
    <div className="flex max-h-[600px] flex-col gap-4 overflow-y-auto pr-1">
      <div className="rounded-md border border-purple-500/30 bg-purple-500/10 p-3 text-xs leading-relaxed text-purple-200">
        <b>🧪 Playground de Decisão Jev: Consulta Pontual & Fan-Out</b>
        <p className="mt-1 text-muted-foreground text-[11px]">
          Faz uma pergunta sobre qualquer nó a 1 framework individual ou a múltiplos em simultâneo
          (Fan-Out) para comparar as respostas probabilísticas do Jev.
        </p>
      </div>

      <div className="flex flex-col gap-2 text-xs">
        <label className="font-semibold text-muted-foreground">Nó Alvo para Avaliação:</label>
        <div className="flex gap-2">
          <Input
            value={targetNode}
            onChange={(e) => setTargetNode(e.target.value)}
            placeholder="Ex: CAPEC-1, CWE-89, T1574.010, D3-AVE"
            className="text-xs"
          />
          <Button
            size="sm"
            variant="outline"
            className="text-xs shrink-0"
            onClick={() => setTargetNode(currentNode)}
          >
            Usar Atual ({currentNode})
          </Button>
        </div>
      </div>

      <div className="flex flex-col gap-1.5 text-xs">
        <label className="font-semibold text-muted-foreground">Frameworks a Consultar (Fan-Out):</label>
        <div className="flex flex-wrap gap-1.5">
          {FRAMEWORK_OPTIONS.map((f) => {
            const isSelected = selectedFws.includes(f.id)
            return (
              <Button
                key={f.id}
                size="sm"
                variant={isSelected ? "default" : "outline"}
                className="h-7 text-xs px-2.5"
                style={isSelected ? { backgroundColor: f.color, color: "#fff", borderColor: f.color } : {}}
                onClick={() => toggleFw(f.id)}
              >
                {f.label}
              </Button>
            )
          })}
        </div>
      </div>

      <div className="flex flex-col gap-1.5 text-xs">
        <label className="font-semibold text-muted-foreground">Pergunta / Meta para o Jev:</label>
        <Textarea
          value={customGoal}
          onChange={(e) => setCustomGoal(e.target.value)}
          rows={2}
          className="text-xs"
        />
      </div>

      <Button
        onClick={handleExecute}
        disabled={directQuery.isPending}
        className="w-full bg-emerald-600 hover:bg-emerald-700 text-white text-xs h-8"
      >
        {directQuery.isPending ? (
          <>
            <Loader2 className="mr-2 size-3.5 animate-spin" /> Avaliando com Jev...
          </>
        ) : (
          <>
            <Sparkles className="mr-2 size-3.5" /> Executar Consulta no Jev System 1
          </>
        )}
      </Button>

      {result && (
        <div className="mt-2 flex flex-col gap-3 border-t pt-3">
          <div className="flex items-center justify-between text-xs">
            <span className="font-semibold text-emerald-400">
              ⚡ Resultados ({result.results.length} frameworks)
            </span>
            <span className="text-muted-foreground text-[11px]">
              {result.totalLatencyMs.toFixed(1)}ms total
            </span>
          </div>

          {result.results.map((r) => (
            <div key={r.framework} className="rounded-md border p-3 text-xs flex flex-col gap-2">
              <div className="flex items-center justify-between">
                <Badge variant="outline" className="font-semibold">
                  {r.framework} · {r.templateUsed}
                </Badge>
                <span className="text-muted-foreground text-[11px]">{r.latencyMs.toFixed(1)}ms</span>
              </div>

              <div className="grid grid-cols-3 gap-2 text-center my-1">
                <div className="rounded bg-muted p-1.5">
                  <p className="text-[10px] text-muted-foreground">Confiança Meta</p>
                  <p className="font-bold text-sm">{Math.round(r.noulGoal * 100)}%</p>
                </div>
                <div className="rounded bg-muted p-1.5">
                  <p className="text-[10px] text-muted-foreground">Ramo Escolhido</p>
                  <p className="font-bold text-xs truncate" title={r.chosenBranch}>
                    {r.chosenBranch}
                  </p>
                </div>
                <div className="rounded bg-muted p-1.5">
                  <p className="text-[10px] text-muted-foreground">Score Heurístico</p>
                  <p className="font-bold text-sm">{r.heuristicScore.toFixed(2)}</p>
                </div>
              </div>

              <Progress value={Math.min(100, r.noulGoal * 100)} />

              <div className="rounded bg-muted/40 p-2 text-[11px]">
                <span className="font-semibold">Nó Selecionado:</span>{" "}
                <Badge variant="secondary" className="text-[10px]">
                  {r.chosenTarget.id}
                </Badge>{" "}
                <span>({r.chosenTarget.label})</span> — <em>{r.chosenTarget.name}</em>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
'''
    playground_comp_file.write_text(playground_comp_code, encoding="utf-8")
    print(f"      -> {playground_comp_file} criado!")

    # 8. Update frontend/src/pages/Explorer/index.tsx
    print("\n[8/8] Atualizar frontend/src/pages/Explorer/index.tsx com seletor de estratégias, filtros de KG e abas integradas...")
    frontend_index_file = REACT_DIR / "frontend" / "src" / "pages" / "Explorer" / "index.tsx"
    frontend_index_code = '''import { GraphView } from "@/components/graph-view"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs"
import { Skeleton } from "@/components/ui/skeleton"
import { Textarea } from "@/components/ui/textarea"
import {
  buildVisEdges,
  buildVisNodes,
  extractLocalSubgraph,
} from "@/lib/graph-visuals"
import {
  DEFAULT_GOAL,
  GOAL_THRESHOLD,
  START_NODES,
  useExecuteHop,
  useFetchGraph,
  type TraversalStep,
  type TraversalStrategy,
} from "@/services"
import { DirectQueryPlayground } from "./direct-query-playground"
import { HopInspector } from "./hop-inspector"
import { ManuscriptsPanel } from "./manuscripts-panel"
import { TemplatesCatalog } from "./templates-catalog"
import { TraversalTimeline } from "./traversal-timeline"
import { toast } from "sonner"
import {
  BookOpen,
  Compass,
  Filter,
  PartyPopper,
  Play,
  RotateCcw,
  Sparkles,
  StepForward,
} from "lucide-react"
import { useMemo, useState } from "react"

const MAX_AUTO_HOPS = 6

const STRATEGIES: { id: TraversalStrategy; label: string; desc: string }[] = [
  {
    id: "canonical",
    label: "🛣️ Canónico: CWE ➔ CAPEC ➔ ATT&CK ➔ D3FEND",
    desc: "Segue a sequência completa de inteligência de ameaças.",
  },
  {
    id: "fast_defense",
    label: "⚡ Defesa Rápida: Atalho Direto para D3FEND",
    desc: "Prioriza contramedidas e salta diretamente para D3FEND assim que houver ponte.",
  },
  {
    id: "threat_hunting",
    label: "🎯 Threat Hunting: ATT&CK ➔ CAPEC ➔ CWE",
    desc: "Investigação forense a partir de técnicas adversárias ativas.",
  },
  {
    id: "free",
    label: "🎲 Exploração Livre (Sem viés de pipeline)",
    desc: "O Jev escolhe livremente os ramos com base no alinhamento semântico.",
  },
]

const KG_FRAMEWORKS = [
  { id: "ALL", label: "🌐 Todos (Federado)" },
  { id: "CWE", label: "🟣 CWE" },
  { id: "CAPEC", label: "🟠 CAPEC" },
  { id: "ATTACK", label: "🔴 ATT&CK" },
  { id: "D3FEND", label: "🟢 D3FEND" },
  { id: "ATLAS", label: "🤖 ATLAS" },
]

export default function ExplorerPage() {
  const { data: graph, isPending, error } = useFetchGraph()
  const hop = useExecuteHop()

  const [strategy, setStrategy] = useState<TraversalStrategy>("canonical")
  const [activeKgFilter, setActiveKgFilter] = useState<string>("ALL")
  const [startNodeId, setStartNodeId] = useState<string>(START_NODES[0].id)
  const [goal, setGoal] = useState(DEFAULT_GOAL)
  const [currentNode, setCurrentNode] = useState<string>(START_NODES[0].id)
  const [traversedPath, setTraversedPath] = useState<string[]>([START_NODES[0].id])
  const [history, setHistory] = useState<TraversalStep[]>([])
  const [goalAchieved, setGoalAchieved] = useState(false)
  const [viewIdx, setViewIdx] = useState(0)
  const [deadEnd, setDeadEnd] = useState<string | null>(null)

  // Subgrafo local com filtragem opcional por KG
  const localGraph = useMemo(() => {
    if (!graph) return { nodes: [], edges: [], hiddenNeighbors: 0 }
    const sub = extractLocalSubgraph(graph, traversedPath, currentNode)
    if (activeKgFilter === "ALL") return sub

    const keepNodeIds = new Set(
      sub.nodes
        .filter((n) => n.group === activeKgFilter || traversedPath.includes(n.id) || n.id === currentNode)
        .map((n) => n.id),
    )

    return {
      nodes: sub.nodes.filter((n) => keepNodeIds.has(n.id)),
      edges: sub.edges.filter((e) => keepNodeIds.has(e.from) && keepNodeIds.has(e.to)),
      hiddenNeighbors: sub.hiddenNeighbors,
    }
  }, [graph, traversedPath, currentNode, activeKgFilter])

  const visNodes = useMemo(
    () => buildVisNodes(localGraph.nodes, traversedPath, currentNode),
    [localGraph, traversedPath, currentNode],
  )
  const visEdges = useMemo(
    () => buildVisEdges(localGraph.edges, traversedPath),
    [localGraph, traversedPath],
  )

  const handleReset = () => {
    setCurrentNode(startNodeId)
    setTraversedPath([startNodeId])
    setHistory([])
    setGoalAchieved(false)
    setViewIdx(0)
    setDeadEnd(null)
  }

  const handleStepForward = () => {
    void runHops(1)
  }

  const handleRunAll = () => {
    void runHops(MAX_AUTO_HOPS)
  }

  const runHops = async (maxHops: number) => {
    let localCurrent = currentNode
    let localPath = traversedPath
    let newSteps = 0

    for (let i = 0; i < maxHops; i++) {
      const result = await hop.mutateAsync({
        currentNode: localCurrent,
        traversedPath: localPath,
        goal,
        strategy,
      })

      if (result.status === "dead-end") {
        setDeadEnd(result.message)
        toast.warning(result.message)
        break
      }

      setDeadEnd(null)
      setHistory((prev) => [...prev, result.step])
      newSteps += 1
      localCurrent = result.currentNode
      localPath = result.traversedPath

      if (result.goalAchieved) {
        setGoalAchieved(true)
        toast.success("🎉 Objetivo alcançado com alta confiança!")
        break
      }
    }

    if (newSteps > 0) {
      setCurrentNode(localCurrent)
      setTraversedPath(localPath)
      setViewIdx(history.length + newSteps - 1)
    }
  }

  const selectedStep = history[viewIdx]

  return (
    <div className="flex flex-col gap-6 p-8">
      <div>
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold">
              🛡️ Threat Modeling Explorer: Meta-Router & KGs
            </h1>
            <p className="text-sm text-muted-foreground">
              Orquestração probabilística System 1 (TypeSafe AI Jev) sobre ontologias CWE, CAPEC, ATT&CK, ATLAS e D3FEND.
            </p>
          </div>
          <Badge variant="outline" className="border-emerald-500/40 text-emerald-400">
            sub-50ms System 1
          </Badge>
        </div>
      </div>

      {/* Controlos de Estratégia e Ações Principais */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="flex flex-col gap-1">
              <span className="text-xs font-semibold text-muted-foreground">
                Estratégia do Meta-Router:
              </span>
              <Select
                value={strategy}
                onValueChange={(val: string) => setStrategy(val as TraversalStrategy)}
              >
                <SelectTrigger className="w-[380px] text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {STRATEGIES.map((s) => (
                    <SelectItem key={s.id} value={s.id} className="text-xs">
                      {s.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="flex items-center gap-2 self-end">
              <Button
                size="sm"
                onClick={handleStepForward}
                disabled={goalAchieved || hop.isPending}
                className="text-xs"
              >
                <StepForward className="mr-1 size-3.5" />
                Salto Seguinte
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={handleRunAll}
                disabled={goalAchieved || hop.isPending}
                className="text-xs"
              >
                <Play className="mr-1 size-3.5" />
                Auto-Executar
              </Button>
              <Button size="sm" variant="ghost" onClick={handleReset} className="text-xs">
                <RotateCcw className="mr-1 size-3.5" />
                Reiniciar
              </Button>
            </div>
          </div>

          <div className="mt-2 flex flex-wrap items-center gap-1">
            <span className="text-xs text-muted-foreground mr-1">Caminho ({traversedPath.length}):</span>
            {traversedPath.map((nodeId, idx) => (
              <span key={nodeId} className="flex items-center gap-1">
                {idx > 0 && <span className="text-muted-foreground text-xs">➔</span>}
                <Badge
                  variant={idx === traversedPath.length - 1 ? "default" : "outline"}
                  className="text-xs"
                >
                  {nodeId}
                </Badge>
              </span>
            ))}
          </div>
        </CardHeader>
      </Card>

      {goalAchieved && (
        <Alert className="border-emerald-500/40 bg-emerald-500/10">
          <PartyPopper className="size-4 text-emerald-400" />
          <AlertTitle className="text-emerald-400 font-semibold">🎉 Objetivo alcançado!</AlertTitle>
          <AlertDescription className="text-xs">
            Paragem em <code>{currentNode}</code> com confiança acima de{" "}
            {GOAL_THRESHOLD * 100}%.
          </AlertDescription>
        </Alert>
      )}

      {deadEnd && (
        <Alert variant="destructive">
          <AlertTitle>Fim da travessia</AlertTitle>
          <AlertDescription className="text-xs">{deadEnd}</AlertDescription>
        </Alert>
      )}

      {/* Grid Principal: Grafo com Filtros de KG à Esquerda + Abas Integradas à Direita */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-5">
        <Card className="lg:col-span-3 flex flex-col">
          <CardHeader className="pb-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <CardTitle className="text-base">🌐 Visualizador de Knowledge Graphs</CardTitle>
              <span className="text-xs text-muted-foreground">
                {graph ? `${graph.nodes.length} nós · ${graph.edges.length} relações` : "A carregar..."}
              </span>
            </div>

            {/* BARRA DE FILTROS DE KG */}
            <div className="mt-2 flex flex-wrap items-center gap-1.5 rounded-md border bg-muted/40 p-1.5">
              <Filter className="ml-1 size-3.5 text-muted-foreground" />
              <span className="text-[11px] font-semibold text-muted-foreground mr-1">
                Isolar KG:
              </span>
              {KG_FRAMEWORKS.map((fw) => (
                <Button
                  key={fw.id}
                  size="sm"
                  variant={activeKgFilter === fw.id ? "default" : "ghost"}
                  className="h-6 text-[11px] px-2"
                  onClick={() => setActiveKgFilter(fw.id)}
                >
                  {fw.label}
                </Button>
              ))}
            </div>
          </CardHeader>

          <CardContent className="flex-1">
            {isPending ? (
              <Skeleton className="h-[560px] w-full" />
            ) : error ? (
              <Alert variant="destructive">
                <AlertTitle>Erro ao carregar o grafo</AlertTitle>
                <AlertDescription>
                  Verifica se o Neo4j está a correr ({String(error.message)}).
                </AlertDescription>
              </Alert>
            ) : (
              <GraphView nodes={visNodes} edges={visEdges} />
            )}
          </CardContent>
        </Card>

        {/* PAINEL DIREITO: ABAS INTEGRADAS (INSPETOR, TEMPLATES, PLAYGROUND) */}
        <Card className="lg:col-span-2">
          <CardHeader className="pb-3">
            <Tabs defaultValue="inspector" className="w-full">
              <TabsList className="grid w-full grid-cols-3 text-xs">
                <TabsTrigger value="inspector" className="text-xs">
                  <Compass className="mr-1 size-3.5" /> Inspetor
                </TabsTrigger>
                <TabsTrigger value="templates" className="text-xs">
                  <BookOpen className="mr-1 size-3.5" /> Templates
                </TabsTrigger>
                <TabsTrigger value="playground" className="text-xs">
                  <Sparkles className="mr-1 size-3.5" /> Playground
                </TabsTrigger>
              </TabsList>

              <TabsContent value="inspector" className="mt-3">
                {history.length > 0 && (
                  <div className="mb-3">
                    <Select
                      value={String(viewIdx)}
                      onValueChange={(value) => setViewIdx(Number(value))}
                    >
                      <SelectTrigger className="text-xs h-8">
                        <SelectValue placeholder="Hop a inspecionar" />
                      </SelectTrigger>
                      <SelectContent>
                        {history.map((step, idx) => (
                          <SelectItem key={step.hop} value={String(idx)} className="text-xs">
                            Hop #{step.hop} (de {step.currentNode})
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                )}

                {selectedStep ? (
                  <HopInspector step={selectedStep} />
                ) : (
                  <p className="text-xs text-muted-foreground">
                    Clica em <strong>Salto Seguinte</strong> ou <strong>Auto-Executar</strong> para inspecionar
                    as decisões do Meta-Router e templates de domínio.
                  </p>
                )}
              </TabsContent>

              <TabsContent value="templates" className="mt-3">
                <TemplatesCatalog />
              </TabsContent>

              <TabsContent value="playground" className="mt-3">
                <DirectQueryPlayground currentNode={currentNode} goal={goal} />
              </TabsContent>
            </Tabs>
          </CardHeader>
        </Card>
      </div>

      {/* Configuração de Ponto de Partida e Meta */}
      <Card>
        <CardHeader>
          <div className="flex flex-col gap-4">
            <div className="flex flex-col gap-1">
              <p className="text-sm font-medium">Nó de partida (ameaça):</p>
              <Select value={startNodeId} onValueChange={setStartNodeId}>
                <SelectTrigger className="w-96 text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {START_NODES.map((node) => (
                    <SelectItem key={node.id} value={node.id} className="text-xs">
                      {node.id} — {node.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="flex flex-col gap-1">
              <p className="text-sm font-medium">Objetivo da pesquisa:</p>
              <Textarea
                value={goal}
                onChange={(event) => setGoal(event.target.value)}
                rows={2}
                className="text-xs"
              />
            </div>
          </div>
        </CardHeader>
      </Card>

      {history.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>📋 Cronologia da Travessia</CardTitle>
            <CardDescription>
              Clica numa linha para inspecionar o salto correspondente.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <TraversalTimeline
              steps={history}
              selectedIdx={viewIdx}
              onSelect={setViewIdx}
            />
          </CardContent>
        </Card>
      )}

      <ManuscriptsPanel />
    </div>
  )
}
'''
    frontend_index_file.write_text(frontend_index_code, encoding="utf-8")
    print(f"      -> {frontend_index_file} atualizado!")

    print("\n" + "=" * 65)
    print("✅ TODAS AS EXTENSÕES SINCRONIZADAS COM SUCESSO!")
    print("=" * 65)


if __name__ == "__main__":
    sync()
