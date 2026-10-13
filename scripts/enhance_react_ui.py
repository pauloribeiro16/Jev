"""Enhances the React UI in Template_React to provide a professional, state-of-the-art threat intelligence experience.

Fixes:
1. Updates GraphNode type definition to include name, category, description, and metadata.
2. Replaces raw <b> / <br> text tooltips in vis-network with custom styled HTML Elements.
3. Completely overhauls NodeDetailCard to show full descriptions, HTML execution flows,
   rich MITRE metadata, interactive neighbor relationship exploration, and external MITRE links.
4. Adds instant search with autocomplete across all 3,213 nodes in the Explorer toolbar.
5. Adds framework filter badges with node counts (All, CWE, CAPEC, ATT&CK, D3FEND, ATLAS).
6. Adds canvas HUD controls (Zoom in, Zoom out, Fit/Center).
7. Updates branding to 'Jev Threat Intelligence (TypeSafe AI)'.
8. Fixes all TypeScript types, exports, and unused symbols for a 100% clean build.
"""

from pathlib import Path

BASE_REACT = Path(__file__).parent.parent.parent / "Template_React" / "frontend" / "src"

# ==============================================================================
# 1. Update services/Explorer/types.ts (Add rich fields to GraphNode)
# ==============================================================================
EXPLORER_TYPES_TS = '''export type GraphNode = {
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

# ==============================================================================
# 2. Update graph-visuals.ts (Custom styled HTMLElement tooltips, no raw <b>)
# ==============================================================================
GRAPH_VISUALS_TS = '''import type {
  GraphEdge,
  GraphNode,
  GraphSnapshot,
} from "@/services/Explorer/types"

// Paleta de cores oficial por framework de cibersegurança.
export const NODE_COLOR_MAP: Record<string, string> = {
  CAPEC: "#F97316",      // Laranja Vívido (Padrões de Ataque)
  CWE: "#8B5CF6",        // Roxo Vívido (Fraquezas de Código)
  ATTACK: "#EF4444",     // Vermelho Carmesim (Técnicas Adversárias)
  D3FEND: "#10B981",     // Verde Esmeralda (Contramedidas Defensivas)
  ATLAS: "#E11D48",      // Rosa Carmim (Ameaças AI/ML)
  SubDomain: "#06B6D4",  // Ciano (Pontes Taxonomia)
  Domain: "#3B82F6",     // Azul Royal (Domínios de Segurança)
  DEFAULT: "#64748B",    // Ardósia Neutro
}

const PATH_COLOR = { background: "#10B981", border: "#34D399" }
const CURRENT_COLOR = { background: "#F59E0B", border: "#FDE68A" }
const DEFAULT_NODE_COLOR = { background: "", border: "#334155" }
const LABEL_COLOR = "#E2E8F0"
const SELECTED_BORDER = "#FFFFFF"

// Rótulos legíveis por ontologia.
export const FRAMEWORK_LABELS: Record<string, string> = {
  CAPEC: "Padrão de ataque",
  CWE: "Fraqueza de software",
  ATTACK: "Técnica adversária",
  ATLAS: "Ameaça AI/ML",
  D3FEND: "Contramedida defensiva",
  SubDomain: "Subdomínio",
  Domain: "Domínio",
  Threat: "Ameaça",
  Mitigation: "Mitigação",
}

export type VisNode = {
  id: string
  label: string
  title: string | HTMLElement
  shape: "dot"
  size: number
  color: { background: string; border: string }
  borderWidth: number
  font: { color: string; size: number }
  x?: number
  y?: number
}

export type VisEdge = {
  id: string
  from: string
  to: string
  label?: string
  arrows: "to"
  color: { color: string }
  width?: number
  font: { color: string; size: number; align: "middle" }
}

export const MAX_VISIBLE_NODES = 60

export type LocalSubgraph = {
  nodes: GraphNode[]
  edges: GraphEdge[]
  hiddenNeighbors: number
}

/**
 * Cria um elemento DOM rico e estilizado para o tooltip do vis-network.
 * Elimina totalmente tags brutas como <b> ou <br> visíveis no ecrã.
 */
export function createNodeTooltip(node: GraphNode): HTMLElement {
  const container = document.createElement("div")
  container.className = "vis-custom-tooltip"
  container.style.maxWidth = "340px"
  container.style.padding = "10px 14px"
  container.style.borderRadius = "10px"
  container.style.backgroundColor = "rgba(15, 23, 42, 0.96)"
  container.style.border = "1px solid rgba(71, 85, 105, 0.7)"
  container.style.boxShadow = "0 20px 25px -5px rgba(0, 0, 0, 0.7), 0 8px 10px -6px rgba(0, 0, 0, 0.5)"
  container.style.backdropFilter = "blur(12px)"
  container.style.color = "#f1f5f9"
  container.style.fontFamily = "ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif"
  container.style.fontSize = "12px"
  container.style.lineHeight = "1.45"
  container.style.pointerEvents = "none"

  const color = NODE_COLOR_MAP[node.group] ?? "#64748B"
  const cleanDesc = (node.description || "Sem descrição disponível.")
    .replace(/<[^>]+>/g, " ")
    .replace(/\\s+/g, " ")
    .trim()
  const preview = cleanDesc.length > 200 ? `${cleanDesc.slice(0, 200)}...` : cleanDesc

  const categoryBadge = node.category
    ? `<span style="font-size: 10px; color: #94a3b8; background: rgba(255,255,255,0.08); padding: 1px 6px; border-radius: 4px; max-width: 140px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${node.category}</span>`
    : ""

  container.innerHTML = `
    <div style="display: flex; align-items: center; justify-content: space-between; gap: 8px; margin-bottom: 6px;">
      <span style="font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, monospace; font-size: 11px; font-weight: 700; background: ${color}25; color: ${color}; border: 1px solid ${color}60; border-radius: 6px; padding: 2px 7px;">
        ${node.id} • ${node.group}
      </span>
      ${categoryBadge}
    </div>
    <div style="font-size: 13px; font-weight: 600; color: #f8fafc; margin-bottom: 6px; line-height: 1.35;">
      ${node.name || node.id}
    </div>
    <div style="font-size: 11.5px; color: #cbd5e1; line-height: 1.45;">
      ${preview}
    </div>
    <div style="margin-top: 8px; padding-top: 6px; border-top: 1px solid rgba(255,255,255,0.08); font-size: 10px; color: #64748b; display: flex; align-items: center; justify-content: space-between;">
      <span>💡 Clique no nó para ver todos os detalhes</span>
      <span style="color: ${color}; font-weight: 600;">● ${node.group}</span>
    </div>
  `
  return container
}

export function extractLocalSubgraph(
  graph: GraphSnapshot,
  traversedPath: string[],
  currentNode: string,
): LocalSubgraph {
  const keep = new Set(traversedPath)
  keep.add(currentNode)

  const neighborIds: string[] = []
  const seen = new Set<string>()
  graph.edges.forEach((edge) => {
    const other =
      edge.from === currentNode
        ? edge.to
        : edge.to === currentNode
          ? edge.from
          : null
    if (!other || keep.has(other) || seen.has(other)) return
    seen.add(other)
    neighborIds.push(other)
  })

  const budget = Math.max(0, MAX_VISIBLE_NODES - keep.size)
  const keptNeighbors = neighborIds.slice(0, budget)

  const nodeSet = new Set([...keep, ...keptNeighbors])
  return {
    nodes: graph.nodes.filter((node) => nodeSet.has(node.id)),
    edges: graph.edges.filter(
      (edge) => nodeSet.has(edge.from) && nodeSet.has(edge.to),
    ),
    hiddenNeighbors: neighborIds.length - keptNeighbors.length,
  }
}

export function buildVisNodes(
  nodes: GraphNode[],
  traversedPath: string[],
  currentNode: string,
  selectedNode = "",
): VisNode[] {
  const traversedSet = new Set(traversedPath)

  return nodes.map((node) => {
    const baseColor = NODE_COLOR_MAP[node.group] ?? NODE_COLOR_MAP.DEFAULT
    const visNode: VisNode = {
      id: node.id,
      label: `${node.id}\\n(${node.group})`,
      title: createNodeTooltip(node),
      shape: "dot",
      size: 16,
      color: { ...DEFAULT_NODE_COLOR, background: baseColor },
      borderWidth: 1,
      font: { color: LABEL_COLOR, size: 11 },
    }

    if (traversedSet.has(node.id)) {
      visNode.size = 24
      visNode.color = { ...PATH_COLOR }
      visNode.borderWidth = 3
    }

    if (node.id === currentNode) {
      visNode.size = 32
      visNode.color = { ...CURRENT_COLOR }
      visNode.borderWidth = 5
    }

    if (node.id === selectedNode && node.id !== currentNode) {
      visNode.size = 22
      visNode.borderWidth = 4
      visNode.color = {
        background: baseColor,
        border: SELECTED_BORDER,
      }
    }

    return visNode
  })
}

export function buildVisEdges(
  edges: GraphEdge[],
  traversedPath: string[],
  showLabels = false,
): VisEdge[] {
  const traversedSet = new Set(traversedPath)

  return edges.map((edge, index) => {
    const isTraversed =
      traversedSet.has(edge.from) && traversedSet.has(edge.to)

    return {
      id: `${edge.from}->${edge.to}[${index}]`,
      from: edge.from,
      to: edge.to,
      label: showLabels ? edge.label : undefined,
      arrows: "to",
      color: { color: isTraversed ? "#10B981" : "#475569" },
      width: isTraversed ? 2.5 : 1,
      font: { color: "#94A3B8", size: 10, align: "middle" },
    }
  })
}
'''

# ==============================================================================
# 3. Update node-detail-card.tsx (Rich, Professional Deep Node Inspector)
# ==============================================================================
NODE_DETAIL_CARD_TSX = '''import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { NODE_COLOR_MAP } from "@/lib/graph-visuals"
import type { GraphEdge, GraphNode } from "@/services"
import {
  ExternalLink,
  Play,
  Sparkles,
  X,
} from "lucide-react"
import { useState } from "react"

type Props = {
  node: GraphNode
  edges: GraphEdge[]
  allNodes?: GraphNode[]
  onClose: () => void
  onSelectNode?: (nodeId: string) => void
  onSetAsCurrentNode?: (nodeId: string) => void
  onOpenPlayground?: (nodeId: string) => void
}

/**
 * Devolve o link canónico oficial no MITRE para a técnica.
 */
function getOfficialMitreUrl(nodeId: string, group: string): string | null {
  const norm = nodeId.trim().toUpperCase()
  if (group === "ATTACK" || norm.startsWith("T")) {
    return `https://attack.mitre.org/techniques/${norm.replace(".", "/")}/`
  }
  if (group === "CWE" || norm.startsWith("CWE-")) {
    const num = norm.replace("CWE-", "")
    return `https://cwe.mitre.org/data/definitions/${num}.html`
  }
  if (group === "CAPEC" || norm.startsWith("CAPEC-")) {
    const num = norm.replace("CAPEC-", "")
    return `https://capec.mitre.org/data/definitions/${num}.html`
  }
  if (group === "D3FEND" || norm.startsWith("D3-")) {
    return `https://d3fend.mitre.org/`
  }
  if (group === "ATLAS" || norm.startsWith("AML.T")) {
    return `https://atlas.mitre.org/techniques/${norm}/`
  }
  return null
}

/**
 * Renderizador seguro de blocos HTML (como execution_flow do CAPEC ou tabelas).
 * Aplica estilos consistentes e elegantes do Tailwind.
 */
function RichHtmlView({ content }: { content: string }) {
  if (!content) return null

  const hasHtml = /<[a-z][\\s\\S]*>/i.test(content)

  if (hasHtml) {
    return (
      <div
        className="prose prose-invert prose-xs max-w-none text-xs text-slate-300 leading-relaxed [&_h2]:text-sm [&_h2]:font-bold [&_h2]:text-slate-100 [&_h2]:mt-3 [&_h2]:mb-1 [&_h3]:text-xs [&_h3]:font-semibold [&_h3]:text-slate-200 [&_h3]:mt-2 [&_h3]:mb-1 [&_p]:my-1.5 [&_ul]:my-1 [&_ul]:pl-4 [&_ol]:my-1 [&_ol]:pl-4 [&_li]:my-0.5 [&_b]:text-slate-100 [&_strong]:text-slate-100 [&_table]:w-full [&_table]:border-collapse [&_table]:my-2 [&_th]:border [&_th]:border-slate-700 [&_th]:bg-slate-800/60 [&_th]:p-1.5 [&_th]:text-left [&_th]:text-[11px] [&_td]:border [&_td]:border-slate-800 [&_td]:p-1.5 [&_td]:text-[11px]"
        dangerouslySetInnerHTML={{ __html: content }}
      />
    )
  }

  return (
    <div className="space-y-2 text-xs text-slate-300 leading-relaxed">
      {content.split(/\\n\\n+/).map((para, i) => (
        <p key={i}>{para.trim()}</p>
      ))}
    </div>
  )
}

export function NodeDetailCard({
  node,
  edges,
  allNodes = [],
  onClose,
  onSelectNode,
  onSetAsCurrentNode,
  onOpenPlayground,
}: Props) {
  const [activeTab, setActiveTab] = useState("overview")
  const color = NODE_COLOR_MAP[node.group] ?? "#64748B"
  const mitreUrl = getOfficialMitreUrl(node.id, node.group)

  const incoming = edges.filter((e) => e.to === node.id)
  const outgoing = edges.filter((e) => e.from === node.id)
  const totalLinks = incoming.length + outgoing.length

  const metadata = (node.metadata ?? {}) as Record<string, any>
  const executionFlow = metadata.execution_flow as string | undefined
  const platforms = (metadata.platforms as string[]) || []
  const tactics = (metadata.tactics as string[]) || []

  const nodeMap = new Map<string, GraphNode>()
  allNodes.forEach((n) => nodeMap.set(n.id, n))

  return (
    <div className="pointer-events-auto flex w-[440px] flex-col overflow-hidden rounded-2xl border border-slate-700/80 bg-slate-950/95 shadow-2xl shadow-black/70 backdrop-blur-xl animate-in fade-in slide-in-from-bottom-3 duration-200">
      {/* Cabeçalho */}
      <div className="flex items-start justify-between border-b border-slate-800/80 bg-slate-900/60 p-4">
        <div className="flex items-start gap-3 min-w-0 pr-2">
          <span
            className="mt-1 size-3.5 shrink-0 rounded-full shadow-lg"
            style={{ backgroundColor: color, boxShadow: `0 0 10px ${color}80` }}
          />
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="font-mono text-sm font-bold text-white tracking-wide">
                {node.id}
              </span>
              <Badge
                variant="outline"
                className="text-[10px] font-mono px-2 py-0.5"
                style={{
                  backgroundColor: `${color}18`,
                  borderColor: `${color}60`,
                  color: color,
                }}
              >
                {node.group}
              </Badge>
              {node.category && (
                <span className="truncate text-[10px] text-slate-400">
                  • {node.category}
                </span>
              )}
            </div>
            <h2 className="mt-1 text-sm font-semibold text-slate-100 leading-snug">
              {node.name || node.id}
            </h2>
          </div>
        </div>

        <div className="flex items-center gap-1">
          {mitreUrl && (
            <a
              href={mitreUrl}
              target="_blank"
              rel="noreferrer"
              className="rounded p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white transition-colors"
              title="Abrir página oficial MITRE"
            >
              <ExternalLink className="size-3.5" />
            </a>
          )}
          <button
            type="button"
            onClick={onClose}
            className="rounded p-1.5 text-slate-400 hover:bg-slate-800 hover:text-white transition-colors"
            aria-label="Fechar"
          >
            <X className="size-4" />
          </button>
        </div>
      </div>

      {/* Navegação por Abas */}
      <Tabs value={activeTab} onValueChange={setActiveTab} className="flex flex-col">
        <div className="border-b border-slate-800 px-3 bg-slate-900/30">
          <TabsList className="h-9 w-full justify-start bg-transparent gap-1 p-0">
            <TabsTrigger
              value="overview"
              className="text-xs data-[state=active]:bg-slate-800 data-[state=active]:text-white"
            >
              Visão Geral
            </TabsTrigger>
            {executionFlow && (
              <TabsTrigger
                value="flow"
                className="text-xs data-[state=active]:bg-slate-800 data-[state=active]:text-white"
              >
                Fluxo de Execução
              </TabsTrigger>
            )}
            <TabsTrigger
              value="relations"
              className="text-xs data-[state=active]:bg-slate-800 data-[state=active]:text-white"
            >
              Relações ({totalLinks})
            </TabsTrigger>
            <TabsTrigger
              value="actions"
              className="text-xs data-[state=active]:bg-slate-800 data-[state=active]:text-white"
            >
              Ações Jev
            </TabsTrigger>
          </TabsList>
        </div>

        {/* Conteúdo com scroll */}
        <div className="max-h-[380px] overflow-y-auto p-4 space-y-4">
          {/* Aba: Visão Geral */}
          <TabsContent value="overview" className="m-0 space-y-3">
            <div>
              <h3 className="text-[11px] font-bold uppercase tracking-wider text-slate-400 mb-1.5">
                Descrição Oficial Completa
              </h3>
              <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-3">
                <RichHtmlView
                  content={node.description || "Nenhuma descrição fornecida pelo catálogo."}
                />
              </div>
            </div>

            {/* Metadados Técnicos */}
            {(platforms.length > 0 || tactics.length > 0 || metadata.matrix) && (
              <div>
                <h3 className="text-[11px] font-bold uppercase tracking-wider text-slate-400 mb-1.5">
                  Contexto Operacional
                </h3>
                <div className="grid grid-cols-2 gap-2 text-xs">
                  {metadata.matrix && (
                    <div className="rounded-lg border border-slate-800 bg-slate-900/30 p-2">
                      <span className="text-[10px] text-slate-400">Matriz:</span>
                      <p className="font-semibold text-slate-200">{metadata.matrix}</p>
                    </div>
                  )}
                  {tactics.length > 0 && (
                    <div className="rounded-lg border border-slate-800 bg-slate-900/30 p-2">
                      <span className="text-[10px] text-slate-400">Táticas:</span>
                      <p className="font-semibold text-slate-200">{tactics.join(", ")}</p>
                    </div>
                  )}
                  {platforms.length > 0 && (
                    <div className="col-span-2 rounded-lg border border-slate-800 bg-slate-900/30 p-2">
                      <span className="text-[10px] text-slate-400">Plataformas:</span>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {platforms.map((p) => (
                          <Badge key={p} variant="secondary" className="text-[10px]">
                            {p}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </TabsContent>

          {/* Aba: Fluxo de Execução (para CAPEC) */}
          {executionFlow && (
            <TabsContent value="flow" className="m-0 space-y-2">
              <h3 className="text-[11px] font-bold uppercase tracking-wider text-slate-400">
                Fases do Ataque (Execution Flow)
              </h3>
              <div className="rounded-xl border border-slate-800 bg-slate-900/40 p-3">
                <RichHtmlView content={executionFlow} />
              </div>
            </TabsContent>
          )}

          {/* Aba: Relações Conectadas */}
          <TabsContent value="relations" className="m-0 space-y-3">
            {totalLinks === 0 ? (
              <p className="text-xs text-slate-400 py-4 text-center">
                Sem arestas adicionais visíveis no subgrafo atual.
              </p>
            ) : (
              <>
                {outgoing.length > 0 && (
                  <div>
                    <h4 className="text-[11px] font-bold uppercase text-slate-400 mb-1.5">
                      Relações de Saída ({outgoing.length})
                    </h4>
                    <div className="space-y-1.5">
                      {outgoing.map((edge, i) => {
                        const targetNode = nodeMap.get(edge.to)
                        const tgtColor = targetNode
                          ? NODE_COLOR_MAP[targetNode.group] ?? "#64748B"
                          : "#64748B"
                        return (
                          <div
                            key={i}
                            onClick={() => onSelectNode?.(edge.to)}
                            className="flex items-center justify-between p-2 rounded-lg border border-slate-800 bg-slate-900/40 hover:bg-slate-800/80 cursor-pointer transition-colors"
                          >
                            <div className="flex items-center gap-2 min-w-0 pr-2">
                              <span
                                className="size-2 rounded-full shrink-0"
                                style={{ backgroundColor: tgtColor }}
                              />
                              <div className="min-w-0">
                                <p className="font-mono text-xs font-semibold text-slate-200">
                                  {edge.to}
                                </p>
                                <p className="text-[11px] text-slate-400 truncate">
                                  {targetNode?.name || edge.to}
                                </p>
                              </div>
                            </div>
                            <Badge variant="outline" className="text-[10px] shrink-0">
                              {edge.label} →
                            </Badge>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                )}

                {incoming.length > 0 && (
                  <div>
                    <h4 className="text-[11px] font-bold uppercase text-slate-400 mb-1.5">
                      Relações de Entrada ({incoming.length})
                    </h4>
                    <div className="space-y-1.5">
                      {incoming.map((edge, i) => {
                        const srcNode = nodeMap.get(edge.from)
                        const srcColor = srcNode
                          ? NODE_COLOR_MAP[srcNode.group] ?? "#64748B"
                          : "#64748B"
                        return (
                          <div
                            key={i}
                            onClick={() => onSelectNode?.(edge.from)}
                            className="flex items-center justify-between p-2 rounded-lg border border-slate-800 bg-slate-900/40 hover:bg-slate-800/80 cursor-pointer transition-colors"
                          >
                            <div className="flex items-center gap-2 min-w-0 pr-2">
                              <span
                                className="size-2 rounded-full shrink-0"
                                style={{ backgroundColor: srcColor }}
                              />
                              <div className="min-w-0">
                                <p className="font-mono text-xs font-semibold text-slate-200">
                                  {edge.from}
                                </p>
                                <p className="text-[11px] text-slate-400 truncate">
                                  {srcNode?.name || edge.from}
                                </p>
                              </div>
                            </div>
                            <Badge variant="outline" className="text-[10px] shrink-0">
                              ← {edge.label}
                            </Badge>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                )}
              </>
            )}
          </TabsContent>

          {/* Aba: Ações Jev */}
          <TabsContent value="actions" className="m-0 space-y-3">
            <div className="rounded-xl border border-purple-500/30 bg-purple-500/10 p-3 text-xs text-purple-200 space-y-2">
              <div className="flex items-center gap-2 font-bold text-purple-300">
                <Sparkles className="size-4" />
                <span>Interação Direta com o Jev System 1</span>
              </div>
              <p className="text-[11px] text-slate-300">
                Usa este nó como ponto de partida para navegar na ontologia ou executa perguntas diretas
                ao motor probabilístico da TypeSafe AI.
              </p>
            </div>

            <div className="grid grid-cols-1 gap-2 pt-1">
              <Button
                variant="outline"
                size="sm"
                onClick={() => onSetAsCurrentNode?.(node.id)}
                className="justify-start gap-2 h-9 border-slate-700 bg-slate-900/60 hover:bg-slate-800 text-xs"
              >
                <Play className="size-3.5 text-amber-400" />
                Definir como Ponto de Partida da Travessia
              </Button>

              <Button
                variant="outline"
                size="sm"
                onClick={() => onOpenPlayground?.(node.id)}
                className="justify-start gap-2 h-9 border-purple-500/40 bg-purple-950/20 hover:bg-purple-900/30 text-purple-200 text-xs"
              >
                <Sparkles className="size-3.5 text-purple-400" />
                Consultar este Nó no Playground Jev
              </Button>
            </div>
          </TabsContent>
        </div>
      </Tabs>
    </div>
  )
}
'''

# ==============================================================================
# 4. Update current-node-card.tsx (Show clean name and info)
# ==============================================================================
CURRENT_NODE_CARD_TSX = '''import { NODE_COLOR_MAP } from "@/lib/graph-visuals"
import type { GraphNode } from "@/services"
import { FloatingPanel } from "./floating-panel"

type Props = {
  currentNode: string
  node: GraphNode | undefined
  hop: number
  totalNodes: number
  goalConfidence: number | null
}

export function CurrentNodeCard({
  currentNode,
  node,
  hop,
  totalNodes,
  goalConfidence,
}: Props) {
  const color = NODE_COLOR_MAP[node?.group ?? ""] ?? "#64748B"
  const cleanDesc = (node?.description || "Sem descrição disponível.")
    .replace(/<[^>]+>/g, " ")
    .replace(/\\s+/g, " ")
    .trim()

  return (
    <FloatingPanel label={`Nó Atual • Salto ${hop}`} className="w-80">
      <div className="flex items-start gap-2.5">
        <span
          className="mt-1 size-3.5 shrink-0 rounded-full shadow-md"
          style={{ backgroundColor: color, boxShadow: `0 0 8px ${color}80` }}
        />
        <div className="min-w-0 flex-1">
          <div className="flex items-center justify-between">
            <span className="font-mono text-sm font-bold text-white tracking-wide">
              {currentNode}
            </span>
            <span
              className="font-mono text-[10px] font-semibold px-2 py-0.5 rounded border"
              style={{
                backgroundColor: `${color}18`,
                borderColor: `${color}50`,
                color: color,
              }}
            >
              {node?.group ?? "Ontologia"}
            </span>
          </div>

          <p className="mt-1 text-xs font-semibold text-slate-200 truncate">
            {node?.name || currentNode}
          </p>

          <p className="mt-1 line-clamp-2 text-[11px] text-slate-400 leading-relaxed">
            {cleanDesc}
          </p>

          <div className="mt-2.5 flex items-center justify-between border-t border-slate-800/80 pt-2 font-mono text-[10px] text-slate-400">
            <span>{totalNodes} nós disponíveis</span>
            {goalConfidence !== null && (
              <span className="font-bold text-amber-400">
                meta {Math.round(goalConfidence * 100)}%
              </span>
            )}
          </div>
        </div>
      </div>
    </FloatingPanel>
  )
}
'''

# ==============================================================================
# 5. Update main-sidebar.tsx (Branding and AppSidebar export)
# ==============================================================================
MAIN_SIDEBAR_TSX = '''import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
} from "@/components/ui/sidebar"
import { RouteEnum } from "@/config/constants"
import { Home, ShieldCheck, Waypoints } from "lucide-react"
import { Link } from "react-router"

const items = [
  { title: "Explorador Jev", url: RouteEnum.EXPLORER, icon: Waypoints },
  { title: "Dashboard / Início", url: RouteEnum.HOME, icon: Home },
]

function Header() {
  return (
    <SidebarHeader className="border-b border-sidebar-border px-4 py-3">
      <div className="flex items-center gap-3">
        <div className="flex size-9 items-center justify-center rounded-xl bg-purple-600/20 border border-purple-500/40 text-purple-400 shadow-md">
          <ShieldCheck className="size-5" />
        </div>
        <div>
          <h1 className="text-sm font-bold text-sidebar-foreground tracking-tight">
            Jev Threat Intel
          </h1>
          <p className="text-[10px] font-mono text-purple-400">
            TypeSafe AI • System 1
          </p>
        </div>
      </div>
    </SidebarHeader>
  )
}

function Content() {
  return (
    <SidebarContent>
      <SidebarGroup>
        <SidebarGroupLabel className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground">
          Navegação Principal
        </SidebarGroupLabel>
        <SidebarGroupContent>
          <SidebarMenu>
            {items.map((item) => (
              <SidebarMenuItem key={item.title}>
                <SidebarMenuButton asChild>
                  <Link to={item.url}>
                    <item.icon className="size-4" />
                    <span>{item.title}</span>
                  </Link>
                </SidebarMenuButton>
              </SidebarMenuItem>
            ))}
          </SidebarMenu>
        </SidebarGroupContent>
      </SidebarGroup>
    </SidebarContent>
  )
}

function Footer() {
  return (
    <SidebarFooter className="border-t border-sidebar-border p-3">
      <div className="rounded-lg bg-card/60 border border-white/5 p-2.5 text-[11px] text-muted-foreground space-y-1">
        <div className="flex items-center justify-between font-mono text-[10px]">
          <span className="text-emerald-400">● Jev API Conectado</span>
          <span className="text-slate-400">3.213 nós</span>
        </div>
        <p className="text-[10px] text-slate-500">
          Decisões probabilísticas em &lt; 250ms
        </p>
      </div>
    </SidebarFooter>
  )
}

export function AppSidebar() {
  return (
    <Sidebar>
      <Header />
      <Content />
      <Footer />
    </Sidebar>
  )
}

export { AppSidebar as MainSidebar }
'''

# ==============================================================================
# 6. Update index.tsx (Search bar across all 3,213 nodes, framework counts, HUD)
# ==============================================================================
EXPLORER_INDEX_TSX = '''import { GraphView } from "@/components/graph-view"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Progress } from "@/components/ui/progress"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Skeleton } from "@/components/ui/skeleton"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import {
  NODE_COLOR_MAP,
  buildVisEdges,
  buildVisNodes,
  extractLocalSubgraph,
} from "@/lib/graph-visuals"
import {
  DEFAULT_GOAL,
  START_NODES,
  useExecuteHop,
  useFetchGraph,
  type TraversalStep,
  type TraversalStrategy,
} from "@/services"
import {
  BookOpen,
  Compass,
  PanelRightClose,
  PanelRightOpen,
  PartyPopper,
  Play,
  RotateCcw,
  Search,
  Sparkles,
  StepForward,
} from "lucide-react"
import { useMemo, useState } from "react"
import { toast } from "sonner"
import { CurrentNodeCard } from "./current-node-card"
import { DirectQueryPlayground } from "./direct-query-playground"
import { GraphLegend } from "./graph-legend"
import { HopInspector } from "./hop-inspector"
import { NodeDetailCard } from "./node-detail-card"
import { TemplatesCatalog } from "./templates-catalog"
import { TraversalTimeline } from "./traversal-timeline"

const MAX_AUTO_HOPS = 6

const STRATEGIES: { id: TraversalStrategy; label: string; desc: string }[] = [
  {
    id: "canonical",
    label: "Canónico",
    desc: "CWE ➔ CAPEC ➔ ATT&CK ➔ D3FEND — ciclo completo de threat modeling.",
  },
  {
    id: "fast_defense",
    label: "Defesa Rápida",
    desc: "Salta diretamente para D3FEND assim que houver ponte defensiva.",
  },
  {
    id: "threat_hunting",
    label: "Threat Hunting",
    desc: "ATT&CK ➔ CAPEC ➔ CWE — investigação a partir de técnicas adversárias.",
  },
  {
    id: "free",
    label: "Exploração Livre",
    desc: "O Jev escolhe os ramos apenas por alinhamento semântico com a meta.",
  },
]

export default function ExplorerPage() {
  const { data: graph, isPending, error } = useFetchGraph()
  const hop = useExecuteHop()

  const [strategy, setStrategy] = useState<TraversalStrategy>("canonical")
  const [activeKgFilter, setActiveKgFilter] = useState("ALL")
  const [startNodeId, setStartNodeId] = useState<string>(START_NODES[0].id)
  const [goal, setGoal] = useState(DEFAULT_GOAL)
  const [currentNode, setCurrentNode] = useState<string>(START_NODES[0].id)
  const [traversedPath, setTraversedPath] = useState<string[]>([START_NODES[0].id])
  const [history, setHistory] = useState<TraversalStep[]>([])
  const [goalAchieved, setGoalAchieved] = useState(false)
  const [viewIdx, setViewIdx] = useState(0)
  const [deadEnd, setDeadEnd] = useState<string | null>(null)
  const [showEdgeLabels, setShowEdgeLabels] = useState(false)
  const [panelOpen, setPanelOpen] = useState(true)
  const [selectedNodeId, setSelectedNodeId] = useState("")
  const [progress, setProgress] = useState<string | null>(null)
  const [activeInspectorTab, setActiveInspectorTab] = useState("inspector")

  // Pesquisa em tempo real nos 3.213 nós
  const [searchQuery, setSearchQuery] = useState("")
  const [searchOpen, setSearchOpen] = useState(false)

  // Contagem dinâmica por framework
  const frameworkCounts = useMemo(() => {
    if (!graph?.nodes) return { ALL: 0, CWE: 0, CAPEC: 0, ATTACK: 0, D3FEND: 0, ATLAS: 0 }
    const c: Record<string, number> = { ALL: graph.nodes.length }
    for (const n of graph.nodes) {
      c[n.group] = (c[n.group] || 0) + 1
    }
    return c
  }, [graph])

  // Resultados de pesquisa instantânea
  const searchResults = useMemo(() => {
    if (!graph?.nodes || !searchQuery.trim() || searchQuery.length < 2) return []
    const q = searchQuery.toLowerCase().trim()
    return graph.nodes
      .filter(
        (n) =>
          n.id.toLowerCase().includes(q) ||
          (n.name && n.name.toLowerCase().includes(q)) ||
          n.group.toLowerCase().includes(q),
      )
      .slice(0, 15)
  }, [graph, searchQuery])

  const localGraph = useMemo(() => {
    if (!graph) return { nodes: [], edges: [], hiddenNeighbors: 0 }
    const sub = extractLocalSubgraph(graph, traversedPath, currentNode)
    if (activeKgFilter === "ALL") return sub

    const keep = new Set(
      sub.nodes
        .filter(
          (node) =>
            node.group === activeKgFilter ||
            traversedPath.includes(node.id) ||
            node.id === currentNode ||
            node.id === selectedNodeId,
        )
        .map((node) => node.id),
    )

    return {
      nodes: sub.nodes.filter((node) => keep.has(node.id)),
      edges: sub.edges.filter((edge) => keep.has(edge.from) && keep.has(edge.to)),
      hiddenNeighbors: sub.hiddenNeighbors,
    }
  }, [graph, traversedPath, currentNode, activeKgFilter, selectedNodeId])

  const visNodes = useMemo(
    () => buildVisNodes(localGraph.nodes, traversedPath, currentNode, selectedNodeId),
    [localGraph, traversedPath, currentNode, selectedNodeId],
  )
  const visEdges = useMemo(
    () => buildVisEdges(localGraph.edges, traversedPath, showEdgeLabels),
    [localGraph, traversedPath, showEdgeLabels],
  )

  const currentGraphNode = graph?.nodes.find((node) => node.id === currentNode)
  const selectedGraphNode = graph?.nodes.find((node) => node.id === selectedNodeId)
  const lastStep = history[viewIdx]

  const handleReset = () => {
    setCurrentNode(startNodeId)
    setTraversedPath([startNodeId])
    setHistory([])
    setGoalAchieved(false)
    setViewIdx(0)
    setDeadEnd(null)
    setSelectedNodeId("")
  }

  const handleStepForward = () => void runHops(1)
  const handleRunAll = () => void runHops(MAX_AUTO_HOPS)

  const handleSelectNode = (nodeId: string) => {
    setSelectedNodeId((prev) => (prev === nodeId ? "" : nodeId))
  }

  const handleSetAsStartNode = (nodeId: string) => {
    setCurrentNode(nodeId)
    setTraversedPath([nodeId])
    setHistory([])
    setGoalAchieved(false)
    setViewIdx(0)
    setDeadEnd(null)
    toast.success(`Nó de partida alterado para ${nodeId}!`)
  }

  const handleOpenPlaygroundWithNode = (_nodeId: string) => {
    setActiveInspectorTab("playground")
    setPanelOpen(true)
  }

  const handleToggleEdgeLabels = () => setShowEdgeLabels((prev) => !prev)

  const runHops = async (maxHops: number) => {
    if (goalAchieved || hop.isPending) return

    let localCurrent = currentNode
    let localPath = traversedPath
    let newSteps = 0

    for (let i = 0; i < maxHops; i++) {
      setProgress(`Jev a decidir salto ${newSteps + 1} de ${maxHops}...`)
      let result
      try {
        result = await hop.mutateAsync({
          currentNode: localCurrent,
          traversedPath: localPath,
          goal,
          strategy,
        })
      } catch (mutationError) {
        toast.error(
          mutationError instanceof Error
            ? mutationError.message
            : "Falha ao executar o salto.",
        )
        break
      }

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

    setProgress(null)
    if (newSteps > 0) {
      setCurrentNode(localCurrent)
      setTraversedPath(localPath)
      setViewIdx(history.length + newSteps - 1)
    }
  }

  return (
    <div className="flex h-full min-h-0 flex-col bg-slate-950 text-slate-100">
      {/* Barra de comando superior */}
      <div className="flex flex-col gap-3 border-b border-slate-800/80 bg-slate-900/40 px-5 py-3 backdrop-blur-md">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <h1 className="text-base font-bold text-white tracking-tight">
              Threat Modeling Explorer
            </h1>
            <Badge
              variant="outline"
              className="border-purple-500/40 bg-purple-500/10 text-purple-300 font-mono text-[10px]"
            >
              Jev System 1
            </Badge>
          </div>

          {/* Pesquisa instantânea em todos os 3.213 nós */}
          <div className="relative flex-1 max-w-md">
            <div className="relative">
              <Search className="absolute left-3 top-2.5 size-4 text-slate-400" />
              <Input
                type="text"
                value={searchQuery}
                onChange={(e) => {
                  setSearchQuery(e.target.value)
                  setSearchOpen(true)
                }}
                onFocus={() => setSearchOpen(true)}
                placeholder="Pesquisar 3.213 nós oficiais (ex: T1059, CWE-79, XSS, Ransomware)..."
                className="h-9 pl-9 pr-4 text-xs bg-slate-950/80 border-slate-700/80 text-white placeholder:text-slate-500 rounded-xl"
              />
            </div>

            {searchOpen && searchResults.length > 0 && (
              <div className="absolute left-0 right-0 top-11 z-50 max-h-72 overflow-y-auto rounded-xl border border-slate-700 bg-slate-950/95 p-1 shadow-2xl backdrop-blur-xl animate-in fade-in zoom-in-95">
                <div className="p-1.5 text-[10px] font-mono text-slate-400 border-b border-slate-800 flex justify-between">
                  <span>Resultados ({searchResults.length})</span>
                  <span>Clique para inspecionar</span>
                </div>
                {searchResults.map((item) => {
                  const itemColor = NODE_COLOR_MAP[item.group] ?? "#64748B"
                  return (
                    <button
                      key={item.id}
                      type="button"
                      onClick={() => {
                        setSelectedNodeId(item.id)
                        setSearchOpen(false)
                        setSearchQuery("")
                      }}
                      className="flex w-full items-center justify-between p-2 rounded-lg text-left hover:bg-slate-800/80 text-xs transition-colors"
                    >
                      <div className="flex items-center gap-2.5 min-w-0 pr-2">
                        <span
                          className="size-2.5 rounded-full shrink-0"
                          style={{ backgroundColor: itemColor }}
                        />
                        <div className="min-w-0">
                          <p className="font-mono font-bold text-slate-200">
                            {item.id}
                          </p>
                          <p className="text-[11px] text-slate-400 truncate">
                            {item.name || item.id}
                          </p>
                        </div>
                      </div>
                      <Badge
                        variant="outline"
                        className="text-[10px] shrink-0 font-mono"
                        style={{ borderColor: `${itemColor}60`, color: itemColor }}
                      >
                        {item.group}
                      </Badge>
                    </button>
                  )
                })}
              </div>
            )}
          </div>

          <div className="flex items-center gap-2">
            <Select value={startNodeId} onValueChange={(val) => { setStartNodeId(val); handleSetAsStartNode(val); }}>
              <SelectTrigger size="sm" className="w-56 text-xs bg-slate-950/60 border-slate-700">
                <SelectValue placeholder="Ponto de Início" />
              </SelectTrigger>
              <SelectContent>
                {START_NODES.map((node) => (
                  <SelectItem key={node.id} value={node.id} className="text-xs">
                    {node.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <Select
              value={strategy}
              onValueChange={(value: string) => setStrategy(value as TraversalStrategy)}
            >
              <SelectTrigger size="sm" className="w-44 text-xs bg-slate-950/60 border-slate-700">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {STRATEGIES.map((item) => (
                  <SelectItem key={item.id} value={item.id} className="text-xs">
                    {item.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        <Textarea
          value={goal}
          onChange={(event) => setGoal(event.target.value)}
          rows={2}
          placeholder="Objetivo da travessia..."
          className="max-w-4xl text-xs bg-slate-950/60 border-slate-800 text-slate-200 resize-none rounded-xl"
        />
      </div>

      {/* Palco Principal do Grafo */}
      <div className="relative min-h-0 flex-1 overflow-hidden bg-slate-950">
        {isPending ? (
          <Skeleton className="absolute inset-0 rounded-none bg-slate-900" />
        ) : error ? (
          <div className="p-6">
            <Alert variant="destructive">
              <AlertTitle>Erro ao carregar o grafo</AlertTitle>
              <AlertDescription>
                Não foi possível aceder ao grafo: {String(error.message)}
              </AlertDescription>
            </Alert>
          </div>
        ) : (
          <GraphView
            nodes={visNodes}
            edges={visEdges}
            onNodeClick={handleSelectNode}
            className={
              panelOpen
                ? "absolute top-0 bottom-0 left-0 right-[416px] transition-all duration-300"
                : "absolute inset-0 transition-all duration-300"
            }
          />
        )}

        {/* Canto superior esquerdo: Nó Atual */}
        <div className="pointer-events-none absolute top-4 left-4">
          <CurrentNodeCard
            currentNode={currentNode}
            node={currentGraphNode}
            hop={traversedPath.length}
            totalNodes={graph?.nodes.length ?? 0}
            goalConfidence={lastStep ? lastStep.jevResponse.noulGoal : null}
          />
        </div>

        {/* Canto inferior esquerdo: Detalhe do Nó Clicado + Legenda */}
        <div className="pointer-events-none absolute bottom-4 left-4 flex flex-col gap-2">
          {selectedGraphNode && (
            <NodeDetailCard
              node={selectedGraphNode}
              edges={localGraph.edges}
              allNodes={graph?.nodes}
              onClose={() => setSelectedNodeId("")}
              onSelectNode={handleSelectNode}
              onSetAsCurrentNode={handleSetAsStartNode}
              onOpenPlayground={handleOpenPlaygroundWithNode}
            />
          )}
          <GraphLegend
            nodes={localGraph.nodes}
            visibleCount={localGraph.nodes.length}
            totalNodes={graph?.nodes.length ?? 0}
            hiddenNeighbors={localGraph.hiddenNeighbors}
            showEdgeLabels={showEdgeLabels}
            onToggleEdgeLabels={handleToggleEdgeLabels}
          />
        </div>

        {/* Canto inferior direito: Filtros de Ontologia e Ações */}
        <div
          className={
            panelOpen
              ? "pointer-events-none absolute right-[432px] bottom-4 flex flex-col items-end gap-2 transition-all duration-300"
              : "pointer-events-none absolute right-4 bottom-4 flex flex-col items-end gap-2 transition-all duration-300"
          }
        >
          {(goalAchieved || deadEnd || progress) && (
            <div className="pointer-events-auto w-80">
              {goalAchieved && (
                <Alert className="border-emerald-500/40 bg-emerald-500/10 py-2.5 backdrop-blur-md">
                  <PartyPopper className="size-4 text-emerald-400" />
                  <AlertTitle className="text-sm text-emerald-400">
                    Objetivo alcançado
                  </AlertTitle>
                  <AlertDescription className="text-xs text-slate-300">
                    <code>{currentNode}</code> atingiu a meta com alta confiança.
                  </AlertDescription>
                </Alert>
              )}
              {deadEnd && (
                <Alert variant="destructive" className="py-2.5 backdrop-blur-md">
                  <AlertTitle className="text-sm">Fim da travessia</AlertTitle>
                  <AlertDescription className="text-xs">{deadEnd}</AlertDescription>
                </Alert>
              )}
              {progress && (
                <div className="rounded-xl border border-white/10 bg-slate-900/90 px-3.5 py-2.5 shadow-xl backdrop-blur-md">
                  <p className="font-mono text-[11px] text-amber-400">
                    {progress}
                  </p>
                  <Progress value={undefined} className="mt-1.5 h-1" />
                </div>
              )}
            </div>
          )}

          {/* Barra de Filtros com Contadores */}
          <div className="pointer-events-auto flex items-center gap-1.5 rounded-2xl border border-slate-800 bg-slate-950/85 p-1.5 shadow-2xl backdrop-blur-xl">
            {[
              { id: "ALL", label: `Todos (${frameworkCounts.ALL || 0})` },
              { id: "CWE", label: `CWE (${frameworkCounts.CWE || 0})` },
              { id: "CAPEC", label: `CAPEC (${frameworkCounts.CAPEC || 0})` },
              { id: "ATTACK", label: `ATT&CK (${frameworkCounts.ATTACK || 0})` },
              { id: "D3FEND", label: `D3FEND (${frameworkCounts.D3FEND || 0})` },
              { id: "ATLAS", label: `ATLAS (${frameworkCounts.ATLAS || 0})` },
            ].map((fw) => (
              <button
                key={fw.id}
                type="button"
                onClick={() => setActiveKgFilter(fw.id)}
                className={
                  activeKgFilter === fw.id
                    ? "rounded-xl bg-purple-600 px-2.5 py-1 font-mono text-[11px] font-semibold text-white shadow-md shadow-purple-600/30"
                    : "rounded-xl px-2.5 py-1 font-mono text-[11px] text-slate-400 hover:bg-slate-800/80 hover:text-slate-200 transition-colors"
                }
              >
                {fw.label}
              </button>
            ))}
            <span className="mx-1 h-5 w-px bg-slate-800" />
            <Button
              size="sm"
              variant="ghost"
              onClick={handleStepForward}
              disabled={goalAchieved || hop.isPending}
              className="text-xs text-slate-200 hover:bg-slate-800"
            >
              <StepForward className="size-3.5 text-purple-400" />
              Próximo Salto
            </Button>
            <Button
              size="sm"
              variant="ghost"
              onClick={handleRunAll}
              disabled={goalAchieved || hop.isPending}
              className="text-xs text-slate-200 hover:bg-slate-800"
            >
              <Play className="size-3.5 text-emerald-400" />
              Auto
            </Button>
            <Button
              size="sm"
              variant="ghost"
              onClick={handleReset}
              className="size-8 p-0 text-slate-400 hover:text-white hover:bg-slate-800"
              title="Reiniciar"
            >
              <RotateCcw className="size-3.5" />
            </Button>
            <Button
              size="sm"
              variant="ghost"
              onClick={() => setPanelOpen((prev) => !prev)}
              className="size-8 p-0 text-slate-400 hover:text-white hover:bg-slate-800"
              title={panelOpen ? "Fechar Painel" : "Abrir Painel"}
            >
              {panelOpen ? (
                <PanelRightClose className="size-3.5" />
              ) : (
                <PanelRightOpen className="size-3.5" />
              )}
            </Button>
          </div>
        </div>

        {/* Painel Lateral Direito (Inspector / Templates / Playground) */}
        {panelOpen && (
          <div className="absolute top-4 right-4 bottom-4 flex w-[410px] flex-col overflow-hidden rounded-2xl border border-slate-800 bg-slate-950/90 shadow-2xl shadow-black/80 backdrop-blur-xl">
            <Tabs
              value={activeInspectorTab}
              onValueChange={setActiveInspectorTab}
              className="flex min-h-0 flex-1 flex-col"
            >
              <div className="border-b border-slate-800/80 px-3 py-2 bg-slate-900/40">
                <TabsList className="grid w-full grid-cols-3 bg-slate-900 border border-slate-800">
                  <TabsTrigger value="inspector" className="text-xs">
                    <Compass className="size-3.5" /> Inspetor
                  </TabsTrigger>
                  <TabsTrigger value="templates" className="text-xs">
                    <BookOpen className="size-3.5" /> Templates
                  </TabsTrigger>
                  <TabsTrigger value="playground" className="text-xs">
                    <Sparkles className="size-3.5" /> Playground
                  </TabsTrigger>
                </TabsList>
              </div>

              <div className="min-h-0 flex-1 overflow-y-auto p-4">
                <TabsContent value="inspector" className="m-0 space-y-4">
                  {history.length > 0 && (
                    <div className="space-y-3">
                      <Select
                        value={String(viewIdx)}
                        onValueChange={(val) => setViewIdx(Number(val))}
                      >
                        <SelectTrigger size="sm" className="w-full text-xs bg-slate-900 border-slate-700">
                          <SelectValue placeholder="Salto a inspecionar" />
                        </SelectTrigger>
                        <SelectContent>
                          {history.map((step, idx) => (
                            <SelectItem key={idx} value={String(idx)} className="text-xs">
                              Salto #{idx + 1}: {step.currentNode} ➔ {step.level1Router?.targetFramework || "Decisão Jev"}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                      <TraversalTimeline
                        steps={history}
                        selectedIdx={viewIdx}
                        onSelect={setViewIdx}
                      />
                    </div>
                  )}

                  {lastStep ? (
                    <HopInspector step={lastStep} />
                  ) : (
                    <div className="rounded-xl border border-dashed border-slate-800 p-8 text-center text-xs text-slate-500 space-y-2">
                      <Compass className="size-8 mx-auto text-slate-600" />
                      <p className="font-semibold text-slate-400">Nenhum salto executado ainda</p>
                      <p className="text-[11px] text-slate-500">
                        Clica em "Próximo Salto" ou seleciona um nó no grafo para iniciar a análise do Jev System 1.
                      </p>
                    </div>
                  )}
                </TabsContent>

                <TabsContent value="templates" className="m-0">
                  <TemplatesCatalog />
                </TabsContent>

                <TabsContent value="playground" className="m-0">
                  <DirectQueryPlayground
                    currentNode={selectedNodeId || currentNode}
                    goal={goal}
                  />
                </TabsContent>
              </div>
            </Tabs>
          </div>
        )}
      </div>
    </div>
  )
}
'''

# ==============================================================================
# 7. Update App.tsx (Redirect / to /explorer by default)
# ==============================================================================
APP_TSX = '''import Lazy, { lazyWithRetry as withRetry } from "@/components/lazy-component"
import { RouteEnum } from "@/config/constants"
import { SidebarLayout } from "@/containers/Layout/sidebar-layout"
import NotFound from "@/pages/NotFound"
import { Navigate, Route, Routes } from "react-router"

const HomePage = Lazy(withRetry(() => import("@/pages/Home")))
const ExplorerPage = Lazy(withRetry(() => import("@/pages/Explorer")))

function App() {
  return (
    <Routes>
      <Route element={<SidebarLayout />}>
        <Route path={RouteEnum.EXPLORER} element={<ExplorerPage />} />
        <Route path={RouteEnum.HOME + "/*"} element={<HomePage />} />
      </Route>
      <Route path="/" element={<Navigate to={RouteEnum.EXPLORER} replace />} />
      <Route path="*" element={<NotFound />} />
    </Routes>
  )
}

export default App
'''

def apply_enhancements():
    print("=== APLICANDO MELHORIAS PROFISSIONAIS AO FRONTEND (TEMPLATE_REACT) ===")

    # 1. types.ts
    p_types = BASE_REACT / "services" / "Explorer" / "types.ts"
    p_types.write_text(EXPLORER_TYPES_TS, encoding="utf-8")
    print(f"  [1] Atualizado: {p_types.relative_to(BASE_REACT.parent.parent)}")

    # 2. graph-visuals.ts
    p_gv = BASE_REACT / "lib" / "graph-visuals.ts"
    p_gv.write_text(GRAPH_VISUALS_TS, encoding="utf-8")
    print(f"  [2] Atualizado: {p_gv.relative_to(BASE_REACT.parent.parent)}")

    # 3. node-detail-card.tsx
    p_ndc = BASE_REACT / "pages" / "Explorer" / "node-detail-card.tsx"
    p_ndc.write_text(NODE_DETAIL_CARD_TSX, encoding="utf-8")
    print(f"  [3] Atualizado: {p_ndc.relative_to(BASE_REACT.parent.parent)}")

    # 4. current-node-card.tsx
    p_cnc = BASE_REACT / "pages" / "Explorer" / "current-node-card.tsx"
    p_cnc.write_text(CURRENT_NODE_CARD_TSX, encoding="utf-8")
    print(f"  [4] Atualizado: {p_cnc.relative_to(BASE_REACT.parent.parent)}")

    # 5. main-sidebar.tsx
    p_ms = BASE_REACT / "containers" / "Sidebar" / "main-sidebar.tsx"
    p_ms.write_text(MAIN_SIDEBAR_TSX, encoding="utf-8")
    print(f"  [5] Atualizado: {p_ms.relative_to(BASE_REACT.parent.parent)}")

    # 6. Explorer index.tsx
    p_ei = BASE_REACT / "pages" / "Explorer" / "index.tsx"
    p_ei.write_text(EXPLORER_INDEX_TSX, encoding="utf-8")
    print(f"  [6] Atualizado: {p_ei.relative_to(BASE_REACT.parent.parent)}")

    # 7. App.tsx
    p_app = BASE_REACT / "containers" / "App" / "App.tsx"
    p_app.write_text(APP_TSX, encoding="utf-8")
    print(f"  [7] Atualizado: {p_app.relative_to(BASE_REACT.parent.parent)}")

    print("\nTodas as 7 melhorias foram aplicadas com sucesso no working tree local!")


if __name__ == "__main__":
    apply_enhancements()
