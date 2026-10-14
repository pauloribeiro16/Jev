import { useEffect, useState } from "react"
import { MetricStrip } from "./metric-strip"
import { Scissors, AlertTriangle, ShieldCheck, Zap, Sparkles, Filter, ChevronRight } from "lucide-react"

type PrunedBranch = {
  node_id: string
  node_name: string
  framework: string
  parent_id: string
  stage: string
  is_viable_prob: number
  heuristic_score: number
  is_trap: boolean
  prune_reason: string
  subgraph_calls_saved: number
}

type ScenarioResult = {
  id: string
  title: string
  initial_cwe: string
  target_d3fend: string
  unpruned_expansions: number
  pruned_expansions: number
  expansions_saved: number
  savings_percent: number
  unpruned_dead_ends: number
  pruned_dead_ends_prevented: number
  traps_injected: number
  traps_pruned: number
  trap_detection_rate: number
  false_negative_count: number
  target_reached: boolean
  surviving_paths: string[][]
  pruned_branches: PrunedBranch[]
  total_time_ms: number
  avg_decision_latency_ms: number
}

type PruningReportData = {
  generated_at: string
  mode: string
  overall_metrics: {
    total_unpruned_expansions: number
    total_pruned_expansions: number
    total_expansions_saved: number
    overall_savings_percent: number
    total_traps_injected: number
    total_traps_pruned: number
    overall_trap_detection_rate: number
    total_false_negatives: number
    zero_false_negatives_verified: boolean
  }
  scenarios: ScenarioResult[]
}

const FW_BADGE: Record<string, string> = {
  CWE: "bg-sky-500/10 text-sky-400 border-sky-500/30",
  CAPEC: "bg-amber-500/10 text-amber-400 border-amber-500/30",
  "ATT&CK": "bg-rose-500/10 text-rose-400 border-rose-500/30",
  D3FEND: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
  ATLAS: "bg-fuchsia-500/10 text-fuchsia-400 border-fuchsia-500/30",
}

export function PruningView() {
  const [data, setData] = useState<PruningReportData | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selectedScenarioIdx, setSelectedScenarioIdx] = useState(0)

  useEffect(() => {
    fetch("/pruning_report.json")
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}: pruning_report.json não encontrado`)
        return res.json()
      })
      .then((json) => {
        setData(json)
        setLoading(false)
      })
      .catch((err) => {
        setError(err.message)
        setLoading(false)
      })
  }, [])

  if (loading) {
    return (
      <div className="p-8 text-sm text-muted-foreground animate-pulse flex items-center gap-2">
        <Scissors className="w-4 h-4 animate-spin text-primary" />
        A carregar benchmark de Poda Precoce & Eliminação de Becos Sem Saída…
      </div>
    )
  }

  if (error || !data) {
    return (
      <div className="rounded-xl border border-destructive/50 bg-destructive/10 p-6 text-sm">
        <p className="font-semibold text-destructive flex items-center gap-2">
          <AlertTriangle className="w-4 h-4" /> Relatório de Poda não encontrado
        </p>
        <p className="text-xs text-muted-foreground mt-2">
          Executa o benchmark: <code>.venv/bin/python3 scripts/run_pruning_test.py</code>
        </p>
      </div>
    )
  }

  const { overall_metrics, scenarios } = data
  const sc = scenarios[selectedScenarioIdx] || scenarios[0]

  return (
    <div className="space-y-6">
      {/* Top High-Level Metrics Strip */}
      <MetricStrip
        metrics={[
          {
            label: "Poupança de Nós / Chamadas",
            value: `${overall_metrics.overall_savings_percent}%`,
            hint: `${overall_metrics.total_expansions_saved} expansões poupadas vs busca cega`,
          },
          {
            label: "Deteção de Armadilhas",
            value: `${overall_metrics.overall_trap_detection_rate}%`,
            hint: `${overall_metrics.total_traps_pruned}/${overall_metrics.total_traps_injected} armadilhas contextualizadas cortadas`,
          },
          {
            label: "Falsos Negativos (Caminhos Válidos)",
            value: `${overall_metrics.total_false_negatives}`,
            hint: "Nenhuma contramedida real foi podada por engano",
          },
          {
            label: "Modo de Inferência",
            value: data.mode === "live_typesafe_api" ? "TypeSafe Jev API" : "Mock Calibrado",
            hint: "Avaliação System 1 com Noul (viabilidade) e Score",
          },
        ]}
      />

      {/* Scenario Selector Tabs */}
      <div className="flex items-center gap-2 overflow-x-auto pb-1">
        {scenarios.map((s, idx) => {
          const active = idx === selectedScenarioIdx
          return (
            <button
              key={s.id}
              type="button"
              className={`flex items-center gap-2 px-3.5 py-2 rounded-xl text-xs font-medium transition-all whitespace-nowrap cursor-pointer border ${
                active
                  ? "bg-primary text-primary-foreground border-primary shadow-sm"
                  : "bg-card hover:bg-popover text-muted-foreground hover:text-foreground border-border"
              }`}
              onClick={() => setSelectedScenarioIdx(idx)}
            >
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>{s.title}</span>
            </button>
          )
        })}
      </div>

      {/* Active Scenario Hero Card */}
      <div className="rounded-2xl border border-border bg-card/60 backdrop-blur p-5 shadow-sm space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border/60 pb-4">
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold uppercase tracking-wider text-primary flex items-center gap-1">
                <Scissors className="w-3.5 h-3.5" /> Caso {selectedScenarioIdx + 1}:
              </span>
              <h2 className="text-lg font-bold text-foreground">{sc.title}</h2>
            </div>
            <p className="text-xs text-muted-foreground mt-1">
              Ponto de Partida: <strong className="text-foreground">{sc.initial_cwe}</strong> · Alvo Defensivo: <strong className="text-emerald-400">{sc.target_d3fend}</strong>
            </p>
          </div>

          <div className="flex items-center gap-3">
            <div className="text-right">
              <div className="text-xl font-mono font-bold text-emerald-400">
                {sc.savings_percent > 0 ? `-${sc.savings_percent}%` : "Baseline"}
              </div>
              <div className="text-[11px] text-muted-foreground">Chamadas Poupadas</div>
            </div>
            <div className="h-8 w-px bg-border" />
            <div className="text-right">
              <div className="text-xl font-mono font-bold text-primary">
                {sc.pruned_branches.length}
              </div>
              <div className="text-[11px] text-muted-foreground">Ramos Podados</div>
            </div>
          </div>
        </div>

        {/* Comparison Grid: Cego vs Jev Guard */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Left: Busca Cega */}
          <div className="rounded-xl border border-rose-500/20 bg-rose-500/5 p-4 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold uppercase tracking-wider text-rose-400 flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5" /> Busca Cega Sem Poda (Baseline)
              </span>
              <span className="text-xs font-mono font-bold text-rose-300">
                {sc.unpruned_expansions} nós explorados
              </span>
            </div>
            <p className="text-xs text-muted-foreground leading-relaxed">
              Explora exaustivamente ramificações implausíveis e becos sem saída ontológicos,
              desperdiçando tokens e latência em técnicas que não têm correspondência em D3FEND.
            </p>
            <div className="flex items-center gap-4 text-xs font-mono pt-1 text-muted-foreground">
              <span>Becos sem saída: <strong className="text-rose-400">{sc.unpruned_dead_ends}</strong></span>
              <span>·</span>
              <span>Armadilhas exploradas: <strong className="text-rose-400">{sc.traps_injected}</strong></span>
            </div>
          </div>

          {/* Right: Jev Early Prune Guard */}
          <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-4 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold uppercase tracking-wider text-emerald-400 flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5" /> Jev Early Prune Guard (Ativo)
              </span>
              <span className="text-xs font-mono font-bold text-emerald-300">
                {sc.pruned_expansions} nós explorados
              </span>
            </div>
            <p className="text-xs text-muted-foreground leading-relaxed">
              Avalia cada transição com Jev (Noul de viabilidade operacional + Score de potencial defensivo).
              Corta o ramo imediatamente no nível 1 ou 2, evitando toda a árvore descendente.
            </p>
            <div className="flex items-center gap-4 text-xs font-mono pt-1 text-muted-foreground">
              <span>Expansões poupadas: <strong className="text-emerald-400">{sc.expansions_saved}</strong></span>
              <span>·</span>
              <span>Armadilhas travadas: <strong className="text-emerald-400">{sc.traps_pruned}/{sc.traps_injected}</strong></span>
            </div>
          </div>
        </div>
      </div>

      {/* Pruned Branches Table */}
      <div className="rounded-2xl border border-border bg-card overflow-hidden shadow-sm">
        <div className="p-4 border-b border-border flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-primary" />
            <h3 className="text-sm font-bold text-foreground">
              Ramos e Becos Sem Saída Eliminados pelo Jev ({sc.pruned_branches.length})
            </h3>
          </div>
          <span className="text-xs text-muted-foreground font-mono">
            Latência média por poda: {sc.avg_decision_latency_ms} ms
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-popover/80 border-b border-border font-semibold text-muted-foreground">
              <tr>
                <th className="py-2.5 px-4">Nó Candidato</th>
                <th className="py-2.5 px-4">Transição</th>
                <th className="py-2.5 px-4">Viabilidade Jev (Noul)</th>
                <th className="py-2.5 px-4">Score Defensivo</th>
                <th className="py-2.5 px-4">Chamadas Poupadas</th>
                <th className="py-2.5 px-4">Justificação do Corte</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/60">
              {sc.pruned_branches.map((b) => (
                <tr key={`${b.parent_id}-${b.node_id}`} className="hover:bg-popover/40 transition-colors">
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-2">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold border ${FW_BADGE[b.framework] || "bg-card"}`}>
                        {b.node_id}
                      </span>
                      <span className="font-medium text-foreground max-w-[220px] truncate" title={b.node_name}>
                        {b.node_name}
                      </span>
                      {b.is_trap && (
                        <span className="px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40 text-[9px] font-bold">
                          ARMADILHA DETETADA
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="py-3 px-4 font-mono text-muted-foreground">
                    {b.stage}
                  </td>
                  <td className="py-3 px-4 font-mono">
                    <span className={b.is_viable_prob < 0.4 ? "text-rose-400 font-bold" : "text-amber-400"}>
                      {(b.is_viable_prob * 100).toFixed(0)}%
                    </span>
                  </td>
                  <td className="py-3 px-4 font-mono">
                    <span className={b.heuristic_score <= 1 ? "text-rose-400 font-bold" : "text-foreground"}>
                      {b.heuristic_score} / 3
                    </span>
                  </td>
                  <td className="py-3 px-4 font-mono text-emerald-400 font-bold">
                    +{b.subgraph_calls_saved} chamadas
                  </td>
                  <td className="py-3 px-4 text-muted-foreground text-[11px] max-w-[320px] truncate" title={b.prune_reason}>
                    {b.prune_reason}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Surviving Defensive Paths */}
      {sc.surviving_paths.length > 0 && (
        <div className="rounded-2xl border border-emerald-500/30 bg-emerald-500/5 p-4 space-y-3">
          <div className="flex items-center gap-2">
            <Zap className="w-4 h-4 text-emerald-400" />
            <h4 className="text-xs font-bold uppercase tracking-wider text-emerald-300">
              Cadeias Defensivas Sobreviventes Aprovadas ({sc.surviving_paths.length})
            </h4>
          </div>
          <div className="space-y-2">
            {sc.surviving_paths.map((p, i) => (
              <div key={i} className="flex items-center gap-2 p-2.5 rounded-xl bg-card border border-border text-xs font-mono overflow-x-auto">
                <span className="text-muted-foreground font-bold">#{i + 1}</span>
                {p.map((n, idx) => (
                  <div key={idx} className="flex items-center gap-2 shrink-0">
                    <span className="px-2 py-0.5 rounded bg-popover font-bold text-foreground border border-border">
                      {n}
                    </span>
                    {idx < p.length - 1 && <ChevronRight className="w-3.5 h-3.5 text-muted-foreground" />}
                  </div>
                ))}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
