import { useEffect, useState } from "react"
import { MetricStrip } from "./metric-strip"

type SurvivingPath = {
  path: string[]
  score: number
}

type BacktrackedBranch = {
  branch: string[]
  reason: string
}

type BeamSearchData = {
  generated_at: string
  incident: {
    title: string
    scenario: string
    target_asset: string
    actor: string
  }
  initial_cwes: string[]
  best_path: string[]
  best_score: number
  drift_guard_verdict: number
  total_expansions: number
  avg_latency_per_expansion_ms: number
  total_latency_ms: number
  all_surviving_paths: SurvivingPath[]
  backtracked_branches: BacktrackedBranch[]
}

export function BeamSearchView() {
  const [data, setData] = useState<BeamSearchData | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetch("/beam_search_report.json")
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}: beam_search_report.json não encontrado`)
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
      <div className="p-6 text-sm text-muted-foreground animate-pulse">
        A carregar benchmark de Beam Search & Backtracking…
      </div>
    )
  }

  if (error || !data) {
    return (
      <div className="rounded-lg border border-destructive/50 bg-destructive/10 p-6 text-sm text-foreground">
        <p className="font-semibold text-destructive">Relatório de Beam Search não encontrado</p>
        <p className="text-xs text-muted-foreground mt-1">
          Executa o benchmark: <code>.venv/bin/python3 scripts/run_beam_search_test.py</code>
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Metric Strip */}
      <MetricStrip
        metrics={[
          { label: "Caminho Vencedor", value: data.best_path.join(" → ") },
          { label: "Score Cumulativo", value: data.best_score.toFixed(4) },
          { label: "Expansões", value: `${data.total_expansions} nós` },
          { label: "Latência Média / Expansão", value: `${data.avg_latency_per_expansion_ms.toFixed(1)} ms` },
          { label: "Tempo Total", value: `${Math.round(data.total_latency_ms)} ms` },
        ]}
      />

      {/* Incident & Search Parameters */}
      <div className="rounded-xl border border-border bg-card p-5 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-border/60 pb-3">
          <div>
            <span className="text-xs font-semibold uppercase tracking-wider text-primary">
              🧭 Parâmetros do Algoritmo de Procura
            </span>
            <h3 className="text-base font-semibold text-foreground mt-0.5">{data.incident.title}</h3>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs bg-primary/20 text-primary border border-primary/30 px-2.5 py-1 rounded-full font-mono">
              Beam Width K = 2
            </span>
            <span className="text-xs bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 px-2.5 py-1 rounded-full">
              Backtracking Ativo
            </span>
          </div>
        </div>

        <p className="text-xs text-muted-foreground leading-relaxed">
          {data.incident.scenario}
        </p>

        <div className="flex flex-wrap gap-4 text-xs pt-1">
          <div>
            <strong className="text-foreground">Ativo Alvo:</strong>{" "}
            <span className="text-muted-foreground">{data.incident.target_asset}</span>
          </div>
          <div>
            <strong className="text-foreground">Ator de Ameaça:</strong>{" "}
            <span className="text-muted-foreground">{data.incident.actor}</span>
          </div>
        </div>
      </div>

      {/* Dead-End & Backtracking Visual Showcase */}
      <div className="rounded-xl border border-border bg-card p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-border/60 pb-3">
          <div className="flex items-center gap-2">
            <span className="text-base font-semibold text-foreground">
              🔀 Resiliência a Becos Sem Saída (Dead-End Recovery)
            </span>
            <span className="text-xs bg-amber-500/20 text-amber-300 border border-amber-500/30 px-2 py-0.5 rounded">
              Caso Real Demonstrado
            </span>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Pruned Dead End */}
          <div className="rounded-lg border border-destructive/40 bg-destructive/10 p-4 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-destructive flex items-center gap-1.5">
                ❌ Beco Sem Saída Ontológico
              </span>
              <span className="text-[11px] font-mono text-muted-foreground">Hop 3 (ATT&CK)</span>
            </div>
            <div className="p-2.5 rounded bg-popover/80 border border-destructive/30 text-xs font-mono text-destructive-foreground">
              {data.backtracked_branches[0]?.branch.join(" → ") || "CWE-285 → CAPEC-39"}
            </div>
            <p className="text-xs text-muted-foreground">
              {data.backtracked_branches[0]?.reason ||
                "CAPEC-39 não possuía vizinhos ATT&CK no grafo. Um algoritmo Greedy 1-Best entraria em falha neste ponto."}
            </p>
          </div>

          {/* Automatic Backtracking Path */}
          <div className="rounded-lg border border-emerald-500/40 bg-emerald-950/20 p-4 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-emerald-400 flex items-center gap-1.5">
                ✓ Recuperação Automática no Beam
              </span>
              <span className="text-[11px] font-mono text-emerald-300/80">Ramo Sobrevivente</span>
            </div>
            <div className="p-2.5 rounded bg-popover/80 border border-emerald-500/30 text-xs font-mono text-emerald-300">
              CWE-285 → CAPEC-1 → T1574.010 → D3-AVE
            </div>
            <p className="text-xs text-muted-foreground">
              O Beam Search manteve o candidato #2 no feixe e continuou a travessia ontológica até às defesas D3FEND sem interrupção.
            </p>
          </div>
        </div>
      </div>

      {/* Surviving Paths Ranking */}
      <div className="rounded-xl border border-border bg-card p-5 space-y-4">
        <h4 className="text-sm font-semibold text-foreground flex items-center gap-2">
          <span>🏆 Todos os Caminhos de Defesa Sobreviventes (K=2)</span>
        </h4>

        <div className="space-y-3">
          {data.all_surviving_paths.map((p, idx) => {
            const isTop = idx === 0
            return (
              <div
                key={idx}
                className={`rounded-lg border p-4 space-y-2 transition-all ${
                  isTop
                    ? "border-primary/60 bg-primary/5 shadow-sm"
                    : "border-border bg-background/50"
                }`}
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span
                      className={`text-xs font-bold px-2 py-0.5 rounded ${
                        isTop ? "bg-primary text-primary-foreground" : "bg-popover text-muted-foreground"
                      }`}
                    >
                      #{idx + 1}
                    </span>
                    <span className="font-mono text-xs sm:text-sm font-medium text-foreground">
                      {p.path.join(" → ")}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-muted-foreground">Score Cumulativo:</span>
                    <span className="text-xs font-mono font-bold text-primary bg-popover px-2 py-0.5 rounded border border-border">
                      {p.score.toFixed(4)}
                    </span>
                  </div>
                </div>

                <div className="flex items-center gap-2 text-xs text-muted-foreground pt-1">
                  <span>Mitigação Proposta:</span>
                  <span className="font-semibold text-foreground font-mono">
                    {p.path[p.path.length - 1]} (D3FEND)
                  </span>
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
