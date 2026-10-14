import { useEffect, useState } from "react"
import { MetricStrip } from "./metric-strip"

type PermutationRun = {
  permutation_label: string
  order: string[]
  decision: string
  confidence: number
  probabilities: Record<string, number>
  latency_ms: number
}

type DistractorResult = {
  variant: string
  decision: string
  expected: string
  is_correct: boolean
  confidence: number
  noise_rejection_score: number
  probabilities: Record<string, number>
  latency_ms: number
}

type DriftEvaluation = {
  chain: string[]
  aligned: boolean
  drift_score?: number
}

type RobustnessData = {
  generated_at: string
  total_execution_time_ms: number
  summary: {
    position_bias_stability: number
    max_probability_deviation: number
    adversarial_distractor_accuracy: number
    round_trip_consistency_rate: number
  }
  tests: {
    position_bias: {
      test_name: string
      description: string
      decision_stability: number
      max_probability_deviation: number
      runs: PermutationRun[]
    }
    adversarial_distractor: {
      test_name: string
      description: string
      accuracy: number
      variants_evaluated: number
      results: DistractorResult[]
    }
    round_trip_drift?: {
      test_name: string
      description: string
      consistency_rate: number
      chains_evaluated: number
      evaluations?: DriftEvaluation[]
    }
  }
}

export function RobustnessView() {
  const [data, setData] = useState<RobustnessData | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetch("/robustness_report.json")
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}: robustness_report.json não encontrado`)
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
        A carregar métricas de robustez e estabilidade…
      </div>
    )
  }

  if (error || !data) {
    return (
      <div className="rounded-xl border border-destructive/50 bg-destructive/10 p-6 text-sm text-foreground">
        <p className="font-semibold text-destructive">Erro ao carregar suite de robustez</p>
        <p className="text-xs text-muted-foreground mt-1">
          Executa a suite via terminal: <code>.venv/bin/python3 scripts/test_robustness_and_drift.py</code>
        </p>
      </div>
    )
  }

  const { summary, tests } = data
  const pb = tests?.position_bias
  const distractor = tests?.adversarial_distractor
  const drift = tests?.round_trip_drift

  return (
    <div className="space-y-6">
      {/* Top metrics summary */}
      <MetricStrip
        metrics={[
          {
            label: "Estabilidade de Posição",
            value: `${Math.round((summary?.position_bias_stability ?? 1) * 100)}%`,
          },
          {
            label: "Desvio Máx. Probabilidade",
            value: `${(summary?.max_probability_deviation ?? 0).toFixed(3)}`,
          },
          {
            label: "Imunidade a Distratores",
            value: `${Math.round((summary?.adversarial_distractor_accuracy ?? 1) * 100)}%`,
          },
          {
            label: "Tempo Total Suite",
            value: `${Math.round(data.total_execution_time_ms ?? 0)} ms`,
          },
        ]}
      />

      {/* Test 1: Position Bias & Permutations */}
      {pb && (
        <div className="rounded-xl border border-border bg-card p-5 space-y-4 shadow-sm">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-border/60 pb-3">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-base font-semibold text-foreground">
                  🔄 Invariância de Posição (Permutações no Choice)
                </span>
                <span className="rounded-full bg-emerald-500/20 text-emerald-400 px-2.5 py-0.5 text-xs font-medium border border-emerald-500/30">
                  {Math.round((pb.decision_stability ?? 1) * 100)}% Estável
                </span>
              </div>
              <p className="text-xs text-muted-foreground mt-1">
                {pb.description}. Avalia se a ordem das opções (rotação e inversão) distorce a probabilidade do modelo.
              </p>
            </div>
            <div className="text-xs font-mono text-muted-foreground bg-popover px-2.5 py-1 rounded-lg border border-border">
              Δ Máx: <strong>{pb.max_probability_deviation ?? 0}</strong>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
            {(pb.runs || []).map((run, idx) => (
              <div
                key={idx}
                className="rounded-lg border border-border/80 bg-background/60 p-3.5 space-y-2.5 transition-all hover:border-primary/40"
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-medium text-primary">{run.permutation_label}</span>
                  <span className="text-[11px] font-mono text-muted-foreground">
                    {run.latency_ms ? `${run.latency_ms.toFixed(0)} ms` : "—"}
                  </span>
                </div>

                <div className="space-y-1">
                  <span className="text-[11px] text-muted-foreground">Ordem das opções:</span>
                  <div className="flex flex-wrap gap-1">
                    {(run.order || []).map((opt) => (
                      <span
                        key={opt}
                        className={`text-[11px] font-mono px-1.5 py-0.5 rounded ${
                          opt === run.decision
                            ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 font-semibold"
                            : "bg-popover text-muted-foreground border border-border"
                        }`}
                      >
                        {opt}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="pt-1 border-t border-border/40 flex items-center justify-between text-xs">
                  <span className="text-muted-foreground">Decisão:</span>
                  <span className="font-bold text-emerald-400">
                    {run.decision} ({Math.round((run.confidence ?? 1) * 100)}%)
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Test 2: Adversarial Distractors (Red Herrings) */}
      {distractor && (
        <div className="rounded-xl border border-border bg-card p-5 space-y-4 shadow-sm">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-border/60 pb-3">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-base font-semibold text-foreground">
                  🎯 Imunidade a Distratores Adversários &amp; Pistas Falsas
                </span>
                <span className="rounded-full bg-emerald-500/20 text-emerald-400 px-2.5 py-0.5 text-xs font-medium border border-emerald-500/30">
                  {Math.round((distractor.accuracy ?? 1) * 100)}% Precisão
                </span>
              </div>
              <p className="text-xs text-muted-foreground mt-1">
                {distractor.description}. Foram testadas {distractor.variants_evaluated} variantes de incidentes com ruído espúrio (ex: SSH brute force, SQLi) sem desviar a causa-raiz (SSRF IMDSv1).
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {(distractor.results || []).map((res, i) => (
              <div key={i} className="rounded-lg border border-border bg-background/50 p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-foreground truncate max-w-[200px]" title={res.variant}>
                    {res.variant}
                  </span>
                  <span className="text-[11px] font-mono text-emerald-400 font-semibold bg-emerald-500/15 px-2 py-0.5 rounded border border-emerald-500/30">
                    ✓ {res.decision}
                  </span>
                </div>

                <div className="text-xs space-y-1.5 pt-1">
                  <div className="flex justify-between text-muted-foreground">
                    <span>Rejeição de Ruído:</span>
                    <strong className="text-primary font-mono">{res.noise_rejection_score?.toFixed(2)} / 3.0</strong>
                  </div>
                  <div className="flex justify-between text-muted-foreground">
                    <span>Confiança Jev:</span>
                    <strong className="text-emerald-400 font-mono">{Math.round((res.confidence ?? 1) * 100)}%</strong>
                  </div>
                  <div className="flex justify-between text-muted-foreground">
                    <span>Latência:</span>
                    <span className="font-mono">{res.latency_ms?.toFixed(0)} ms</span>
                  </div>
                </div>

                {res.probabilities && (
                  <div className="space-y-1 pt-2 border-t border-border/50">
                    <span className="text-[11px] text-muted-foreground">Probabilidades:</span>
                    {Object.entries(res.probabilities).map(([cand, prob]) => (
                      <div key={cand} className="flex items-center gap-1.5 text-[11px]">
                        <span className="w-14 font-mono text-muted-foreground">{cand}</span>
                        <div className="flex-1 h-1.5 rounded-full bg-popover overflow-hidden border border-border/40">
                          <div
                            className={`h-full rounded-full ${
                              cand === res.decision ? "bg-emerald-400" : "bg-muted-foreground/30"
                            }`}
                            style={{ width: `${Math.round(prob * 100)}%` }}
                          />
                        </div>
                        <span className="w-8 text-right font-mono text-[10px] text-muted-foreground">
                          {Math.round(prob * 100)}%
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Test 3: Semantic Drift Analysis */}
      {drift && (
        <div className="rounded-xl border border-border bg-card p-5 space-y-3 shadow-sm">
          <div className="flex items-center justify-between border-b border-border/60 pb-3">
            <div>
              <span className="text-base font-semibold text-foreground">
                🧭 Avaliação de Deriva Semântica (Cadeias Ontológicas)
              </span>
              <p className="text-xs text-muted-foreground mt-1">
                {drift.description}. {drift.chains_evaluated} cadeias sequenciais avaliadas de ponta a ponta.
              </p>
            </div>
            <span className="text-xs font-mono bg-popover px-2.5 py-1 rounded border border-border text-muted-foreground">
              {drift.chains_evaluated} Cadeias
            </span>
          </div>
          <p className="text-xs text-muted-foreground leading-relaxed">
            Mede a sensibilidade de classificação ao longo da cadeia causal. Mostra que o System 1 discrimina nós vizinhos com base no contexto cumulativo, evitando a perda de fidelidade semântica.
          </p>
        </div>
      )}
    </div>
  )
}
