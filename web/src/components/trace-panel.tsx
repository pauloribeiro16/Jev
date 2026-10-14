import { useEffect, useState, useMemo } from "react"
import { MetricStrip } from "./metric-strip"

type Criteria = Record<string, string> | string[] | undefined
type Answer = {
  type?: string
  choice?: string
  confidence?: number
  noul?: number
  score?: number
  legend?: Record<string, string>
  probabilities?: Record<string, number>
}
type Trace = {
  key?: string
  title?: string
  ok?: boolean
  error?: string
  iso?: string
  site?: string
  model?: string
  tokens?: number
  latencyMs?: number
  request_id?: string
  input_tokens?: number
  output_tokens?: number
  request?: {
    state?: any
    questions?: Record<string, { type?: string; instructions?: string; criteria?: Criteria }>
  }
  response?: { answers?: Record<string, Answer> }
}

type TraceSession = {
  id: string
  site: string
  siteLabel: string
  title: string
  scenario?: string
  hop?: string
  calls: Trace[]
  totalTokens: number
  totalLatencyMs: number
  startedAt?: string
}

function labelFor(key: string, criteria: Criteria): string {
  if (!criteria) return key
  const raw = Array.isArray(criteria) ? criteria[Number(key)] : (criteria as Record<string, string>)[key]
  if (raw === undefined || raw === null) return key
  if (typeof raw !== "string") return JSON.stringify(raw)
  const m = /'([^']*)'\s*\(([^)]*)\)/.exec(raw)
  return m ? `${m[1]} (${m[2]})` : raw
}

function scoreLabel(score: number, legend?: Record<string, string>) {
  if (!legend || typeof legend !== "object") return `score ${score}`
  const keys = Object.keys(legend).map(Number).filter((n) => !isNaN(n)).sort((a, b) => a - b)
  if (!keys.length) return `score ${score}`
  const lo = keys.filter((k) => k <= score).pop()
  const hi = keys.find((k) => k > score)
  if (hi === undefined) return `score ${score} · ${legend[String(lo)] || ""}`
  if (lo === undefined) return `score ${score} · below ${legend[String(hi)] || ""}`
  return `score ${score} · ${legend[String(lo)] || ""} → ${legend[String(hi)] || ""}`
}

function ProbsBar({
  probabilities,
  criteria,
  picked,
}: {
  probabilities?: Record<string, number>
  criteria: Criteria
  picked?: string
}) {
  if (!probabilities || typeof probabilities !== "object") return null
  const entries = Object.entries(probabilities).sort((a, b) => b[1] - a[1])
  if (!entries.length) return null
  const top = Math.max(...entries.map(([, v]) => v), 0.001)

  return (
    <ul className="space-y-1.5 pt-1">
      {entries.map(([k, v]) => {
        const isSelected = k === picked
        return (
          <li key={k} className="flex items-center gap-2 text-xs">
            <div className="w-56 min-w-0 flex flex-col">
              <span className={`truncate text-xs ${isSelected ? "font-bold text-primary" : "text-foreground"}`}>
                {labelFor(k, criteria)}
              </span>
              <span className="font-mono text-[10px] text-muted-foreground">{k}</span>
            </div>
            <div className="flex-1 h-2 rounded-full bg-popover overflow-hidden border border-border/50">
              <div
                className={`h-full rounded-full transition-all duration-300 ${
                  isSelected ? "bg-primary" : "bg-muted-foreground/30"
                }`}
                style={{ width: `${Math.min(100, Math.round((v / top) * 100))}%` }}
              />
            </div>
            <span className={`w-12 text-right font-mono text-xs ${isSelected ? "font-bold text-primary" : "text-muted-foreground"}`}>
              {typeof v === "number" ? `${Math.round(v * 100)}%` : v}
            </span>
          </li>
        )
      })}
    </ul>
  )
}

function StepCard({ trace, stepIndex }: { trace: Trace; stepIndex: number }) {
  const [showPayload, setShowPayload] = useState(false)
  const request = trace.request || {}
  const response = trace.response || {}
  const questions = request.questions || {}
  const answers = response.answers || {}
  const state = request.state || {}
  const hopName = state.current_hop || state.active_framework || state.strategy

  return (
    <div className="rounded-xl border border-border bg-card p-4 space-y-3 transition-all hover:border-primary/40">
      {/* Step Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-border/60 pb-2.5">
        <div className="flex items-center gap-2">
          <span className="flex items-center justify-center w-6 h-6 rounded-full bg-primary/20 text-primary font-mono text-xs font-bold border border-primary/40">
            {stepIndex + 1}
          </span>
          {hopName && (
            <span className="text-xs font-bold text-foreground bg-popover px-2.5 py-0.5 rounded border border-border">
              {hopName}
            </span>
          )}
          <span className="text-xs font-mono text-primary font-medium">
            {trace.iso?.slice(11, 19) || "—"}
          </span>
        </div>
        <div className="flex items-center gap-2 text-xs font-mono text-muted-foreground">
          <span className="bg-popover px-2 py-0.5 rounded border border-border">
            ⏱️ {trace.latencyMs?.toFixed(0) ?? 0} ms
          </span>
          <span className="bg-popover px-2 py-0.5 rounded border border-border">
            🪙 {(trace.tokens ?? 0).toLocaleString()} tok
          </span>
          <button
            type="button"
            className="text-xs text-primary hover:underline ml-2 cursor-pointer"
            onClick={() => setShowPayload((v) => !v)}
          >
            {showPayload ? "Ocultar State" : "Ver State JSON"}
          </button>
        </div>
      </div>

      {/* Expandable State Payload */}
      {showPayload && (
        <div className="p-3 rounded-lg bg-background/90 border border-border/80 space-y-1 text-xs">
          <span className="font-semibold text-muted-foreground">State Completo:</span>
          <pre className="text-[11px] font-mono text-foreground/90 overflow-x-auto max-h-48 p-2 rounded bg-popover/60 border border-border/50">
            {JSON.stringify(state, null, 2)}
          </pre>
        </div>
      )}

      {/* Evaluated Questions & Answers */}
      <div className="space-y-3">
        {Object.entries(questions).map(([qName, q]) => {
          const a = answers[qName]
          return (
            <div key={qName} className="rounded-lg bg-background/60 border border-border/80 p-3 space-y-2">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1.5">
                <div className="flex items-center gap-2">
                  <span className="font-bold text-foreground text-xs">{qName}</span>
                  <span className="text-[10px] font-mono uppercase bg-primary/15 text-primary border border-primary/30 px-1.5 py-0.5 rounded">
                    {q.type}
                  </span>
                </div>
                {a?.confidence !== undefined && (
                  <span className="text-[11px] font-mono text-muted-foreground">
                    Confiança: <strong className="text-emerald-400">{Math.round(a.confidence * 100)}%</strong>
                  </span>
                )}
              </div>

              {q.instructions && (
                <p className="text-xs text-muted-foreground italic leading-relaxed bg-popover/40 p-2 rounded border border-border/40">
                  "{q.instructions}"
                </p>
              )}

              {/* Chosen verdict */}
              {a && (
                <div className="flex flex-wrap items-center gap-2 text-xs pt-0.5">
                  {a.choice && (
                    <span className="font-semibold text-emerald-300 bg-emerald-500/15 border border-emerald-500/30 px-2.5 py-0.5 rounded">
                      ✓ Decisão: {labelFor(a.choice, q.criteria)}
                    </span>
                  )}
                  {a.noul !== undefined && (
                    <span className="font-semibold text-primary bg-primary/15 border border-primary/30 px-2.5 py-0.5 rounded">
                      Noul: {a.noul}
                    </span>
                  )}
                  {a.score !== undefined && (
                    <span className="font-semibold text-amber-300 bg-amber-500/15 border border-amber-500/30 px-2.5 py-0.5 rounded">
                      {scoreLabel(a.score, a.legend)}
                    </span>
                  )}
                </div>
              )}

              {/* Probability Distribution */}
              {a?.probabilities && (
                <div className="pt-1">
                  <span className="text-[11px] font-semibold text-muted-foreground">Distribuição de Probabilidades:</span>
                  <ProbsBar
                    probabilities={a.probabilities}
                    criteria={a.legend || q.criteria}
                    picked={a.choice}
                  />
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

export function TracePanel({ open }: { open?: boolean }) {
  const [traces, setTraces] = useState<Trace[] | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // View state
  const [viewMode, setViewMode] = useState<"sessions" | "chronological">("sessions")
  const [selectedSuite, setSelectedSuite] = useState<string>("ALL")
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null)
  const [searchQuery, setSearchQuery] = useState("")
  const [filterType, setFilterType] = useState<string>("ALL")

  useEffect(() => {
    if (!open || traces) return
    setLoading(true)
    fetch("/jev_traces.jsonl")
      .then((r) => {
        if (!r.ok) throw new Error(`jev_traces.jsonl returned ${r.status}`)
        return r.text()
      })
      .then((text) => {
        const parsed: Trace[] = text
          .split("\n")
          .filter(Boolean)
          .map((line) => {
            try {
              return JSON.parse(line) as Trace
            } catch {
              return null
            }
          })
          .filter((t): t is Trace => t !== null && typeof t === "object")
          .reverse()
        setTraces(parsed)
        setLoading(false)
      })
      .catch((e) => {
        setError(e.message)
        setLoading(false)
      })
  }, [open, traces])

  // Group traces into structured sessions
  const sessions = useMemo(() => {
    if (!traces) return []
    const map = new Map<string, TraceSession>()

    // Process chronological order (oldest to newest for session pipelines)
    const reversed = [...traces].reverse()

    reversed.forEach((t) => {
      const site = t.site || "unknown"
      const state = t.request?.state || {}
      let groupKey = ""
      let siteLabel = ""
      let title = ""
      let scenario = ""

      if (site === "sequential_test") {
        siteLabel = "Teste Sequencial"
        const inc = state.incident || {}
        title = inc.title || "Incidente Sequencial"
        groupKey = `seq:${title}`
        scenario = inc.scenario || ""
      } else if (site === "orchestrator") {
        siteLabel = "Orquestrador"
        const goal = state.user_goal
        title = goal ? `Orquestrador: ${goal.slice(0, 55)}…` : "Orquestrador de Travessia"
        groupKey = `orch:${goal || "default"}`
        scenario = goal || ""
      } else if (site === "attack_tree") {
        siteLabel = "Árvore de Ataque"
        const goal = state.adversary_goal
        title = goal ? `Árvore de Ataque: ${goal}` : "Decomposição em Árvore de Ataque"
        groupKey = `at:${goal || "default"}`
        scenario = goal || ""
      } else {
        siteLabel = "Outro Módulo"
        title = `Sessão ${site}`
        groupKey = `other:${site}`
      }

      if (!map.has(groupKey)) {
        map.set(groupKey, {
          id: groupKey,
          site,
          siteLabel,
          title,
          scenario,
          calls: [],
          totalTokens: 0,
          totalLatencyMs: 0,
          startedAt: t.iso,
        })
      }

      const s = map.get(groupKey)!
      s.calls.push(t)
      s.totalTokens += t.tokens || 0
      s.totalLatencyMs += t.latencyMs || 0
    })

    return Array.from(map.values())
  }, [traces])

  // Filtered sessions
  const filteredSessions = useMemo(() => {
    if (selectedSuite === "ALL") return sessions
    return sessions.filter((s) => s.site === selectedSuite)
  }, [sessions, selectedSuite])

  // Set default selected session
  useEffect(() => {
    if (filteredSessions.length > 0 && (!selectedSessionId || !filteredSessions.some((s) => s.id === selectedSessionId))) {
      setSelectedSessionId(filteredSessions[0].id)
    }
  }, [filteredSessions, selectedSessionId])

  const activeSession = useMemo(() => {
    return sessions.find((s) => s.id === selectedSessionId) || filteredSessions[0] || null
  }, [sessions, selectedSessionId, filteredSessions])

  // Filtered flat list of calls
  const filteredTraces = useMemo(() => {
    if (!traces) return []
    return traces.filter((t) => {
      // Filter by suite
      if (selectedSuite !== "ALL" && t.site !== selectedSuite) return false

      // Filter by question type
      if (filterType !== "ALL") {
        const qs = t.request?.questions || {}
        const matchesType = Object.values(qs).some((q) => q.type === filterType)
        if (!matchesType) return false
      }

      // Filter by search query
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase()
        const matchId = t.request_id?.toLowerCase().includes(q)
        const matchSite = t.site?.toLowerCase().includes(q)
        const stateStr = JSON.stringify(t.request?.state || "").toLowerCase()
        const ansStr = JSON.stringify(t.response?.answers || "").toLowerCase()
        if (!matchId && !matchSite && !stateStr.includes(q) && !ansStr.includes(q)) {
          return false
        }
      }

      return true
    })
  }, [traces, selectedSuite, filterType, searchQuery])

  if (!open) return null

  const totalTokens = (traces || []).reduce((s, t) => s + (t.tokens || 0), 0)
  const avgLatency = traces?.length
    ? (traces.reduce((s, t) => s + (t.latencyMs || 0), 0) / traces.length).toFixed(0)
    : "0"

  return (
    <div className="space-y-6">
      {/* Top Metric Strip */}
      <MetricStrip
        metrics={[
          { label: "Total de Chamadas", value: String(traces?.length || 0) },
          { label: "Sessões / Incidentes", value: String(sessions.length) },
          { label: "Latência Média", value: `${avgLatency} ms` },
          { label: "Tokens Consumidos", value: totalTokens.toLocaleString() },
          { label: "Modelo Jev", value: "jev-1.13.0" },
        ]}
      />

      {/* View Mode & Filter Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 rounded-xl border border-border bg-card p-3.5">
        {/* View Mode Toggle */}
        <div className="flex items-center gap-1.5 p-1 rounded-lg bg-background border border-border w-fit">
          <button
            type="button"
            className={`px-3 py-1 rounded-md text-xs font-semibold transition-all cursor-pointer ${
              viewMode === "sessions"
                ? "bg-primary text-primary-foreground shadow-sm"
                : "text-muted-foreground hover:text-foreground"
            }`}
            onClick={() => setViewMode("sessions")}
          >
            📂 Por Incidente &amp; Sessão ({sessions.length})
          </button>
          <button
            type="button"
            className={`px-3 py-1 rounded-md text-xs font-semibold transition-all cursor-pointer ${
              viewMode === "chronological"
                ? "bg-primary text-primary-foreground shadow-sm"
                : "text-muted-foreground hover:text-foreground"
            }`}
            onClick={() => setViewMode("chronological")}
          >
            📋 Lista Cronológica ({filteredTraces.length})
          </button>
        </div>

        {/* Suite Category Pills */}
        <div className="flex items-center gap-1.5 flex-wrap">
          <span className="text-xs text-muted-foreground font-medium mr-1">Módulo:</span>
          <button
            type="button"
            className={`px-2.5 py-1 rounded-full text-xs font-medium border cursor-pointer transition-all ${
              selectedSuite === "ALL"
                ? "bg-primary/20 text-primary border-primary font-bold"
                : "bg-popover text-muted-foreground border-border hover:text-foreground"
            }`}
            onClick={() => setSelectedSuite("ALL")}
          >
            Todos ({traces?.length || 0})
          </button>
          <button
            type="button"
            className={`px-2.5 py-1 rounded-full text-xs font-medium border cursor-pointer transition-all ${
              selectedSuite === "sequential_test"
                ? "bg-primary/20 text-primary border-primary font-bold"
                : "bg-popover text-muted-foreground border-border hover:text-foreground"
            }`}
            onClick={() => setSelectedSuite("sequential_test")}
          >
            ⚡ Teste Sequencial (68)
          </button>
          <button
            type="button"
            className={`px-2.5 py-1 rounded-full text-xs font-medium border cursor-pointer transition-all ${
              selectedSuite === "orchestrator"
                ? "bg-primary/20 text-primary border-primary font-bold"
                : "bg-popover text-muted-foreground border-border hover:text-foreground"
            }`}
            onClick={() => setSelectedSuite("orchestrator")}
          >
            🤖 Orquestrador (19)
          </button>
          <button
            type="button"
            className={`px-2.5 py-1 rounded-full text-xs font-medium border cursor-pointer transition-all ${
              selectedSuite === "attack_tree"
                ? "bg-primary/20 text-primary border-primary font-bold"
                : "bg-popover text-muted-foreground border-border hover:text-foreground"
            }`}
            onClick={() => setSelectedSuite("attack_tree")}
          >
            🌳 Árvore de Ataque (6)
          </button>
        </div>
      </div>

      {loading && <p className="text-sm text-muted-foreground animate-pulse p-4">A carregar registos…</p>}

      {error && (
        <div className="rounded-xl border border-destructive/40 bg-destructive/10 p-4 text-xs text-foreground space-y-1">
          <p className="font-bold text-destructive">Erro ao ler traces</p>
          <p className="text-muted-foreground">{error}</p>
        </div>
      )}

      {/* MODE 1: GROUPED BY INCIDENT / SESSION (ORGANIZED & INTUITIVE) */}
      {viewMode === "sessions" && !loading && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* Left Column: Sessions List */}
          <div className="lg:col-span-4 rounded-xl border border-border bg-card p-3 space-y-2 max-h-[750px] overflow-y-auto">
            <div className="flex items-center justify-between pb-2 border-b border-border/70 px-1">
              <span className="text-xs font-bold uppercase tracking-wider text-muted-foreground">
                Sessões ({filteredSessions.length})
              </span>
              <span className="text-[11px] text-muted-foreground">Escolha uma sessão</span>
            </div>

            <div className="space-y-1.5">
              {filteredSessions.map((s) => {
                const isSelected = s.id === activeSession?.id
                return (
                  <button
                    key={s.id}
                    type="button"
                    className={`w-full text-left p-3 rounded-lg border transition-all cursor-pointer space-y-1.5 ${
                      isSelected
                        ? "bg-primary/10 border-primary shadow-sm"
                        : "bg-background/60 border-border/70 hover:border-muted-foreground hover:bg-background"
                    }`}
                    onClick={() => setSelectedSessionId(s.id)}
                  >
                    <div className="flex items-center justify-between gap-1">
                      <span className="text-[10px] font-mono font-semibold uppercase px-1.5 py-0.5 rounded bg-popover text-primary border border-border">
                        {s.siteLabel}
                      </span>
                      <span className="text-[11px] font-mono text-muted-foreground">
                        {s.calls.length} {s.calls.length === 1 ? "chamada" : "chamadas"}
                      </span>
                    </div>

                    <h4 className="text-xs font-bold text-foreground line-clamp-2 leading-snug">
                      {s.title}
                    </h4>

                    <div className="flex items-center justify-between text-[11px] text-muted-foreground pt-1 border-t border-border/40 font-mono">
                      <span>⏱️ {Math.round(s.totalLatencyMs)} ms</span>
                      <span>🪙 {s.totalTokens.toLocaleString()} tok</span>
                    </div>
                  </button>
                )
              })}
            </div>
          </div>

          {/* Right Column: Active Session Pipeline & Steps */}
          <div className="lg:col-span-8 space-y-4">
            {activeSession ? (
              <>
                {/* Active Session Overview Header */}
                <div className="rounded-xl border border-border bg-card p-5 space-y-3">
                  <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3 border-b border-border/60 pb-3">
                    <div>
                      <span className="text-[11px] font-mono uppercase text-primary font-bold bg-primary/15 px-2 py-0.5 rounded border border-primary/30">
                        {activeSession.siteLabel}
                      </span>
                      <h3 className="text-lg font-bold text-foreground mt-1.5">
                        {activeSession.title}
                      </h3>
                    </div>
                    <div className="flex items-center gap-2 text-xs font-mono">
                      <span className="rounded-lg bg-popover border border-border px-2.5 py-1 text-foreground">
                        ⏱️ <strong>{Math.round(activeSession.totalLatencyMs)} ms</strong> total
                      </span>
                      <span className="rounded-lg bg-popover border border-border px-2.5 py-1 text-foreground">
                        🔗 <strong>{activeSession.calls.length}</strong> saltos
                      </span>
                    </div>
                  </div>

                  {activeSession.scenario && (
                    <p className="text-xs text-muted-foreground leading-relaxed italic bg-popover/40 p-3 rounded-lg border border-border/50">
                      "{activeSession.scenario}"
                    </p>
                  )}
                </div>

                {/* Step Timeline */}
                <div className="space-y-4">
                  <div className="flex items-center justify-between px-1">
                    <span className="text-xs font-bold uppercase tracking-wider text-primary">
                      Sequência de Chamadas ({activeSession.calls.length} micro-decisões)
                    </span>
                    <span className="text-xs text-muted-foreground">Ordem de execução</span>
                  </div>

                  {activeSession.calls.map((call, idx) => (
                    <StepCard key={call.request_id || idx} trace={call} stepIndex={idx} />
                  ))}
                </div>
              </>
            ) : (
              <div className="p-8 text-center text-sm text-muted-foreground border border-dashed border-border rounded-xl">
                Selecione uma sessão à esquerda para ver a cadeia de micro-decisões.
              </div>
            )}
          </div>
        </div>
      )}

      {/* MODE 2: CHRONOLOGICAL SEARCHABLE LIST (FLAT LOG AUDIT) */}
      {viewMode === "chronological" && !loading && (
        <div className="space-y-4">
          {/* Search & Filter Bar */}
          <div className="flex flex-col sm:flex-row sm:items-center gap-3">
            <input
              type="text"
              className="flex-1 rounded-lg border border-border bg-card px-3.5 py-2 text-xs text-foreground placeholder:text-muted-foreground outline-none"
              placeholder="Pesquisar por nó (ex: CWE-285, T1078), pergunta, ID ou termo..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
            <div className="flex items-center gap-2">
              <span className="text-xs text-muted-foreground">Tipo de Questão:</span>
              <select
                className="rounded-lg border border-border bg-card px-2.5 py-1.5 text-xs text-foreground outline-none cursor-pointer"
                value={filterType}
                onChange={(e) => setFilterType(e.target.value)}
              >
                <option value="ALL">Todos os Tipos</option>
                <option value="choice">Choice (Seleção)</option>
                <option value="score">Score (Avaliação)</option>
                <option value="noul">Noul (Booleano)</option>
              </select>
            </div>
          </div>

          <div className="space-y-3">
            {filteredTraces.length === 0 ? (
              <p className="text-xs text-muted-foreground p-4 text-center border border-dashed border-border rounded-xl">
                Nenhuma chamada encontrada com os filtros selecionados.
              </p>
            ) : (
              filteredTraces.map((call, idx) => (
                <StepCard key={call.request_id || idx} trace={call} stepIndex={idx} />
              ))
            )}
          </div>
        </div>
      )}
    </div>
  )
}
