// @ts-nocheck — 22 KB of data-shaped component authored outside this migration.
// Type it when it is wired into the app; do not silently let it look checked.
import { useEffect, useState, useMemo } from 'react'

const FRAMEWORK_COLORS = {
  CWE: 'var(--cwe)',
  CAPEC: 'var(--capec)',
  'ATT&CK': 'var(--attack)',
  ATTACK: 'var(--attack)',
  D3FEND: 'var(--d3fend)',
  ATLAS: 'var(--atlas)',
}

export default function DecisionChainView({ open, onClose, onPickNode }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [selectedCaseId, setSelectedCaseId] = useState(null)
  const [selectedStepIdx, setSelectedStepIdx] = useState(0)
  const [selectedNodeId, setSelectedNodeId] = useState(null)
  const [activeTab, setActiveTab] = useState('both') // 'both', 'jev', 'official'
  const [showScenario, setShowScenario] = useState(false)

  useEffect(() => {
    if (!open) return
    setLoading(true)
    fetch('/test_runs.json')
      .then((res) => {
        if (!res.ok) throw new Error(`Status ${res.status}: test_runs.json não encontrado`)
        return res.json()
      })
      .then((json) => {
        setData(json)
        if (json.cases?.length > 0 && !selectedCaseId) {
          setSelectedCaseId(json.cases[0].id)
          const firstStep = json.cases[0].steps?.[0]
          setSelectedNodeId(firstStep?.selected_id)
        }
        setLoading(false)
        setError(null)
      })
      .catch((err) => {
        setError(err.message)
        setLoading(false)
      })
  }, [open])

  // Vulnerability families filtering
  const [selectedFamily, setSelectedFamily] = useState('ALL')

  // Filtered cases based on selected family
  const filteredCases = useMemo(() => {
    if (!data?.cases) return []
    if (selectedFamily === 'ALL') return data.cases
    return data.cases.filter((c) => (c.vulnerability_family || c.category) === selectedFamily)
  }, [data, selectedFamily])

  // Active case lookup
  const activeCase = useMemo(() => {
    if (!filteredCases || filteredCases.length === 0) {
      return data?.cases?.[0] || null
    }
    const found = filteredCases.find((c) => c.id === selectedCaseId)
    return found || filteredCases[0]
  }, [data, filteredCases, selectedCaseId])

  // Group cases by vulnerability family
  const casesByFamily = useMemo(() => {
    if (!data?.cases) return {}
    const map = {}
    for (const c of data.cases) {
      const fam = c.vulnerability_family || c.category || 'Outras Vulnerabilidades'
      if (!map[fam]) map[fam] = []
      map[fam].push(c)
    }
    return map
  }, [data])

  const steps = activeCase?.steps || []
  const activeStep = steps[selectedStepIdx] || steps[0]

  // Update selectedNodeId when step changes if not set
  useEffect(() => {
    if (activeStep && (!selectedNodeId || !activeStep.candidates?.[selectedNodeId])) {
      setSelectedNodeId(activeStep.selected_id)
    }
  }, [activeStep, selectedNodeId])

  // Selected candidate details
  const selectedCandidate = useMemo(() => {
    if (!activeStep?.candidates || !selectedNodeId) return null
    return activeStep.candidates[selectedNodeId] || null
  }, [activeStep, selectedNodeId])

  const handleSelectCase = (caseId) => {
    setSelectedCaseId(caseId)
    setSelectedStepIdx(0)
    const newCase = data?.cases?.find((c) => c.id === caseId)
    const firstStep = newCase?.steps?.[0]
    if (firstStep) {
      setSelectedNodeId(firstStep.selected_id)
      if (onPickNode) onPickNode(firstStep.selected_id)
    }
  }

  const handleSelectFamily = (fam) => {
    setSelectedFamily(fam)
    setSelectedStepIdx(0)
    const targetCases = fam === 'ALL' ? data?.cases : data?.cases?.filter((c) => (c.vulnerability_family || c.category) === fam)
    if (targetCases && targetCases.length > 0) {
      setSelectedCaseId(targetCases[0].id)
      const firstStep = targetCases[0].steps?.[0]
      if (firstStep) {
        setSelectedNodeId(firstStep.selected_id)
        if (onPickNode) onPickNode(firstStep.selected_id)
      }
    }
  }

  const handleSelectNode = (stepIdx, nodeId) => {
    setSelectedStepIdx(stepIdx)
    setSelectedNodeId(nodeId)
    if (onPickNode && nodeId) {
      onPickNode(nodeId)
    }
  }

  if (!open) return null

  return (
    <div className="decision-view-wrapper" aria-label="Cadeia de Decisão Jev">
      <div className="decision-view">
        {/* Top Header */}
        <header className="decision-view__header">
          <div className="decision-view__title-group">
            <div className="decision-view__badge-row">
              <span className="decision-view__badge">⚡ Teste Sequencial Jev</span>
              {data?.cases?.length && (
                <span className="decision-view__count-badge">{data.cases.length} cenários avaliados</span>
              )}
            </div>
            <h2>Taxonomia & Árvore de Decisão por Caso</h2>
            <p className="decision-view__subtitle">
              Navegação ontológica causal e organizada por <strong>família de vulnerabilidade</strong> e <strong>caso de teste</strong>.
            </p>
          </div>
          {onClose && (
            <button type="button" className="iconbtn" onClick={onClose} aria-label="Fechar">
              ✕
            </button>
          )}
        </header>

        {loading && <p className="empty">A carregar cenários de teste…</p>}

        {error && (
          <div className="decision-view__empty">
            <p>Nenhum resultado de teste encontrado.</p>
            <p className="empty">
              Executa a suite com: <code>.venv/bin/python3 scripts/run_sequential_test.py</code>
            </p>
          </div>
        )}

        {activeCase && (
          <div className="decision-view__content">
            {/* Vulnerability Family Filter Pills */}
            <div className="family-filter-bar">
              <span className="family-filter-bar__label">🛡️ Tipo de Vulnerabilidade:</span>
              <div className="family-filter-bar__pills">
                <button
                  type="button"
                  className={`family-pill ${selectedFamily === 'ALL' ? 'is-active' : ''}`}
                  onClick={() => handleSelectFamily('ALL')}
                >
                  Todos ({data?.cases?.length || 0})
                </button>
                {Object.entries(casesByFamily).map(([famName, famCases]) => (
                  <button
                    key={famName}
                    type="button"
                    className={`family-pill ${selectedFamily === famName ? 'is-active' : ''}`}
                    onClick={() => handleSelectFamily(famName)}
                  >
                    {famName} ({famCases.length})
                  </button>
                ))}
              </div>
            </div>

            {/* Scenario Selector & Grouping */}
            <div className="scenario-bar">
              <label htmlFor="scenario-select" className="scenario-bar__label">
                📁 Caso de Estudo / Incidente:
              </label>
              <select
                id="scenario-select"
                className="scenario-bar__select"
                value={activeCase.id}
                onChange={(e) => handleSelectCase(e.target.value)}
              >
                {Object.entries(casesByFamily).map(([famName, caseList]) => {
                  const filtered = selectedFamily === 'ALL' ? caseList : caseList.filter((c) => (c.vulnerability_family || c.category) === selectedFamily)
                  if (filtered.length === 0) return null
                  return (
                    <optgroup key={famName} label={`🛡️ ${famName}`}>
                      {filtered.map((c) => (
                        <option key={c.id} value={c.id}>
                          {c.vulnerability_type ? `[${c.vulnerability_type}] ` : ''}{c.title}
                        </option>
                      ))}
                    </optgroup>
                  )
                })}
              </select>
            </div>

            {/* Case Overview Card */}
            <div className="case-card">
              <div className="case-card__header">
                <div>
                  <div className="case-card__tag-row">
                    <span className="case-card__tag">{activeCase.vulnerability_family || activeCase.category}</span>
                    {activeCase.vulnerability_type && (
                      <span className="case-card__subtag">{activeCase.vulnerability_type}</span>
                    )}
                  </div>
                  <h3 className="case-card__title">{activeCase.title}</h3>
                </div>
                <div className="case-card__stats">
                  <span className="stat-pill">
                    ⏱️ <strong>{activeCase.total_latency_ms} ms</strong> cadeia completa
                  </span>
                  <span className="stat-pill">
                    🔗 <strong>{steps.length}</strong> saltos ontológicos
                  </span>
                  <button
                    type="button"
                    className="linkbtn case-card__toggle"
                    onClick={() => setShowScenario((v) => !v)}
                  >
                    {showScenario ? 'Ocultar contexto' : 'Ver contexto e arquitetura'}
                  </button>
                </div>
              </div>

              {showScenario && (
                <div className="case-card__details">
                  <div className="detail-row">
                    <strong>Incidente:</strong>
                    <span>{activeCase.scenario}</span>
                  </div>
                  <div className="detail-row">
                    <strong>Ativo Alvo:</strong>
                    <span>{activeCase.target_asset}</span>
                  </div>
                  <div className="detail-row">
                    <strong>Arquitetura:</strong>
                    <span>{activeCase.architecture}</span>
                  </div>
                </div>
              )}
            </div>

            {/* Visual Decision Tree Graph (Caminho Percorrido vs Opções Descartadas) */}
            <div className="decision-tree-panel">
              <div className="decision-tree-panel__head">
                <span className="section-label">Subgrafo da Árvore de Decisão:</span>
                <span className="decision-tree-panel__hint">
                  Nós acesos = <strong>caminho escolhido</strong> · Nós a tracejado ={' '}
                  <strong>opções descartadas</strong>
                </span>
              </div>

              <div className="decision-tree">
                {steps.map((st, stepIdx) => {
                  const fwColor = FRAMEWORK_COLORS[st.framework] || 'var(--focus)'
                  const candList = Object.values(st.candidates || {}).sort(
                    (a, b) => (b.is_chosen ? 1 : 0) - (a.is_chosen ? 1 : 0) || b.probability - a.probability
                  )

                  return (
                    <div key={st.step_index} className="tree-column">
                      <div className="tree-column__header" style={{ borderBottomColor: fwColor }}>
                        <span className="tree-column__badge" style={{ backgroundColor: fwColor }}>
                          {st.framework}
                        </span>
                        <span className="tree-column__step">Salto {stepIdx + 1}</span>
                      </div>

                      <div className="tree-column__nodes">
                        {candList.map((cand) => {
                          const isWinner = cand.is_chosen
                          const isSelected = cand.id === selectedNodeId && stepIdx === selectedStepIdx
                          const probPct = Math.round((cand.probability || 0) * 100)

                          return (
                            <button
                              key={cand.id}
                              type="button"
                              className={`tree-node ${isWinner ? 'is-winner' : 'is-pruned'} ${
                                isSelected ? 'is-selected' : ''
                              }`}
                              style={{
                                '--fw-color': fwColor,
                              }}
                              onClick={() => handleSelectNode(stepIdx, cand.id)}
                            >
                              <div className="tree-node__top">
                                <strong className="tree-node__id">{cand.id}</strong>
                                <span className={`tree-node__status ${isWinner ? 'is-winner-tag' : ''}`}>
                                  {isWinner ? `✓ ${probPct}%` : `${probPct}%`}
                                </span>
                              </div>
                              <span className="tree-node__name">{cand.name}</span>
                            </button>
                          )
                        })}
                      </div>

                      {stepIdx < steps.length - 1 && (
                        <div className="tree-column__connector" aria-hidden="true">
                          <span className="connector-arrow">➔</span>
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>

            {/* Dual Inspector Panel (Decisão Jev + Documentação Oficial MITRE) */}
            {selectedCandidate && (
              <div className="dual-inspector">
                {/* Inspector Header with Node Overview */}
                <div className="dual-inspector__head">
                  <div className="dual-inspector__badge-row">
                    <span
                      className="badge"
                      style={{
                        backgroundColor: FRAMEWORK_COLORS[selectedCandidate.framework],
                        color: '#0b0f17',
                      }}
                    >
                      {selectedCandidate.framework}
                    </span>
                    <span
                      className={`status-pill ${
                        selectedCandidate.is_chosen ? 'status-pill--chosen' : 'status-pill--pruned'
                      }`}
                    >
                      {selectedCandidate.is_chosen ? '✓ Escolhido pelo Jev' : '✕ Opção Descartada'}
                    </span>
                    <span className="stat-pill">
                      Probabilidade: <strong>{Math.round(selectedCandidate.probability * 100)}%</strong>
                    </span>
                  </div>

                  <h3 className="dual-inspector__title">
                    {selectedCandidate.id} — {selectedCandidate.name}
                  </h3>

                  <div className="dual-inspector__actions">
                    <button
                      type="button"
                      className="linkbtn step-card__focusbtn"
                      onClick={() => onPickNode && onPickNode(selectedCandidate.id)}
                    >
                      🎯 Centrar no Grafo Geral
                    </button>
                    {selectedCandidate.official_url && (
                      <a
                        href={selectedCandidate.official_url}
                        target="_blank"
                        rel="noreferrer"
                        className="linkbtn dual-inspector__link"
                      >
                        ↗ Documentação Oficial {selectedCandidate.framework}
                      </a>
                    )}
                  </div>
                </div>

                {/* Section Toggle */}
                <div className="dual-inspector__tabs">
                  <button
                    type="button"
                    className={`tab-btn ${activeTab === 'both' ? 'is-active' : ''}`}
                    onClick={() => setActiveTab('both')}
                  >
                    Visão Completa
                  </button>
                  <button
                    type="button"
                    className={`tab-btn ${activeTab === 'jev' ? 'is-active' : ''}`}
                    onClick={() => setActiveTab('jev')}
                  >
                    ⚡ Julgamento do Jev
                  </button>
                  <button
                    type="button"
                    className={`tab-btn ${activeTab === 'official' ? 'is-active' : ''}`}
                    onClick={() => setActiveTab('official')}
                  >
                    📖 Catálogo Oficial MITRE
                  </button>
                </div>

                {/* Section 1: Jev Decision Analysis */}
                {(activeTab === 'both' || activeTab === 'jev') && (
                  <div className="inspector-box inspector-box--jev">
                    <div className="inspector-box__title">
                      <span>⚡ Decisão Estruturada do Jev (System 1)</span>
                      <span className="stat-pill">Salto {selectedStepIdx + 1} de {steps.length}</span>
                    </div>

                    <div className="inspector-field">
                      <span className="field-label">Instrução / Pergunta ao Jev:</span>
                      <p className="inspector-field__quote">"{activeStep.question}"</p>
                    </div>

                    <div className="inspector-field">
                      <span className="field-label">O que o Jev avaliou nesta opção:</span>
                      <p className="inspector-field__text">
                        {selectedCandidate.prompt_summary || selectedCandidate.full_description?.slice(0, 200)}
                      </p>
                    </div>

                    {/* Verdict chips for this step if winner */}
                    {selectedCandidate.is_chosen && (activeStep.noul_label || activeStep.score_label) && (
                      <div className="step-card__verdicts">
                        {activeStep.noul_label && (
                          <div className="verdict-chip verdict-chip--noul">
                            <span className="verdict-chip__type">Noul</span>
                            <span className="verdict-chip__text">{activeStep.noul_label}</span>
                          </div>
                        )}
                        {activeStep.score_label && (
                          <div className="verdict-chip verdict-chip--score">
                            <span className="verdict-chip__type">Score {activeStep.score_value}</span>
                            <span className="verdict-chip__text">{activeStep.score_label}</span>
                          </div>
                        )}
                      </div>
                    )}

                    {/* Probabilities Comparison Bar */}
                    <div className="inspector-field">
                      <span className="field-label">Comparação de Probabilidades no Salto:</span>
                      <ul className="prob-list">
                        {Object.values(activeStep.candidates || {})
                          .sort((a, b) => b.probability - a.probability)
                          .map((cand) => (
                            <li
                              key={cand.id}
                              className={`prob-list__item ${cand.id === selectedCandidate.id ? 'is-highlight' : ''}`}
                              onClick={() => handleSelectNode(selectedStepIdx, cand.id)}
                            >
                              <div className="prob-list__info">
                                <span className="prob-list__id">{cand.id}</span>
                                <span className="prob-list__title">{cand.name}</span>
                              </div>
                              <div className="prob-list__bar-col">
                                <div className="prob-list__track">
                                  <div
                                    className="prob-list__fill"
                                    style={{
                                      width: `${Math.round(cand.probability * 100)}%`,
                                      backgroundColor: cand.is_chosen
                                        ? FRAMEWORK_COLORS[cand.framework]
                                        : 'var(--text-faint)',
                                    }}
                                  />
                                </div>
                              </div>
                              <span className="prob-list__num">
                                {Math.round(cand.probability * 100)}%
                              </span>
                            </li>
                          ))}
                      </ul>
                    </div>
                  </div>
                )}

                {/* Section 2: Official MITRE Catalog Information */}
                {(activeTab === 'both' || activeTab === 'official') && (
                  <div className="inspector-box inspector-box--official">
                    <div className="inspector-box__title">
                      <span>📖 Documentação Oficial ({selectedCandidate.framework})</span>
                      {selectedCandidate.category && (
                        <span className="stat-pill">{selectedCandidate.category}</span>
                      )}
                    </div>

                    <div className="inspector-field">
                      <span className="field-label">Descrição Oficial Completa:</span>
                      <div className="official-description">
                        {selectedCandidate.full_description || 'Sem descrição oficial registada.'}
                      </div>
                    </div>

                    <div className="inspector-field">
                      <span className="field-label">Referência Externa:</span>
                      <a
                        href={selectedCandidate.official_url}
                        target="_blank"
                        rel="noreferrer"
                        className="official-link-box"
                      >
                        <span className="official-link-box__title">
                          Catálogo Oficial MITRE / {selectedCandidate.framework}
                        </span>
                        <span className="official-link-box__url">
                          {selectedCandidate.official_url}
                        </span>
                      </a>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
