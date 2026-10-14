import { useState } from "react"
import DecisionChainView from "@/components/decision-chain-view"
import { RobustnessView } from "@/components/robustness-view"
import { BeamSearchView } from "@/components/beam-search-view"
import { PruningView } from "@/components/pruning-view"

type Tab = "tree" | "robustness" | "beam" | "pruning"

export default function DecisionChainPage() {
  const [activeTab, setActiveTab] = useState<Tab>("pruning")

  return (
    <div className="space-y-6 p-6">
      <header className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border/60 pb-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-foreground">
            Inferência & Árvores de Decisão Jev
          </h1>
          <p className="text-sm text-muted-foreground mt-0.5">
            Exploração ontológica sequencial completa (CWE → CAPEC → ATT&amp;CK/ATLAS → D3FEND), testes de robustez, beam search e poda de becos sem saída.
          </p>
        </div>

        {/* Navigation Tabs */}
        <div className="flex items-center gap-1.5 p-1 rounded-xl bg-card border border-border flex-wrap">
          <button
            type="button"
            className={`px-3.5 py-1.5 rounded-lg text-xs font-medium transition-all ${
              activeTab === "pruning"
                ? "bg-primary text-primary-foreground shadow-sm font-bold"
                : "text-muted-foreground hover:text-foreground hover:bg-popover"
            }`}
            onClick={() => setActiveTab("pruning")}
          >
            ✂️ Poda &amp; Becos Sem Saída
          </button>
          <button
            type="button"
            className={`px-3.5 py-1.5 rounded-lg text-xs font-medium transition-all ${
              activeTab === "tree"
                ? "bg-primary text-primary-foreground shadow-sm"
                : "text-muted-foreground hover:text-foreground hover:bg-popover"
            }`}
            onClick={() => setActiveTab("tree")}
          >
            ⚡ Árvore de Decisão (6 Casos)
          </button>
          <button
            type="button"
            className={`px-3.5 py-1.5 rounded-lg text-xs font-medium transition-all ${
              activeTab === "robustness"
                ? "bg-primary text-primary-foreground shadow-sm"
                : "text-muted-foreground hover:text-foreground hover:bg-popover"
            }`}
            onClick={() => setActiveTab("robustness")}
          >
            🛡️ Robustez &amp; Distratores
          </button>
          <button
            type="button"
            className={`px-3.5 py-1.5 rounded-lg text-xs font-medium transition-all ${
              activeTab === "beam"
                ? "bg-primary text-primary-foreground shadow-sm"
                : "text-muted-foreground hover:text-foreground hover:bg-popover"
            }`}
            onClick={() => setActiveTab("beam")}
          >
            🧭 Beam Search (K=2)
          </button>
        </div>
      </header>

      {/* Main Content Area */}
      <div>
        {activeTab === "pruning" && <PruningView />}
        {activeTab === "tree" && (
          <DecisionChainView open onClose={undefined} onPickNode={undefined} />
        )}
        {activeTab === "robustness" && <RobustnessView />}
        {activeTab === "beam" && <BeamSearchView />}
      </div>
    </div>
  )
}
