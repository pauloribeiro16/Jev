const STEPS = [
  {
    cmd: "python scripts/fetch_official_data.py",
    what: "Descarrega as 8 ontologias oficiais (CWE, CAPEC, ATT&CK ×3, D3FEND, ATLAS, mappings) para data/official/, arquiva versões anteriores e regista sha256 em data/versions/manifest.jsonl.",
  },
  {
    cmd: "python scripts/export_canonical_graph.py --with-traces",
    what: "Exporta o grafo federado (nós + arestas + proveniência) e os traces do Jev para web/public/, que o site lê em runtime.",
  },
  {
    cmd: "npm run build && npm run preview",
    what: "Compila e serve o site. Os dados não são versionados no git — regenera-os com os dois passos acima.",
  },
]

export default function HowItWorksPage() {
  return (
    <div className="max-w-3xl space-y-4 p-6">
      <header>
        <h1 className="text-xl font-semibold">Como funciona</h1>
        <p className="text-sm text-muted-foreground">
          O site é estático e gratuito a correr: lê os dados exportados do grafo federado. Os
          passos para regenerar tudo:
        </p>
      </header>
      <ol className="space-y-3">
        {STEPS.map((s, i) => (
          <li key={s.cmd} className="space-y-1.5 rounded-lg border bg-card p-4">
            <div className="flex items-baseline gap-3">
              <span className="font-mono text-xs text-muted-foreground">{i + 1}.</span>
              <code className="font-mono text-sm">{s.cmd}</code>
            </div>
            <p className="pl-8 text-sm text-muted-foreground">{s.what}</p>
          </li>
        ))}
      </ol>
      <p className="text-xs text-muted-foreground">
        Chamadas reais ao Jev passam pela guarda de orçamento
        (<code>src/frameworks/jev_budget.py</code>) e ficam registadas no ledger.
      </p>
    </div>
  )
}
