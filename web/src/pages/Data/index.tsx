import { useGraphData, useProvenanceData } from "@/services/graph-data"
import { MetricStrip } from "@/components/metric-strip"
import { CountDonut } from "@/components/count-donut"
import { DataTable, type Column } from "@/components/data-table"
import { QueryState } from "@/components/query-state"
import type { DatasetRevision } from "@/lib/types"

const columns: Column<DatasetRevision>[] = [
  { key: "key", header: "Source", render: (r) => r.key },
  { key: "filename", header: "Ficheiro", render: (r) => r.filename },
  { key: "sha256", header: "sha256", mono: true, render: (r) => r.sha256.slice(0, 12) },
  {
    key: "fetchedAt",
    header: "Fetch",
    render: (r) => r.fetchedAt.replace("T", " ").slice(0, 16),
  },
]

export default function DataPage() {
  const graph = useGraphData()
  const prov = useProvenanceData()
  const revisions: DatasetRevision[] = prov.data?.datasets ?? []

  return (
    <div className="space-y-4 p-6">
      <header>
        <h1 className="text-xl font-semibold">Dados</h1>
        <p className="text-sm text-muted-foreground">
          As ontologias oficiais por trás do grafo, com a revisão exacta (sha256) de cada fonte.
        </p>
      </header>

      <QueryState isLoading={graph.isLoading || prov.isLoading} error={graph.error}>
        <div className="space-y-4">
          <MetricStrip
            metrics={[
              { label: "Nós", value: String(graph.data?.totalNodes ?? 0) },
              { label: "Arestas", value: String(graph.data?.edges.length ?? 0) },
              { label: "Datasets", value: String(revisions.length) },
              {
                label: "Gerado em",
                value: `${Math.round(graph.data?.provenance?.generationTimeMs ?? 0)} ms`,
              },
            ]}
          />

          <div className="max-w-sm">
            <CountDonut title="Entidades por framework" data={graph.data?.provenance?.frameworks ?? {}} />
          </div>

          <section className="space-y-2">
            <h2 className="text-sm font-semibold">Revisões dos datasets</h2>
            <DataTable columns={columns} rows={revisions} rowKey={(r) => r.key} />
          </section>

          {prov.data?.generatedAt && (
            <p className="text-xs text-muted-foreground">
              Grafo exportado em {prov.data.generatedAt}.
            </p>
          )}
        </div>
      </QueryState>
    </div>
  )
}
