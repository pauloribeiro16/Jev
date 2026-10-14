import type { Provenance as ProvenanceType } from "@/lib/types"

export function ProvenancePanel({ provenance }: { provenance: ProvenanceType | null }) {
  if (!provenance) return null
  return (
    <div className="mx-auto max-w-[860px] rounded-md border border-line bg-surface p-5">
      <h2 className="mb-2 text-base font-semibold">Dataset revision</h2>
      <p className="mb-4 text-dim">
        Generated {provenance.generatedAt} in {provenance.generationTimeMs} ms, from the official
        ontologies below at exactly these revisions.
      </p>
      <table className="w-full border-collapse text-xs">
        <thead>
          <tr className="text-left text-faint">
            <th className="border-b border-line px-2 py-1.5 font-medium">Source</th>
            <th className="border-b border-line px-2 py-1.5 font-medium">File</th>
            <th className="border-b border-line px-2 py-1.5 font-medium">sha256</th>
            <th className="border-b border-line px-2 py-1.5 font-medium">Fetched</th>
          </tr>
        </thead>
        <tbody>
          {provenance.datasets.map((d) => (
            <tr key={d.key}>
              <td className="border-b border-line/50 px-2 py-1.5">{d.key}</td>
              <td className="border-b border-line/50 px-2 py-1.5">{d.filename}</td>
              <td
                className="border-b border-line/50 px-2 py-1.5 font-mono text-dim"
                title={d.sha256}
              >
                {d.sha256.slice(0, 12)}
              </td>
              <td className="border-b border-line/50 px-2 py-1.5">
                {d.fetchedAt.replace("T", " ").slice(0, 16)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}