import { cn } from "@/lib/utils"

export type Metric = {
  label: string
  value: string
  hint?: string
}

const numberFormat = new Intl.NumberFormat("pt-PT")

export function formatNumber(value: number): string {
  return numberFormat.format(value)
}

export function formatSeconds(seconds: number): string {
  // Arredonda-se ao segundo. Os valores que chegam do backend já vêm
  // arredondados, mas uma média por chamada não — e 35,575 s aparecia na
  // página como "35.575245110639855 s".
  if (seconds < 90) return `${Math.round(seconds)} s`
  const minutes = Math.round(seconds / 60)
  if (minutes < 90) return `${minutes} min`
  // pt-PT usa vírgula decimal
  return `${(minutes / 60).toFixed(1).replace(".", ",")} h`
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} kB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

type Props = {
  metrics: Metric[]
  className?: string
}

export function MetricStrip({ metrics, className }: Props) {
  return (
    <dl className={cn("grid gap-3 sm:grid-cols-2 lg:grid-cols-4", className)}>
      {metrics.map((metric) => (
        <div key={metric.label} className="rounded-lg border bg-card px-3 py-2">
          <dt className="text-xs uppercase tracking-wide text-muted-foreground">
            {metric.label}
          </dt>
          <dd className="mt-0.5 font-mono text-lg font-semibold">{metric.value}</dd>
          {metric.hint ? (
            <p className="mt-0.5 text-xs text-muted-foreground">{metric.hint}</p>
          ) : null}
        </div>
      ))}
    </dl>
  )
}
