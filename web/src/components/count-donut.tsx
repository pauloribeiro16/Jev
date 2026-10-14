import { Pie, PieChart } from "recharts"

import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart"
import { cn } from "@/lib/utils"

type Props = {
  title: string
  hint?: string
  /** Contagem por categoria, ex.: métodos de verificação da Fase 2. */
  data: Record<string, number>
  className?: string
}

const COLORS = 5

/**
 * Donut de uma distribuição discreta — o total vive no centro, a legenda tem
 * contagens reais. Mesmos tokens --chart-* do resto dos gráficos.
 */
export function CountDonut({ title, hint, data, className }: Props) {
  const entries = Object.entries(data).filter(([, count]) => count > 0)
  if (entries.length === 0) return null
  const total = entries.reduce((sum, [, count]) => sum + count, 0)

  const config = Object.fromEntries(
    entries.map(([key], index) => [
      key,
      { label: key, color: `var(--chart-${(index % COLORS) + 1})` },
    ]),
  ) satisfies ChartConfig

  const chartData = entries.map(([name, count], index) => ({
    name,
    count,
    fill: `var(--chart-${(index % COLORS) + 1})`,
  }))

  return (
    <section className={cn("space-y-2 rounded-xl border bg-card p-4", className)}>
      <header>
        <h2 className="text-sm font-semibold">{title}</h2>
        {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
      </header>
      <div className="relative">
        <ChartContainer config={config} className="mx-auto aspect-square max-h-44">
          <PieChart>
            <ChartTooltip cursor={false} content={<ChartTooltipContent hideLabel />} />
            <Pie
              data={chartData}
              dataKey="count"
              nameKey="name"
              innerRadius={52}
              strokeWidth={4}
            />
          </PieChart>
        </ChartContainer>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-mono text-xl font-semibold tabular-nums">{total}</span>
          <span className="text-[10px] uppercase tracking-wide text-muted-foreground">
            total
          </span>
        </div>
      </div>
      <ul className="space-y-1">
        {entries.map(([name, count], index) => (
          <li key={name} className="flex items-center gap-2 text-xs text-muted-foreground">
            <span
              aria-hidden
              className={cn("size-2 rounded-full")}
              style={{ background: `var(--chart-${(index % COLORS) + 1})` }}
            />
            {name}
            <span className="ml-auto font-mono">{count}</span>
          </li>
        ))}
      </ul>
    </section>
  )
}
