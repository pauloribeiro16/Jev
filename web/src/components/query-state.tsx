import { LoadingSpinner } from "@/components/ui/spinner"
import type { ReactNode } from "react"

type Props = {
  isLoading: boolean
  error: unknown
  children?: ReactNode
  empty?: boolean
  emptyMessage?: string
}

// Um sítio só para os três estados de uma query — evita repetir a mesma
// boilerplate em cada página e garante a mesma copy em todo o inspector.
export function QueryState({ isLoading, error, children, empty, emptyMessage }: Props) {
  if (isLoading) {
    return (
      <div className="flex items-center gap-3 py-10 text-sm text-muted-foreground">
        <LoadingSpinner />
        A carregar…
      </div>
    )
  }

  if (error) {
    const message = error instanceof Error ? error.message : "Erro desconhecido"
    return (
      <div className="rounded-md border border-red-500/40 bg-red-500/5 p-4 text-sm">
        <p className="font-medium text-red-700 dark:text-red-300">Não foi possível carregar</p>
        <p className="mt-1 font-mono text-xs text-muted-foreground">{message}</p>
      </div>
    )
  }

  if (empty) {
    return (
      <p className="py-6 text-sm text-muted-foreground">{emptyMessage ?? "Nada a mostrar."}</p>
    )
  }

  if (!children) return <p className="py-6 text-sm text-muted-foreground">Nada a mostrar.</p>

  return <>{children}</>
}
