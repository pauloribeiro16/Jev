import { TracePanel } from "@/components/trace-panel"

export default function TracePage() {
  return (
    <div className="space-y-4 p-6">
      <header>
        <h1 className="text-xl font-semibold">Trace Jev</h1>
        <p className="text-sm text-muted-foreground">
          Cada chamada registada pela guarda: o state e as perguntas enviadas, as respostas com as
          distribuições de probabilidade.
        </p>
      </header>
      <TracePanel open />
    </div>
  )
}
