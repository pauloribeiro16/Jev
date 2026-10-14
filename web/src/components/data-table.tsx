import { cn } from "@/lib/utils"
import { Fragment } from "react"

export type Column<T> = {
  key: string
  header: string
  // `mono` para chaves e tokens: números grandes alinham melhor em monoespaçada.
  mono?: boolean
  className?: string
  render: (row: T) => React.ReactNode
}

type Props<T> = {
  columns: Column<T>[]
  rows: T[]
  rowKey: (row: T) => string
  empty?: string
  onRowClick?: (row: T) => void
  /**
   * Linha expansível (progressive disclosure): quando `expandedKey` é a chave da
   * linha, o conteúdo extra renderiza por baixo dela. A página é quem detém o
   * estado — a tabela continua burra.
   */
  expandedKey?: string | null
  renderExpanded?: (row: T) => React.ReactNode
}

export function DataTable<T>({ columns, rows, rowKey, empty, onRowClick, expandedKey, renderExpanded }: Props<T>) {
  if (rows.length === 0) {
    return <p className="text-sm text-muted-foreground py-6">{empty ?? "Nada a mostrar."}</p>
  }

  return (
    <div className="overflow-x-auto rounded-lg border">
      <table className="w-full text-sm">
        <thead className="bg-muted/50">
          <tr>
            {columns.map((column) => (
              <th
                key={column.key}
                className={cn(
                  "whitespace-nowrap px-3 py-2 text-left font-medium text-muted-foreground",
                  column.className,
                )}
              >
                {column.header}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <Fragment key={rowKey(row)}>
              <tr
                onClick={onRowClick ? () => onRowClick(row) : undefined}
                className={cn("border-t", onRowClick && "cursor-pointer hover:bg-muted/40")}
              >
                {columns.map((column) => (
                  <td
                    key={column.key}
                    className={cn("px-3 py-2 align-top", column.mono && "font-mono text-xs", column.className)}
                  >
                    {column.render(row)}
                  </td>
                ))}
              </tr>
              {renderExpanded && expandedKey === rowKey(row) && (
                <tr className="border-t bg-muted/20">
                  <td colSpan={columns.length} className="px-3 py-2">
                    {renderExpanded(row)}
                  </td>
                </tr>
              )}
            </Fragment>
          ))}
        </tbody>
      </table>
    </div>
  )
}
