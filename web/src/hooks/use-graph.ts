import { useCallback, useEffect, useMemo, useState } from "react"
import { useGraphData, neighboursOf } from "@/services/graph-data"
import { tracePath } from "@/lib/graph"
import { FRAMEWORKS } from "@/lib/types"

export interface UseGraphOptions {
  pathFrom?: string | null
  pathTo?: string | null
}

export function useGraph(options?: UseGraphOptions) {
  const { data: graph = null, error } = useGraphData()
  const [selectedIds, setSelectedIds] = useState<string[]>([])
  const [expanded, setExpanded] = useState<Set<string>>(new Set())
  const [relations, setRelations] = useState<Set<string>>(new Set())
  const [internalPathFrom, setInternalPathFrom] = useState<string | null>(null)
  const [internalPathTo, setInternalPathTo] = useState<string | null>(null)

  const pathFrom = options?.pathFrom !== undefined ? options.pathFrom : internalPathFrom
  const pathTo = options?.pathTo !== undefined ? options.pathTo : internalPathTo
  const setPathFrom = setInternalPathFrom
  const setPathTo = setInternalPathTo

  const allRelations = useMemo(
    () => [...new Set(graph?.edges.map((e) => e.label))].sort(),
    [graph],
  )

  useEffect(() => {
    if (graph && relations.size === 0 && allRelations.length) setRelations(new Set(allRelations))
  }, [graph, allRelations, relations.size])

  const allowedEdges = useMemo(
    () => graph?.edges.filter((e) => relations.has(e.label)) ?? [],
    [graph, relations],
  )

  const pathResult = useMemo(() => {
    if (!graph || !pathFrom || !pathTo) return null
    return tracePath(graph, pathFrom, pathTo, relations)
  }, [graph, pathFrom, pathTo, relations])

  const pathNodes = useMemo(() => {
    return new Set(pathResult?.nodes ?? [])
  }, [pathResult])

  const pathEdges = useMemo(() => {
    if (!graph || !pathResult || pathResult.nodes.length < 2) return new Set<string>()
    const ids = new Set<string>()
    const pathList = pathResult.nodes
    const pairs = new Set<string>()
    for (let i = 0; i < pathList.length - 1; i++) {
      pairs.add(`${pathList[i]}->${pathList[i + 1]}`)
      pairs.add(`${pathList[i + 1]}->${pathList[i]}`)
    }
    for (const e of graph.edges) {
      if (pairs.has(`${e.from}->${e.to}`)) {
        ids.add(e.id)
      }
    }
    return ids
  }, [graph, pathResult])

  const select = useCallback((id: string | null, additive: boolean) => {
    if (!id) {
      setSelectedIds([])
      return
    }
    setSelectedIds((prev) =>
      additive ? (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]) : [id],
    )
  }, [])

  const toggleExpanded = useCallback((id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }, [])

  const toggleRelation = useCallback((rel: string) => {
    setRelations((prev) => {
      const next = new Set(prev)
      if (next.has(rel)) next.delete(rel)
      else next.add(rel)
      return next
    })
  }, [])

  const toggleFramework = useCallback((fw: string) => {
    setEnabledFrameworks((prev) => {
      const next = new Set(prev)
      if (next.has(fw)) next.delete(fw)
      else next.add(fw)
      return next
    })
  }, [])

  const showAllFrameworks = useCallback(() => setEnabledFrameworks(new Set(FRAMEWORKS)), [])
  const clearExpanded = useCallback(() => setExpanded(new Set()), [])

  const [enabledFrameworks, setEnabledFrameworks] = useState<Set<string>>(() => new Set(FRAMEWORKS))

  const neighbours = useCallback(
    (id: string) => (graph ? neighboursOf(graph, id) : []),
    [graph],
  )

  return {
    graph, error,
    selectedIds, select,
    expanded, toggleExpanded,
    relations, toggleRelation, allRelations, allowedEdges,
    pathFrom, setPathFrom, pathTo, setPathTo, pathNodes, pathEdges,
    enabledFrameworks, toggleFramework, showAllFrameworks, clearExpanded,
    neighbours,
  }
}
