import { useCallback } from "react"
import { useSearchParams } from "react-router"

/**
 * One query param as controlled state, template-style (?case= deep links).
 * setParams uses replace so back history is not polluted per keystroke.
 */
export function useUrlState(key: string, fallback: string) {
  const [params, setParams] = useSearchParams()

  const value = params.get(key) ?? fallback
  const setValue = useCallback(
    (v: string | null) => {
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev)
          if (v === null || v === "" || v === fallback) next.delete(key)
          else next.set(key, v)
          return next
        },
        { replace: true },
      )
    },
    [key, fallback, setParams],
  )

  return [value, setValue] as const
}
