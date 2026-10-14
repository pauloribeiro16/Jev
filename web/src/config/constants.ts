export const BUDGETS = [50, 100, 300] as const

/** Default node budget rendered at once; searching or expanding overrides it. */
export const DEFAULT_BUDGET = 100

/** Hit tolerance in SCREEN px. 14px radius clears WCAG 2.2 SC 2.5.8 (24px). */
export const HIT_PX = 14

/** Paths only via this enum — no hand-written paths in components (template rule). */
export const RouteEnum = {
  GRAPH: "/",
  TRACE: "/trace",
  DATA: "/dados",
  DECISION_CHAIN: "/cadeia",
  HOW_IT_WORKS: "/como-funciona",
  NOT_FOUND: "/404",
} as const
