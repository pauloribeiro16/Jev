import type { Framework, NodeKind } from "@/lib/types"

export const COLOR_OF: Record<Framework, string> = {
  CWE: "#0072b2",
  CAPEC: "#e69f00",
  "ATT&CK": "#d55e00",
  D3FEND: "#009e73",
  ATLAS: "#cc79a7",
}

/** Side count per framework; colourblind users get the shape as the second channel. */
export const SIDES: Record<Framework, number> = { CWE: 24, CAPEC: 4, "ATT&CK": 3, D3FEND: 4, ATLAS: 6 }

export const colorOf = (fw: string) => COLOR_OF[fw as Framework] ?? "#64748B"
export const sidesOf = (fw: string) => SIDES[fw as Framework] ?? 24
export { KIND_OF } from "@/lib/types"
export type { NodeKind }
