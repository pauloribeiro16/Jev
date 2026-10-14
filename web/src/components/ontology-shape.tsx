import { colorOf, sidesOf } from "@/lib/palette"

/** Mirrors the canvas glyph so the shape encoding is decodable, not guesswork. */
export function Shape({ fw, size = 12 }: { fw: string; size?: number }) {
  const s = sidesOf(fw)
  const pts = Array.from({ length: s }, (_, i) => {
    const a = (Math.PI * 2 * i) / s - Math.PI / 2
    return `${(5 + Math.cos(a) * 4).toFixed(2)},${(5 + Math.sin(a) * 4).toFixed(2)}`
  }).join(" ")
  return (
    <svg width={size} height={size} viewBox="0 0 10 10" aria-hidden className="shrink-0">
      <polygon points={pts} fill={colorOf(fw)} />
    </svg>
  )
}
