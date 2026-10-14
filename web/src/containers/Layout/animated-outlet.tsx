import { AnimatePresence, motion, useReducedMotion } from "motion/react"
import { Outlet, useLocation } from "react-router"

/**
 * Outlet com transição de página: fade/slide curto ao trocar de rota. Só
 * transform/opacity (GPU-friendly) e desligado quando o sistema pede
 * `prefers-reduced-motion`. O `mode="wait"` evita duas páginas em DOM ao
 * mesmo tempo; `initial={false}` não anima o primeiro carregamento.
 */
export function AnimatedOutlet() {
  const location = useLocation()
  const reduceMotion = useReducedMotion()

  return (
    <AnimatePresence mode="wait" initial={false}>
      <motion.div
        key={location.pathname}
        className="h-full w-full"
        initial={reduceMotion ? { opacity: 1 } : { opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        exit={reduceMotion ? { opacity: 1 } : { opacity: 0, y: -6 }}
        transition={{ duration: 0.18, ease: "easeOut" }}
      >
        <Outlet />
      </motion.div>
    </AnimatePresence>
  )
}
