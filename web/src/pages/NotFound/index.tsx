import { Link } from "react-router"
import { buttonVariants } from "@/components/ui/button"
import { RouteEnum } from "@/config/constants"

export default function NotFound() {
  return (
    <div className="grid h-full place-items-center p-6">
      <div className="space-y-3 text-center">
        <h1 className="font-mono text-2xl font-semibold">404</h1>
        <p className="text-sm text-muted-foreground">Esta página não existe.</p>
        <Link to={RouteEnum.GRAPH} className={buttonVariants({ variant: "outline" })}>
          Voltar ao grafo
        </Link>
      </div>
    </div>
  )
}
