import { cn } from "@/lib/utils"
import { Loader2 } from "lucide-react"

interface Props {
  className?: string
}

export const LoadingSpinner = (props: Props) => {
  const { className } = props
  return (
    <div className="flex justify-center items-center h-full">
      <Loader2
        className={cn(
          "w-12 h-12 animate-spin *:stroke-accent-primary",
          className,
        )}
      />
    </div>
  )
}
