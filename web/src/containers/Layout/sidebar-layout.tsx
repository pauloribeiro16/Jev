import { ModeToggle } from "@/components/mode-toggle"
import { SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar"
import { AppSidebar } from "../Sidebar/main-sidebar"
import { AnimatedOutlet } from "./animated-outlet"

export const SidebarLayout = () => {
  return (
    <SidebarProvider defaultOpen={false} className="flex h-screen w-screen overflow-hidden">
      <AppSidebar />
      <div className="flex-1 flex flex-col min-w-0 h-screen overflow-hidden">
        <div className="h-10 min-h-[40px] items-center border-b border-border/70 justify-between flex px-3 bg-card/75 backdrop-blur z-20 shrink-0">
          <div className="flex items-center gap-2">
            <SidebarTrigger />
            <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider hidden sm:inline">
              Jev · Federated Threat Graph
            </span>
          </div>
          <ModeToggle />
        </div>
        <div className="flex-1 min-h-0 overflow-y-auto relative">
          <AnimatedOutlet />
        </div>
      </div>
    </SidebarProvider>
  )
}
