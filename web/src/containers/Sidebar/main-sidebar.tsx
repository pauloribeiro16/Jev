import { Database, GitBranch, Waypoints, HelpCircle, Zap, type LucideIcon } from "lucide-react"
import { Link, useLocation } from "react-router"
import {
  Sidebar, SidebarContent, SidebarFooter, SidebarGroup, SidebarGroupContent,
  SidebarGroupLabel, SidebarHeader, SidebarMenu, SidebarMenuButton, SidebarMenuItem,
} from "@/components/ui/sidebar"
import { RouteEnum } from "@/config/constants"

type Item = { title: string; url: string; icon: LucideIcon }

const items: Item[] = [
  { title: "Grafo", url: RouteEnum.GRAPH, icon: Waypoints },
  { title: "Trace Jev", url: RouteEnum.TRACE, icon: Zap },
  { title: "Cadeia de Decisão", url: RouteEnum.DECISION_CHAIN, icon: GitBranch },
  { title: "Dados", url: RouteEnum.DATA, icon: Database },
  { title: "Como funciona", url: RouteEnum.HOW_IT_WORKS, icon: HelpCircle },
]

function Header() {
  return (
    <SidebarHeader>
      <SidebarMenu>
        <SidebarMenuItem>
          <SidebarMenuButton asChild>
            <Link to={RouteEnum.GRAPH}>
              <Waypoints />
              <span className="font-semibold">Jev</span>
            </Link>
          </SidebarMenuButton>
        </SidebarMenuItem>
      </SidebarMenu>
    </SidebarHeader>
  )
}

function Content() {
  const { pathname } = useLocation()
  return (
    <SidebarContent>
      <SidebarGroup>
        <SidebarGroupLabel>Navegação</SidebarGroupLabel>
        <SidebarGroupContent>
          <SidebarMenu>
            {items.map((item) => {
              const active = pathname === item.url || (item.url !== "/" && pathname.startsWith(item.url))
              return (
                <SidebarMenuItem key={item.title}>
                  <SidebarMenuButton asChild isActive={active}>
                    <Link to={item.url}>
                      <item.icon />
                      <span>{item.title}</span>
                    </Link>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              )
            })}
          </SidebarMenu>
        </SidebarGroupContent>
      </SidebarGroup>
    </SidebarContent>
  )
}

function Footer() {
  return (
    <SidebarFooter className="group-data-[collapsible=icon]:hidden">
      <p className="px-2 text-xs text-muted-foreground whitespace-nowrap">
        CWE · CAPEC · ATT&amp;CK · D3FEND · ATLAS
      </p>
    </SidebarFooter>
  )
}

export function AppSidebar() {
  return (
    <Sidebar collapsible="icon">
      <Header />
      <Content />
      <Footer />
    </Sidebar>
  )
}
