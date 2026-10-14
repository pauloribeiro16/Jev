import Lazy, { lazyWithRetry } from "@/components/lazy-component"
import { SidebarLayout } from "@/containers/Layout/sidebar-layout"
import { RouteEnum } from "@/config/constants"
import { Navigate, Route, Routes } from "react-router"

const GraphPage = Lazy(lazyWithRetry(() => import("@/pages/Graph")))
const TracePage = Lazy(lazyWithRetry(() => import("@/pages/Trace")))
const DataPage = Lazy(lazyWithRetry(() => import("@/pages/Data")))
const DecisionChainPage = Lazy(lazyWithRetry(() => import("@/pages/DecisionChain")))
const HowItWorksPage = Lazy(lazyWithRetry(() => import("@/pages/HowItWorks")))
const NotFound = Lazy(lazyWithRetry(() => import("@/pages/NotFound")))

function App() {
  return (
    <Routes>
      <Route element={<SidebarLayout />}>
        <Route path={RouteEnum.GRAPH} element={<GraphPage />} />
        <Route path={RouteEnum.TRACE} element={<TracePage />} />
        <Route path={RouteEnum.DECISION_CHAIN} element={<DecisionChainPage />} />
        <Route path={RouteEnum.DATA} element={<DataPage />} />
        <Route path={RouteEnum.HOW_IT_WORKS} element={<HowItWorksPage />} />
        <Route path={RouteEnum.NOT_FOUND} element={<NotFound />} />
      </Route>
      <Route path="*" element={<Navigate to={RouteEnum.NOT_FOUND} replace />} />
    </Routes>
  )
}

export default App
