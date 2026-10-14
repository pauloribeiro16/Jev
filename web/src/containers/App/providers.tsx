import { ThemeProvider } from "@/components/theme-provider"
import { Toaster } from "@/components/ui/sonner"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { StrictMode } from "react"
import { BrowserRouter } from "react-router"

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { refetchOnWindowFocus: false, retry: 0 },
  },
})

export default function Providers({ children }: { children: React.ReactNode }) {
  return (
    <StrictMode>
      <ThemeProvider defaultTheme="dark">
        <QueryClientProvider client={queryClient}>
          <BrowserRouter>
            {children}
            <Toaster />
          </BrowserRouter>
        </QueryClientProvider>
      </ThemeProvider>
    </StrictMode>
  )
}
