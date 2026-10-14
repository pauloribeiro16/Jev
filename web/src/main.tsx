import App from "@/containers/App/App"
import Providers from "@/containers/App/providers"
import { createRoot } from "react-dom/client"
import "./index.css"

createRoot(document.getElementById("root")!).render(
  <Providers>
    <App />
  </Providers>,
)
