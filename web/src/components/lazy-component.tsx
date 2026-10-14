import type { ComponentType, JSX } from "react"
import React, { Suspense, lazy as originalLazy } from "react"
import { LoadingSpinner } from "./ui/spinner"

/**
 * It suspends a component while it's loading
 *
 * IMPORTANT!
 * Be sure to NOT create lazy loaded components on render!
 *
 * EXAMPLE:
 * const LazyGoodExample = LazyComponent(GoodExample);
 * return (
 *   <Router>
 *     <Route to="/good-example">
 *       <LazyComponent/>
 *     </Route>
 *     <Route to="/bad-example" component={LazyComponent(BadExample)}/>
 *   </Router>
 * );
 */
const LazyComponent = <Props extends object>(
  Component: React.ComponentType<Props>,
): React.FC<Props> => {
  const SuspendedComponent: React.FC<Props> = (props: Props): JSX.Element => (
    <Suspense fallback={<LoadingSpinner />}>
      <Component {...props} />
    </Suspense>
  )

  return SuspendedComponent
}

const hasReloaded = () => {
  try {
    return sessionStorage.getItem("chunk-error-reload") === "true"
  } catch {
    // if something failed, we fall back as true to avoid infinite loops
    return true
  }
}

const storeReloaded = (value: boolean) => {
  try {
    sessionStorage.setItem("chunk-error-reload", value.toString())
  } catch {
    return
  }
}

/**
 * React lazy helper with retry mechanism.
 * After deploying new builds or just due to bad networks, it is common to face `ChunkLoadError`
 * while trying to fetch async chunks on route navigation. This function wraps React.lazy and
 * tries to refresh the browser when facing this issue.
 * https://gist.github.com/raphael-leger/4d703dea6c845788ff9eb36142374bdb#file-lazywithretry-js
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function lazyWithRetry<T extends ComponentType<any>>(
  factory: () => Promise<{ default: T }>,
) {
  return originalLazy(async function lazyWithRetry() {
    const hasReloadedAlready = hasReloaded()

    try {
      const component = await factory()
      storeReloaded(false)

      return component
    } catch (error) {
      // Assuming that the user is not on the latest version of the application, let's
      // refresh the browser to download the latest build.
      if (!hasReloadedAlready) {
        storeReloaded(true)
        window.location.reload()
        // While waiting for browser reload, continue showing the LoaderBig
        return { default: LoadingSpinner } as unknown as { default: T }
      }

      // The page has already been reloaded, so we're assuming the user is using the latest build,
      // hence throwing the error to avoid infinite loops.
      throw error
    }
  })
}

export default LazyComponent
