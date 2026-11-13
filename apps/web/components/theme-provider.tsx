"use client"

import * as React from "react"

export type Theme = "light" | "dark" | "system"

export interface ThemeProviderProps {
  children: React.ReactNode
  attribute?: string
  defaultTheme?: Theme
  enableSystem?: boolean
  disableTransitionOnChange?: boolean
  storageKey?: string
}

export interface UseThemeProps {
  theme: Theme
  setTheme: (theme: Theme) => void
  resolvedTheme: "light" | "dark"
  themes: Theme[]
  systemTheme?: "light" | "dark"
}

const ThemeContext = React.createContext<UseThemeProps>({
  theme: "system",
  setTheme: () => {},
  resolvedTheme: "light",
  themes: ["light", "dark", "system"],
  systemTheme: "light",
})

export function useTheme(): UseThemeProps {
  return React.useContext(ThemeContext)
}

const DARK_MEDIA_QUERY = "(prefers-color-scheme: dark)"

function subscribeSystemTheme(onChange: () => void): () => void {
  const mediaQuery = window.matchMedia(DARK_MEDIA_QUERY)
  mediaQuery.addEventListener("change", onChange)
  return () => mediaQuery.removeEventListener("change", onChange)
}

function getSystemTheme(): "light" | "dark" {
  if (typeof window === "undefined") return "light"
  return window.matchMedia(DARK_MEDIA_QUERY).matches ? "dark" : "light"
}

export function ThemeProvider({
  children,
  defaultTheme = "system",
  storageKey = "theme",
  disableTransitionOnChange = false,
}: ThemeProviderProps) {
  const [theme, setThemeState] = React.useState<Theme>(() => {
    if (typeof window === "undefined") return defaultTheme
    try {
      const stored = localStorage.getItem(storageKey) as Theme | null
      return stored ?? defaultTheme
    } catch {
      return defaultTheme
    }
  })

  // System preference is an external store, so derive it instead of mirroring
  // it into state from an effect (which would cascade a render on mount).
  const systemTheme = React.useSyncExternalStore(
    subscribeSystemTheme,
    getSystemTheme,
    () => "light" as const
  )

  const resolvedTheme: "light" | "dark" =
    theme === "system" ? systemTheme : theme

  const applyTheme = React.useCallback(
    (targetTheme: Theme, currentSystemTheme: "light" | "dark") => {
      const root = document.documentElement
      const isDark =
        targetTheme === "dark" ||
        (targetTheme === "system" && currentSystemTheme === "dark")

      let cleanupTransition: (() => void) | null = null
      if (disableTransitionOnChange) {
        const css = document.createElement("style")
        css.appendChild(
          document.createTextNode(
            "*,*::before,*::after{-webkit-transition:none!important;-moz-transition:none!important;-o-transition:none!important;-ms-transition:none!important;transition:none!important}"
          )
        )
        document.head.appendChild(css)
        cleanupTransition = () => {
          window.getComputedStyle(document.body)
          setTimeout(() => {
            if (document.head.contains(css)) {
              document.head.removeChild(css)
            }
          }, 1)
        }
      }

      root.classList.remove("light", "dark")
      root.classList.add(isDark ? "dark" : "light")
      root.style.colorScheme = isDark ? "dark" : "light"

      if (cleanupTransition) {
        cleanupTransition()
      }
    },
    [disableTransitionOnChange]
  )

  React.useEffect(() => {
    applyTheme(theme, systemTheme)

    const handleStorage = (e: StorageEvent) => {
      if (e.key === storageKey && e.newValue) {
        const newTheme = e.newValue as Theme
        setThemeState(newTheme)
        applyTheme(newTheme, systemTheme)
      }
    }

    window.addEventListener("storage", handleStorage)

    return () => {
      window.removeEventListener("storage", handleStorage)
    }
  }, [theme, storageKey, applyTheme, systemTheme])

  const setTheme = React.useCallback(
    (newTheme: Theme) => {
      setThemeState(newTheme)
      applyTheme(newTheme, systemTheme)
      try {
        localStorage.setItem(storageKey, newTheme)
      } catch {}
    },
    [storageKey, applyTheme, systemTheme]
  )

  const value = React.useMemo<UseThemeProps>(
    () => ({
      theme,
      setTheme,
      resolvedTheme,
      themes: ["light", "dark", "system"],
      systemTheme,
    }),
    [theme, setTheme, resolvedTheme, systemTheme]
  )

  return (
    <ThemeContext.Provider value={value}>
      {children}
    </ThemeContext.Provider>
  )
}
