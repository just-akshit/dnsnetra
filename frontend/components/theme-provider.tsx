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

function getSystemTheme(): "light" | "dark" {
  if (typeof window === "undefined") return "light"
  return window.matchMedia("(prefers-color-scheme: dark)").matches
    ? "dark"
    : "light"
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

  const [systemTheme, setSystemTheme] = React.useState<"light" | "dark">("light")

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
    const initialSystem = getSystemTheme()
    setSystemTheme(initialSystem)
    applyTheme(theme, initialSystem)

    const mediaQuery = window.matchMedia("(prefers-color-scheme: dark)")
    const handleSystemChange = (e: MediaQueryListEvent) => {
      const newSystem = e.matches ? "dark" : "light"
      setSystemTheme(newSystem)
      if (theme === "system") {
        applyTheme("system", newSystem)
      }
    }

    const handleStorage = (e: StorageEvent) => {
      if (e.key === storageKey && e.newValue) {
        const newTheme = e.newValue as Theme
        setThemeState(newTheme)
        applyTheme(newTheme, systemTheme)
      }
    }

    mediaQuery.addEventListener("change", handleSystemChange)
    window.addEventListener("storage", handleStorage)

    return () => {
      mediaQuery.removeEventListener("change", handleSystemChange)
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
