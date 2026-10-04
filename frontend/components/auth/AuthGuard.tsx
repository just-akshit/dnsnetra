"use client"

import * as React from "react"
import { useRouter } from "next/navigation"
import { authApi, type AuthUser } from "@/lib/auth/api"

const UserContext = React.createContext<AuthUser | null>(null)
export const useAuthUser = () => React.useContext(UserContext)

/** Asks the backend whether the session cookie is valid; the server stays authoritative. */
export function AuthGuard({ children }: { children: React.ReactNode }) {
  const router = useRouter()
  const [user, setUser] = React.useState<AuthUser | null>(null)

  React.useEffect(() => {
    authApi
      .me()
      .then((u) => (u ? setUser(u) : router.replace("/login")))
      .catch(() => router.replace("/login"))
  }, [router])

  if (!user) return null
  return <UserContext.Provider value={user}>{children}</UserContext.Provider>
}
