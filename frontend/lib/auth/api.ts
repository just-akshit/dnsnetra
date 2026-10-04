/**
 * DNSNetra auth client.
 *
 * Session lives in the backend's HttpOnly `dnsnetra_session` cookie, so every
 * call uses `credentials: "include"`. Nothing here stores tokens, passwords,
 * or CAPTCHA answers anywhere in the browser.
 */

export const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000"
const AUTH = `${API_BASE}/api/v1/auth`

export type AuthErrorKind =
  | "credentials"
  | "captcha"
  | "captcha_expired"
  | "rate_limited"
  | "pending"
  | "taken"
  | "validation"
  | "network"
  | "unknown"

export class AuthApiError extends Error {
  constructor(
    public kind: AuthErrorKind,
    message: string
  ) {
    super(message)
  }
  /** The CAPTCHA is single-use: any failed attempt needs a fresh one. */
  get needsNewCaptcha() {
    return this.kind !== "network" && this.kind !== "rate_limited"
  }
}

export interface CaptchaChallenge {
  captcha_id: string
  image: string
  expires_in: number
}

export interface AuthUser {
  id: number | string
  username: string
  email?: string | null
  role: string
  status: string
  must_change_password?: boolean
}

function detailText(detail: unknown): string {
  if (typeof detail === "string") return detail
  if (Array.isArray(detail)) {
    return detail
      .map((d) => (d && typeof d === "object" && "msg" in d ? String(d.msg) : ""))
      .filter(Boolean)
      .join(". ")
  }
  return ""
}

function classify(status: number, detail: string): AuthApiError {
  const d = detail.toLowerCase()
  if (status === 429)
    return new AuthApiError("rate_limited", "Too many attempts. Please try again shortly.")
  if (d.includes("captcha")) {
    const stale = /expired|already been used|not found|invalid/.test(d)
    return stale
      ? new AuthApiError("captcha_expired", "That CAPTCHA expired. We loaded a new one.")
      : new AuthApiError("captcha", "Incorrect CAPTCHA. Please try again.")
  }
  if (d.includes("pending") || d.includes("awaiting"))
    return new AuthApiError("pending", "Your account is pending administrator approval.")
  if (status === 401 || status === 403)
    return new AuthApiError("credentials", "Incorrect username or password")
  if (status === 409) return new AuthApiError("taken", "That username is already taken.")
  if (status === 400 || status === 422)
    return new AuthApiError("validation", detail || "Please check your details and try again.")
  return new AuthApiError("unknown", "Something went wrong. Please try again.")
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response
  try {
    res = await fetch(`${AUTH}${path}`, {
      credentials: "include",
      cache: "no-store",
      ...init,
      headers: { Accept: "application/json", "Content-Type": "application/json" },
    })
  } catch {
    throw new AuthApiError("network", "Can't reach DNSNetra. Check your connection and try again.")
  }
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw classify(res.status, detailText(body?.detail))
  }
  return res.json() as Promise<T>
}

const post = <T>(path: string, body: unknown) =>
  request<T>(path, { method: "POST", body: JSON.stringify(body) })

export const authApi = {
  captcha: () => request<CaptchaChallenge>("/captcha"),

  login: (b: {
    username: string
    password: string
    captcha_id: string
    captcha_answer: string
  }) => post<{ user: AuthUser }>("/login", b),

  signup: (b: {
    username: string
    password: string
    confirm_password: string
    captcha_id: string
    captcha_answer: string
  }) => post<{ message: string; username: string; status: string }>("/signup", b),

  logout: () => post<unknown>("/logout", {}),

  /** Resolves to null when there is no valid session. */
  async me(): Promise<AuthUser | null> {
    try {
      return await request<AuthUser>("/me")
    } catch (e) {
      if (e instanceof AuthApiError && e.kind === "network") throw e
      return null
    }
  },
}

/** Mirrors backend policy for UX only; the API stays authoritative. */
export function validateUsername(v: string): string | null {
  if (!v.trim()) return "Enter a username"
  if (v.length < 3 || v.length > 50) return "Use 3 to 50 characters"
  if (!/^[a-zA-Z0-9_.-]+$/.test(v)) return "Letters, numbers, dot, dash and underscore only"
  return null
}

export function validatePassword(v: string, username: string): string | null {
  if (!v) return "Enter a password"
  if (v.length < 8 || v.length > 128) return "Use 8 to 128 characters"
  if (!/[A-Za-z]/.test(v)) return "Include at least one letter"
  if (!/[^A-Za-z]/.test(v)) return "Include a number or symbol"
  if (v.toLowerCase() === username.trim().toLowerCase()) return "Must differ from your username"
  return null
}
