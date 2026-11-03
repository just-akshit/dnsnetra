/**
 * Admin users API client.
 *
 * Mirrors the opaque-session model from lib/auth/api.ts — credentials are in
 * the HttpOnly cookie; nothing is stored in JS. All routes are admin-only on
 * the server; the client enforces nothing itself.
 */

import { getActiveApiBase } from "@/lib/auth/api"

export type UserRole = "ADMIN" | "ANALYST" | "SUPPORT"
export type UserStatus = "PENDING" | "ACTIVE" | "DISABLED"

export interface AdminUser {
  id: number
  username: string
  email?: string | null
  role: UserRole
  status: UserStatus
  is_active: boolean
  created_at?: string
  updated_at?: string
  last_login_at?: string | null
  must_change_password?: boolean
}

export interface UserListResponse {
  total: number
  limit: number
  offset: number
  items: AdminUser[]
}

export class AdminApiError extends Error {
  constructor(public status: number, message: string) {
    super(message)
    this.name = "AdminApiError"
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${getActiveApiBase()}${path}`, {
    credentials: "include",
    cache: "no-store",
    ...init,
    headers: {
      Accept: "application/json",
      ...(init?.body ? { "Content-Type": "application/json" } : {}),
      ...(init?.headers ?? {}),
    },
  })
  const body = await res.json().catch(() => ({}))
  if (!res.ok) {
    throw new AdminApiError(res.status, body?.detail ?? `Request failed (${res.status})`)
  }
  return body as T
}

function qs(params: Record<string, string | number | undefined>): string {
  const s = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== "") s.set(k, String(v))
  }
  const str = s.toString()
  return str ? `?${str}` : ""
}

export const usersApi = {
  list: (params: { status?: UserStatus; limit?: number; offset?: number } = {}) =>
    request<UserListResponse>(`/api/v1/users${qs(params)}`),

  get: (id: number) =>
    request<AdminUser>(`/api/v1/users/${id}`),

  create: (body: { username: string; password: string; role: UserRole; status: UserStatus }) =>
    request<AdminUser>("/api/v1/users", { method: "POST", body: JSON.stringify(body) }),

  update: (id: number, body: { role?: UserRole; status?: UserStatus; is_active?: boolean }) =>
    request<AdminUser>(`/api/v1/users/${id}`, { method: "PATCH", body: JSON.stringify(body) }),

  approve: (id: number, role: "ANALYST" | "SUPPORT") =>
    request<{ message: string }>(`/api/v1/users/${id}/approve`, {
      method: "POST",
      body: JSON.stringify({ role }),
    }),

  disable: (id: number) =>
    request<{ message: string }>(`/api/v1/users/${id}/disable`, { method: "POST" }),

  enable: (id: number) =>
    request<{ message: string }>(`/api/v1/users/${id}/enable`, { method: "POST" }),

  resetPassword: (id: number, newPassword: string) =>
    request<{ message: string }>(`/api/v1/users/${id}/reset-password`, {
      method: "POST",
      body: JSON.stringify({ new_password: newPassword }),
    }),

  revokeSessions: (id: number) =>
    request<{ message: string; revoked_count: number }>(`/api/v1/users/${id}/revoke-sessions`, {
      method: "POST",
    }),
}
