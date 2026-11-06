/**
 * Client-side mirror of the backend role hierarchy (api/user_admin_policy.py).
 *
 * This only decides which controls to render. The backend is authoritative and
 * will reject anything the UI lets slip through.
 */

import type { UserRole } from "./users-api"

const MANAGEABLE: Record<string, UserRole[]> = {
  SUPER_ADMIN: ["SUPER_ADMIN", "ADMIN", "ANALYST", "SUPPORT"],
  ADMIN: ["ANALYST", "SUPPORT"],
}

export function canManage(
  actorRole: string | undefined | null,
  target: { id: number; role: string },
  selfId?: number | string | null
): boolean {
  if (!actorRole) return false
  if (selfId != null && Number(selfId) === target.id) return false
  return MANAGEABLE[actorRole]?.includes(target.role as UserRole) ?? false
}

export function assignableRoles(actorRole: string | undefined | null): UserRole[] {
  return MANAGEABLE[actorRole ?? ""] ?? []
}
