"use client"

import * as React from "react"
import { useAuthUser } from "@/components/auth/AuthGuard"
import {
  usersApi,
  AdminApiError,
  type AdminUser,
  type ResetCodeResponse,
  type ResetPasswordResponse,
  type UserRole,
} from "@/lib/admin/users-api"
import { assignableRoles, canManage } from "@/lib/admin/permissions"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from "@/components/ui/table"
import {
  Dialog, DialogContent, DialogDescription, DialogFooter,
  DialogHeader, DialogTitle, DialogTrigger,
} from "@/components/ui/dialog"
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select"

const STATUS_STYLE: Record<string, string> = {
  ACTIVE: "bg-emerald-500/10 text-emerald-700",
  PENDING: "bg-amber-500/10 text-amber-700",
  DISABLED: "bg-muted text-muted-foreground",
}

const ONCE_ONLY_WARNING =
  "Shown once. Give it to the user in person or over a secure channel. " +
  "They must change it at first login."

export default function UsersPage() {
  const me = useAuthUser()
  const isAdmin = me?.role === "ADMIN" || me?.role === "SUPER_ADMIN"
  const [users, setUsers] = React.useState<AdminUser[]>([])
  const [error, setError] = React.useState<string | null>(null)
  const [busy, setBusy] = React.useState(false)

  const load = React.useCallback(async () => {
    try {
      const res = await usersApi.list({ limit: 200 })
      setUsers(res.items)
      setError(null)
    } catch (e) {
      setError(e instanceof AdminApiError ? e.message : "Could not load users.")
    }
  }, [])

  React.useEffect(() => {
    if (isAdmin) void load()
  }, [load, isAdmin])

  async function run(action: () => Promise<unknown>) {
    setBusy(true)
    try {
      await action()
      await load()
    } catch (e) {
      setError(e instanceof AdminApiError ? e.message : "Action failed.")
    } finally {
      setBusy(false)
    }
  }

  if (!isAdmin) {
    return <p className="p-6 text-sm text-muted-foreground">Administrator access required.</p>
  }

  const pending = users.filter((u) => u.status === "PENDING")
  const others = users.filter((u) => u.status !== "PENDING")
  const roles = assignableRoles(me?.role)

  return (
    <div className="flex flex-col gap-6 p-4 lg:p-6">
      <header className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold">Users</h1>
          <p className="text-sm text-muted-foreground">
            Approve new accounts and manage existing ones.
          </p>
        </div>
        <CreateUserDialog disabled={busy} onCreated={load} roles={roles} />
      </header>

      {error && <p role="alert" className="text-sm text-destructive">{error}</p>}

      <section className="flex flex-col gap-2">
        <h2 className="text-sm font-medium">Pending approval ({pending.length})</h2>
        <UserTable
          users={pending}
          busy={busy}
          actions={(u) => (
            <>
              {(["ANALYST", "SUPPORT"] as const)
                .filter(() => canManage(me?.role, u, me?.id))
                .map((role) => (
                  <Button key={role} size="sm" disabled={busy}
                    onClick={() => run(() => usersApi.approve(u.id, role))}>
                    Approve as {role}
                  </Button>
                ))}
            </>
          )}
        />
      </section>

      <section className="flex flex-col gap-2">
        <h2 className="text-sm font-medium">All accounts</h2>
        <UserTable
          users={others}
          busy={busy}
          actions={(u) => {
            const allowed = canManage(me?.role, u, me?.id)
            const canRevoke = allowed || (me?.id != null && Number(me.id) === u.id)
            return (
              <>
                {canRevoke && (
                  <Button size="sm" variant="outline" disabled={busy}
                    onClick={() => run(() => usersApi.revokeSessions(u.id))}>
                    Revoke sessions
                  </Button>
                )}
                {u.status === "ACTIVE" ? (
                  allowed && (
                    <Button size="sm" variant="destructive" disabled={busy}
                      onClick={() => run(() => usersApi.disable(u.id))}>
                      Disable
                    </Button>
                  )
                ) : (
                  allowed && (
                    <Button size="sm" variant="outline" disabled={busy}
                      onClick={() => run(() => usersApi.enable(u.id))}>
                      Enable
                    </Button>
                  )
                )}
                {allowed && (
                  <ChangeRoleDialog user={u} roles={roles} disabled={busy} onDone={load} />
                )}
                {allowed && <ResetPasswordDialog user={u} disabled={busy} onDone={load} />}
                {allowed && <ResetCodeDialog user={u} disabled={busy} onDone={load} />}
              </>
            )
          }}
        />
      </section>
    </div>
  )
}

function UserTable({
  users, busy, actions,
}: {
  users: AdminUser[]
  busy: boolean
  actions: (u: AdminUser) => React.ReactNode
}) {
  if (!users.length) return <p className="text-sm text-muted-foreground">None.</p>
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Username</TableHead>
          <TableHead>Role</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Last login</TableHead>
          <TableHead className="text-right">Actions</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {users.map((u) => (
          <TableRow key={u.id}>
            <TableCell className="font-medium">{u.username}</TableCell>
            <TableCell>{u.role}</TableCell>
            <TableCell>
              <Badge className={STATUS_STYLE[u.status]}>{u.status}</Badge>
            </TableCell>
            <TableCell className="text-muted-foreground">
              {u.last_login_at ? new Date(u.last_login_at).toLocaleString() : "Never"}
            </TableCell>
            <TableCell className="flex justify-end gap-2">{actions(u)}</TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  )
}

function CreateUserDialog({
  disabled, onCreated, roles,
}: {
  disabled: boolean
  onCreated: () => void
  roles: UserRole[]
}) {
  const defaultRole: UserRole = roles.includes("ANALYST") ? "ANALYST" : (roles[0] ?? "ANALYST")
  const [open, setOpen] = React.useState(false)
  const [username, setUsername] = React.useState("")
  const [password, setPassword] = React.useState("")
  const [role, setRole] = React.useState<UserRole>(defaultRole)
  const [error, setError] = React.useState<string | null>(null)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    try {
      await usersApi.create({ username, password, role, status: "ACTIVE" })
      setOpen(false)
      setUsername("")
      setPassword("")
      setRole(defaultRole)
      onCreated()
    } catch (e) {
      setError(e instanceof AdminApiError ? e.message : "Could not create user.")
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger render={<Button disabled={disabled} />}>Create user</DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Create user</DialogTitle>
          <DialogDescription>
            The user must change this password at first login.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={submit} className="flex flex-col gap-3">
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="new-username">Username</Label>
            <Input id="new-username" value={username} onChange={(e) => setUsername(e.target.value)} required />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="new-password">Temporary password</Label>
            <Input
              id="new-password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              minLength={8}
              maxLength={128}
              autoComplete="new-password"
            />
            <p className="text-xs text-muted-foreground">
              At least 8 characters, including a letter and a number or symbol.
            </p>
          </div>
          <div className="flex flex-col gap-1.5">
            <Label>Role</Label>
            <Select value={role} onValueChange={(v) => { if (v) setRole(v as UserRole) }}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                {roles.map((r) => (
                  <SelectItem key={r} value={r}>{r}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
          <DialogFooter>
            <Button type="submit">Create</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function ChangeRoleDialog({
  user, roles, disabled, onDone,
}: {
  user: AdminUser
  roles: UserRole[]
  disabled: boolean
  onDone: () => void
}) {
  const [open, setOpen] = React.useState(false)
  const [role, setRole] = React.useState<UserRole>(user.role as UserRole)
  const [error, setError] = React.useState<string | null>(null)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    try {
      await usersApi.update(user.id, { role })
      setOpen(false)
      setError(null)
      onDone()
    } catch (e) {
      setError(e instanceof AdminApiError ? e.message : "Could not change role.")
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger render={<Button size="sm" variant="outline" disabled={disabled} />}>
        Change role
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Change {user.username}&apos;s role</DialogTitle>
          <DialogDescription>Only roles you may assign are listed.</DialogDescription>
        </DialogHeader>
        <form onSubmit={submit} className="flex flex-col gap-3">
          <Select value={role} onValueChange={(v) => { if (v) setRole(v as UserRole) }}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              {roles.map((r) => (
                <SelectItem key={r} value={r}>{r}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          {error && <p className="text-sm text-destructive">{error}</p>}
          <DialogFooter><Button type="submit">Save role</Button></DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function ResetPasswordDialog({
  user, disabled, onDone,
}: { user: AdminUser; disabled: boolean; onDone: () => void }) {
  const [open, setOpen] = React.useState(false)
  const [result, setResult] = React.useState<ResetPasswordResponse | null>(null)
  const [error, setError] = React.useState<string | null>(null)

  function close(next: boolean) {
    setOpen(next)
    if (!next) {
      setResult(null)
      setError(null)
    }
  }

  async function confirm() {
    try {
      const res = await usersApi.resetPassword(user.id)
      setResult(res)
      setError(null)
      onDone()
    } catch (e) {
      setError(e instanceof AdminApiError ? e.message : "Could not reset password.")
    }
  }

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogTrigger render={<Button size="sm" variant="outline" disabled={disabled} />}>
        Reset password
      </DialogTrigger>
      <DialogContent>
        {result ? (
          <>
            <DialogHeader>
              <DialogTitle>Temporary password for {result.username}</DialogTitle>
              <DialogDescription>{ONCE_ONLY_WARNING}</DialogDescription>
            </DialogHeader>
            <code
              data-testid="temporary-password"
              className="rounded bg-muted p-3 text-sm break-all"
            >
              {result.temporary_password}
            </code>
            <DialogFooter>
              <Button
                type="button"
                onClick={() => navigator.clipboard?.writeText(result.temporary_password)}
              >
                Copy
              </Button>
              <Button type="button" variant="outline" onClick={() => close(false)}>
                Close dialog
              </Button>
            </DialogFooter>
          </>
        ) : (
          <>
            <DialogHeader>
              <DialogTitle>Reset {user.username}&apos;s password?</DialogTitle>
              <DialogDescription>
                This signs them out everywhere and forces a password change at next login.
              </DialogDescription>
            </DialogHeader>
            {error && <p className="text-sm text-destructive">{error}</p>}
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => close(false)}>
                Cancel
              </Button>
              <Button type="button" variant="destructive" onClick={confirm}>
                Confirm reset
              </Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  )
}

function ResetCodeDialog({
  user, disabled, onDone,
}: { user: AdminUser; disabled: boolean; onDone: () => void }) {
  const [open, setOpen] = React.useState(false)
  const [result, setResult] = React.useState<ResetCodeResponse | null>(null)
  const [error, setError] = React.useState<string | null>(null)

  function close(next: boolean) {
    setOpen(next)
    if (!next) {
      setResult(null)
      setError(null)
    }
  }

  async function confirm() {
    try {
      const res = await usersApi.resetCode(user.id)
      setResult(res)
      setError(null)
      onDone()
    } catch (e) {
      setError(e instanceof AdminApiError ? e.message : "Could not issue a reset code.")
    }
  }

  return (
    <Dialog open={open} onOpenChange={close}>
      <DialogTrigger render={<Button size="sm" variant="outline" disabled={disabled} />}>
        Issue reset code
      </DialogTrigger>
      <DialogContent>
        {result ? (
          <>
            <DialogHeader>
              <DialogTitle>Reset code for {user.username}</DialogTitle>
              <DialogDescription>
                Shown once. It expires at {new Date(result.expires_at).toLocaleString()}.
              </DialogDescription>
            </DialogHeader>
            <code data-testid="reset-code" className="rounded bg-muted p-3 text-sm break-all">
              {result.code}
            </code>
            <DialogFooter>
              <Button
                type="button"
                onClick={() => navigator.clipboard?.writeText(result.code)}
              >
                Copy
              </Button>
              <Button type="button" variant="outline" onClick={() => close(false)}>
                Close dialog
              </Button>
            </DialogFooter>
          </>
        ) : (
          <>
            <DialogHeader>
              <DialogTitle>Issue a reset code for {user.username}?</DialogTitle>
              <DialogDescription>
                The user redeems the code on the reset-password page and chooses their own password.
              </DialogDescription>
            </DialogHeader>
            {error && <p className="text-sm text-destructive">{error}</p>}
            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => close(false)}>
                Cancel
              </Button>
              <Button type="button" onClick={confirm}>
                Issue code
              </Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  )
}
