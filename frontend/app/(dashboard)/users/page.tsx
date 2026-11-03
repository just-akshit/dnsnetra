"use client"

import * as React from "react"
import { useAuthUser } from "@/components/auth/AuthGuard"
import { usersApi, AdminApiError, type AdminUser, type UserRole } from "@/lib/admin/users-api"
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

export default function UsersPage() {
  const me = useAuthUser()
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

  React.useEffect(() => { if (me?.role === "ADMIN") void load() }, [load, me?.role])

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

  if (me?.role !== "ADMIN") {
    return <p className="p-6 text-sm text-muted-foreground">Administrator access required.</p>
  }

  const pending = users.filter((u) => u.status === "PENDING")
  const others = users.filter((u) => u.status !== "PENDING")

  return (
    <div className="flex flex-col gap-6 p-4 lg:p-6">
      <header className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold">Users</h1>
          <p className="text-sm text-muted-foreground">
            Approve new accounts and manage existing ones.
          </p>
        </div>
        <CreateUserDialog disabled={busy} onCreated={load} />
      </header>

      {error && <p role="alert" className="text-sm text-destructive">{error}</p>}

      <section className="flex flex-col gap-2">
        <h2 className="text-sm font-medium">Pending approval ({pending.length})</h2>
        <UserTable
          users={pending}
          busy={busy}
          actions={(u) => (
            <>
              {(["ANALYST", "SUPPORT"] as const).map((role) => (
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
          actions={(u) => (
            <>
              <Button size="sm" variant="outline" disabled={busy}
                onClick={() => run(() => usersApi.revokeSessions(u.id))}>
                Revoke sessions
              </Button>
              {u.status === "ACTIVE" ? (
                <Button size="sm" variant="destructive" disabled={busy}
                  onClick={() => run(() => usersApi.disable(u.id))}>
                  Disable
                </Button>
              ) : (
                <Button size="sm" variant="outline" disabled={busy}
                  onClick={() => run(() => usersApi.enable(u.id))}>
                  Enable
                </Button>
              )}
              <ResetPasswordDialog user={u} disabled={busy} onDone={load} />
            </>
          )}
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

function CreateUserDialog({ disabled, onCreated }: { disabled: boolean; onCreated: () => void }) {
  const [open, setOpen] = React.useState(false)
  const [username, setUsername] = React.useState("")
  const [password, setPassword] = React.useState("")
  const [role, setRole] = React.useState<UserRole>("ANALYST")
  const [error, setError] = React.useState<string | null>(null)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    try {
      await usersApi.create({ username, password, role, status: "ACTIVE" })
      setOpen(false); setUsername(""); setPassword(""); setRole("ANALYST"); onCreated()
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
            <Input id="new-password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label>Role</Label>
            <Select value={role} onValueChange={(v) => { if (v) setRole(v as UserRole) }}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="ANALYST">ANALYST</SelectItem>
                <SelectItem value="SUPPORT">SUPPORT</SelectItem>
                <SelectItem value="ADMIN">ADMIN</SelectItem>
              </SelectContent>
            </Select>
          </div>
          {error && <p className="text-sm text-destructive">{error}</p>}
          <DialogFooter>
            <Button type="submit">Create</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function ResetPasswordDialog({
  user, disabled, onDone,
}: { user: AdminUser; disabled: boolean; onDone: () => void }) {
  const [open, setOpen] = React.useState(false)
  const [password, setPassword] = React.useState("")
  const [error, setError] = React.useState<string | null>(null)

  async function submit(e: React.FormEvent) {
    e.preventDefault()
    try {
      await usersApi.resetPassword(user.id, password)
      setOpen(false); setPassword(""); onDone()
    } catch (e) {
      setError(e instanceof AdminApiError ? e.message : "Could not reset password.")
    }
  }

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger render={<Button size="sm" variant="outline" disabled={disabled} />}>
        Reset password
      </DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Reset {user.username}&apos;s password</DialogTitle>
          <DialogDescription>
            All sessions are revoked. The user must change this password at next login.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={submit} className="flex flex-col gap-3">
          <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
          {error && <p className="text-sm text-destructive">{error}</p>}
          <DialogFooter><Button type="submit">Reset</Button></DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

