import Link from "next/link"

export function AuthFooter({ prompt, label, href }: { prompt: string; label: string; href: string }) {
  return (
    <p className="text-center text-sm text-[var(--auth-muted)]">
      {prompt}{" "}
      <Link href={href} className="font-medium text-[var(--auth-accent)] underline">
        {label}
      </Link>
    </p>
  )
}
