"use client"

import { AnimatePresence, motion } from "motion/react"
import { CircleAlertIcon } from "lucide-react"

export function AuthError({ message }: { message?: string | null }) {
  return (
    <AnimatePresence mode="popLayout" initial={false}>
      {message ? (
        <motion.div
          key={message}
          role="alert"
          initial={{ opacity: 0, y: -4, scale: 0.99 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={{ opacity: 0, y: -4, scale: 0.99 }}
          transition={{ type: "spring", bounce: 0, duration: 0.24 }}
          className="flex items-start gap-2 rounded-[10px] border border-[var(--auth-danger)]/25 bg-[var(--auth-danger)]/[0.06] px-3 py-2 text-[0.78125rem] font-medium text-[var(--auth-danger)]"
        >
          <CircleAlertIcon className="mt-0.5 size-4 shrink-0" />
          <span>{message}</span>
        </motion.div>
      ) : null}
    </AnimatePresence>
  )
}
