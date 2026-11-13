"use client"

import * as React from "react"
import { authApi, type CaptchaChallenge } from "./api"

export interface CaptchaState {
  challenge: CaptchaChallenge | null
  loading: boolean
  failed: boolean
  answer: string
  setAnswer: (v: string) => void
  /** Fetch a fresh challenge and clear the typed answer. */
  refresh: () => void
}

export function useCaptcha(): CaptchaState {
  const [challenge, setChallenge] = React.useState<CaptchaChallenge | null>(null)
  const [loading, setLoading] = React.useState(true)
  const [failed, setFailed] = React.useState(false)
  const [answer, setAnswer] = React.useState("")

  const refresh = React.useCallback(() => {
    setLoading(true)
    setFailed(false)
    setAnswer("")
    authApi
      .captcha()
      .then(setChallenge)
      .catch(() => {
        setChallenge(null)
        setFailed(true)
      })
      .finally(() => setLoading(false))
  }, [])

  React.useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect -- initial fetch
    refresh()
  }, [refresh])

  return { challenge, loading, failed, answer, setAnswer, refresh }
}
