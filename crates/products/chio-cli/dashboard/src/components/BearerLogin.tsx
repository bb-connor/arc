import { useState, type FormEvent } from 'react'

interface BearerLoginProps {
  onLogin: (token: string) => void
  storageError: string
}

export function BearerLogin({ onLogin, storageError }: BearerLoginProps) {
  const [error, setError] = useState('')
  const message = error || storageError

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = event.currentTarget
    const token = String(new FormData(form).get('token') ?? '').trim()
    if (!token) {
      setError('Enter a bearer token.')
      return
    }
    if (!/^[\x21-\x7e]+$/.test(token)) {
      setError('Enter a bearer token without spaces or control characters.')
      return
    }
    try {
      onLogin(token)
      form.reset()
    } catch {
      setError('Unable to store the bearer token in this tab.')
    }
  }

  return (
    <section className="auth-notice" aria-labelledby="auth-title">
      <h2 id="auth-title">Bearer token required</h2>
      <p>Enter your trust-control bearer token. It stays in this browser tab until you log out or close the tab.</p>
      <form className="auth-form" onSubmit={submit}>
        <div className="filter-group">
          <label htmlFor="bearer-token">Bearer token</label>
          <input
            id="bearer-token"
            name="token"
            type="password"
            autoComplete="off"
            spellCheck={false}
            aria-invalid={error ? true : undefined}
            aria-describedby={message ? 'auth-error' : undefined}
          />
        </div>
        {message && <p id="auth-error" role="alert">{message}</p>}
        <button className="btn-clear" type="submit">Log in</button>
      </form>
    </section>
  )
}
