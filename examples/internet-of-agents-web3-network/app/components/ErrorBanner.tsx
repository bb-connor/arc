"use client";

interface ErrorBannerProps {
  title?: string;
  message: string;
  detail?: string;
  onRetry?: () => void;
}

export function ErrorBanner({ title, message, detail, onRetry }: ErrorBannerProps): JSX.Element {
  return (
    <div className="error-banner" role="alert" data-testid="error-banner">
      <div className="card">
        <h1>{title ?? "Bundle unavailable"}</h1>
        <p>
          The Chio Evidence Console could not load the bundle. It fails closed
          so that a missing or corrupted artifact never renders as valid
          evidence.
        </p>
        <p className="muted">{message}</p>
        {detail ? <pre>{detail}</pre> : null}
        {onRetry ? (
          <button type="button" className="retry" onClick={onRetry}>
            retry
          </button>
        ) : null}
      </div>
    </div>
  );
}
