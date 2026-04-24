"use client";

import { useEffect } from "react";
import { ErrorBanner } from "@/components/ErrorBanner";

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}): JSX.Element {
  useEffect(() => {
    // Surface to console for server-log capture during smoke runs.
    // eslint-disable-next-line no-console
    console.error("chio-console global error boundary:", error);
  }, [error]);

  return (
    <ErrorBanner
      title="Unrecoverable error"
      message={error.message}
      detail={error.digest}
      onRetry={reset}
    />
  );
}
