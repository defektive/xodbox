import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "@/lib/api";

interface ApiResult<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  reload: () => void;
}

// useApi loads data from a GET endpoint, re-fetching whenever `path` changes.
// It is deliberately small — the admin views are read-mostly and don't need a
// full data-fetching library.
export function useApi<T>(path: string): ApiResult<T> {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [nonce, setNonce] = useState(0);

  const reload = useCallback(() => setNonce((n) => n + 1), []);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError(null);
    api
      .get<T>(path)
      .then((d) => {
        if (active) setData(d);
      })
      .catch((e) => {
        if (active) setError(e instanceof ApiError ? e.message : "request failed");
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [path, nonce]);

  return { data, error, loading, reload };
}
