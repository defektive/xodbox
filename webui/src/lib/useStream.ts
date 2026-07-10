import { useEffect, useRef } from "react";
import { apiBase } from "@/lib/base";
import type { InteractionSummary } from "@/lib/types";

// useInteractionStream opens a Server-Sent Events connection to the realtime
// interaction stream (optionally filtered by the same query string the view
// uses) and invokes onEvent for each newly captured interaction. EventSource
// carries the session cookie and reconnects automatically.
export function useInteractionStream(
  query: string,
  onEvent: (i: InteractionSummary) => void,
) {
  const cb = useRef(onEvent);
  cb.current = onEvent;

  useEffect(() => {
    const url = apiBase + "stream" + (query ? "?" + query : "");
    const es = new EventSource(url, { withCredentials: true });
    es.addEventListener("interaction", (e) => {
      try {
        cb.current(JSON.parse((e as MessageEvent).data) as InteractionSummary);
      } catch {
        /* ignore malformed frames */
      }
    });
    return () => es.close();
  }, [query]);
}
