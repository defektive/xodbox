import { useCallback, useEffect, useRef, useState } from "react";

// useLiveFeed manages a realtime-appended list: it seeds from an initial page,
// prepends live items (newest first, capped), and de-dupes by id so a duplicate
// or reconnected stream frame neither re-inserts a row nor inflates liveCount.
//
// Usage: `claim(id)` returns true the first time an id is seen — the caller then
// calls `add(item)`. For async fetches, call `claim` first (to gate the fetch),
// then `add` on success or `release(id)` on failure.
export function useLiveFeed<T extends { id: number }>(
  initial: T[] | undefined,
  cap = 200,
) {
  const [items, setItems] = useState<T[]>([]);
  const [liveCount, setLiveCount] = useState(0);
  const seen = useRef<Set<number>>(new Set());

  useEffect(() => {
    const arr = initial ?? [];
    setItems(arr);
    setLiveCount(0);
    seen.current = new Set(arr.map((x) => x.id));
  }, [initial]);

  const claim = useCallback((id: number) => {
    if (seen.current.has(id)) return false;
    seen.current.add(id);
    return true;
  }, []);

  const add = useCallback(
    (item: T) => {
      setItems((prev) => [item, ...prev].slice(0, cap));
      setLiveCount((c) => c + 1);
    },
    [cap],
  );

  const release = useCallback((id: number) => {
    seen.current.delete(id);
  }, []);

  return { items, liveCount, claim, add, release };
}
