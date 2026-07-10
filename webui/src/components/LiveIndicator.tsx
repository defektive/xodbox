// LiveIndicator is the pulsing green "Live" badge shown on realtime views.
export function LiveIndicator() {
  return (
    <span
      className="flex items-center gap-1.5 text-xs text-muted-foreground"
      title="Live updates via server-sent events"
    >
      <span className="relative flex h-2 w-2">
        <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-500 opacity-75" />
        <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500" />
      </span>
      Live
    </span>
  );
}
