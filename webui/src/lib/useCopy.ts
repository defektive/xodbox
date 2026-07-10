import { useState } from "react";

// useCopy copies text to the clipboard and exposes a brief "copied" flag for
// button feedback.
export function useCopy() {
  const [copied, setCopied] = useState(false);
  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  }
  return { copied, copy };
}
