import type { CheckResponse } from "../lib/types";
import { sourceName } from "../lib/labels";

interface Props {
  result: CheckResponse;
}

export function SourcesNote({ result }: Props) {
  const checked = result.sources_checked.map(sourceName);
  const unavailable = result.sources_unavailable.map(sourceName);

  return (
    <footer className="sources-note">
      {checked.length > 0 && <p>Checked with: {checked.join(", ")}.</p>}
      {unavailable.length > 0 && (
        <p className="sources-note__warn">
          Couldn't reach: {unavailable.join(", ")} — this result may be incomplete.
        </p>
      )}
    </footer>
  );
}
