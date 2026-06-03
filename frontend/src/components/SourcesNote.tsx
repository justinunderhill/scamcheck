import type { CheckResponse } from "../lib/types";
import { sourceName } from "../lib/labels";
import { Check, Dash } from "./icons";

interface Props {
  result: CheckResponse;
}

export function SourcesNote({ result }: Props) {
  const checked = result.sources_checked.filter((s) => s !== "ai").map(sourceName);
  const unavailable = result.sources_unavailable.filter((s) => s !== "ai").map(sourceName);

  return (
    <footer className="sources-note">
      {checked.length > 0 && (
        <p className="sources-note__line">
          <Check width={15} height={15} aria-hidden="true" className="sources-note__ok" />
          <span>Checked with {checked.join(", ")}</span>
        </p>
      )}
      {unavailable.length > 0 && (
        <p className="sources-note__line sources-note__warn">
          <Dash width={15} height={15} aria-hidden="true" />
          <span>Couldn't reach {unavailable.join(", ")} — this result may be incomplete.</span>
        </p>
      )}
    </footer>
  );
}
