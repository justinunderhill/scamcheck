import type { CheckResponse } from "../lib/types";
import { VERDICT_LABEL } from "../lib/labels";

interface Props {
  result: CheckResponse;
}

export function VerdictCard({ result }: Props) {
  const { verdict, score, summary, final_url } = result;
  return (
    <section className={`verdict verdict--${verdict}`} aria-live="polite">
      <div className="verdict__header">
        <span className="verdict__badge">{VERDICT_LABEL[verdict]}</span>
        <span className="verdict__score" title="Higher means riskier">
          Risk {score}/100
        </span>
      </div>
      <p className="verdict__summary">{summary}</p>
      {/* Plain text, never a clickable link — we don't send users to the destination. */}
      <p className="verdict__url">Checked: {final_url}</p>
    </section>
  );
}
