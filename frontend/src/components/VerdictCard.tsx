import type { CheckResponse, Verdict } from "../lib/types";
import { RiskGauge } from "./RiskGauge";
import { ShieldAlert, ShieldCheck, ShieldX } from "./icons";

interface Props {
  result: CheckResponse;
}

const HEADLINE: Record<Verdict, string> = {
  safe: "No known threats found",
  suspicious: "This link looks suspicious",
  dangerous: "Don't trust this link",
};

function VerdictIcon({ verdict }: { verdict: Verdict }) {
  const props = { width: 22, height: 22, "aria-hidden": true } as const;
  if (verdict === "safe") return <ShieldCheck {...props} />;
  if (verdict === "suspicious") return <ShieldAlert {...props} />;
  return <ShieldX {...props} />;
}

export function VerdictCard({ result }: Props) {
  const { verdict, score, summary, final_url } = result;
  return (
    <section className="verdict" data-verdict={verdict} aria-live="polite">
      <div className="verdict__gauge">
        <RiskGauge score={score} verdict={verdict} />
      </div>
      <div className="verdict__body">
        <span className="verdict__chip">
          <VerdictIcon verdict={verdict} />
          {verdict}
        </span>
        <h2 className="verdict__headline">{HEADLINE[verdict]}</h2>
        <p className="verdict__summary">{summary}</p>
        {/* Plain text — never a clickable link; we don't send users onward. */}
        <p className="verdict__url" title={final_url}>
          <span className="verdict__url-label">Checked</span> {final_url}
        </p>
      </div>
    </section>
  );
}
