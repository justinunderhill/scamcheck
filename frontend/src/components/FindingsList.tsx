import { useState } from "react";
import type { Finding, Severity } from "../lib/types";
import { Chevron, Sparkle } from "./icons";

interface Props {
  findings: Finding[];
}

const SEVERITY_LABEL: Record<Severity, string> = {
  low: "Minor",
  medium: "Caution",
  high: "Serious",
};

export function FindingsList({ findings }: Props) {
  if (findings.length === 0) {
    return (
      <p className="findings__empty">
        None of our checks raised a specific warning. That's reassuring — but
        stay cautious anyway, especially if this link arrived unexpectedly.
      </p>
    );
  }

  // Most serious first.
  const order: Severity[] = ["high", "medium", "low"];
  const sorted = [...findings].sort(
    (a, b) => order.indexOf(a.severity) - order.indexOf(b.severity),
  );

  return (
    <ul className="findings">
      {sorted.map((f, i) => (
        <FindingRow key={i} finding={f} index={i} />
      ))}
    </ul>
  );
}

function FindingRow({ finding, index }: { finding: Finding; index: number }) {
  const [open, setOpen] = useState(false);
  return (
    <li
      className={`finding finding--${finding.severity}`}
      data-severity={finding.severity}
      style={{ animationDelay: `${index * 70}ms` }}
    >
      <div className="finding__main">
        <span className="finding__severity">{SEVERITY_LABEL[finding.severity]}</span>
        <div className="finding__text">
          <p className="finding__title">{finding.title}</p>
          <p className="finding__detail">{finding.detail}</p>
        </div>
      </div>
      {finding.tip && (
        <div className="finding__tipwrap">
          <button
            type="button"
            className="finding__tiptoggle"
            aria-expanded={open}
            onClick={() => setOpen((o) => !o)}
          >
            <Sparkle width={15} height={15} aria-hidden="true" />
            What to learn from this
            <Chevron width={16} height={16} aria-hidden="true" className={open ? "is-open" : ""} />
          </button>
          <div className={`finding__tip ${open ? "is-open" : ""}`}>
            <p>{finding.tip}</p>
          </div>
        </div>
      )}
    </li>
  );
}
