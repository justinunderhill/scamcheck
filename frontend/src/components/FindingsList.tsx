import type { Finding } from "../lib/types";

interface Props {
  findings: Finding[];
}

export function FindingsList({ findings }: Props) {
  if (findings.length === 0) {
    return (
      <p className="findings__empty">
        None of our checks raised a specific warning. Stay cautious anyway —
        especially if this link arrived unexpectedly.
      </p>
    );
  }

  return (
    <ul className="findings">
      {findings.map((f, i) => (
        <li key={i} className={`finding finding--${f.severity}`}>
          <div className="finding__head">
            <span className="finding__severity">{f.severity}</span>
            <span className="finding__title">{f.title}</span>
          </div>
          <p className="finding__detail">{f.detail}</p>
          {f.tip && (
            <details className="finding__tip">
              <summary>What to learn from this</summary>
              <p>{f.tip}</p>
            </details>
          )}
        </li>
      ))}
    </ul>
  );
}
