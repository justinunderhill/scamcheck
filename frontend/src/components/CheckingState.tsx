import { useEffect, useState } from "react";
import { Check, Search } from "./icons";

// A calm, reassuring progress sequence shown while the request is in flight.
// The real backend runs everything in one call; this staggered reveal lowers
// anxiety during the wait and quietly teaches what's being checked.
const STEPS = [
  "Reading the web address",
  "Checking Google Web Risk",
  "Checking VirusTotal",
  "Writing your plain-language summary",
];

export function CheckingState() {
  const [done, setDone] = useState(0);

  useEffect(() => {
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) {
      setDone(STEPS.length - 1);
      return;
    }
    const timers = STEPS.map((_, i) =>
      window.setTimeout(() => setDone((d) => Math.max(d, i + 1)), 450 * (i + 1)),
    );
    // Hold the last step "in progress" until the response actually arrives.
    return () => timers.forEach(clearTimeout);
  }, []);

  return (
    <section className="checking" aria-live="polite" aria-busy="true">
      <div className="checking__pulse">
        <Search width={26} height={26} />
      </div>
      <p className="checking__title">Checking this link…</p>
      <ul className="checking__steps">
        {STEPS.map((label, i) => {
          const state = i < done ? "done" : i === done ? "active" : "pending";
          return (
            <li key={label} className={`checking__step checking__step--${state}`}>
              <span className="checking__dot">
                {state === "done" ? <Check width={15} height={15} /> : <span className="checking__spinner" />}
              </span>
              <span>{label}</span>
            </li>
          );
        })}
      </ul>
    </section>
  );
}
