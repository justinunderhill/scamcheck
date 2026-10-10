import { useEffect, useState } from "react";
import { Check, Search } from "./icons";

// A calm, reassuring progress sequence shown while the request is in flight.
// The real backend runs everything in one call; this staggered reveal lowers
// anxiety during the wait and quietly teaches what's being checked.
const LINK_STEPS = ["Reading the web address", "Checking Google Web Risk", "Checking VirusTotal"];
const MESSAGE_STEP = "Reading your message for scam tricks";
const SUMMARY_STEP = "Writing your plain-language summary";

// Typical end-to-end time, used to pace the bar. AI message analysis is the
// slow part (~10s in prod); a link-only check usually lands in a few seconds.
const TYPICAL_SECONDS_WITH_MESSAGE = 11;
const TYPICAL_SECONDS_LINK_ONLY = 4;
// The bar eases toward this ceiling and never reaches 100% on its own — the
// response arriving is what completes it (this component unmounts).
const BAR_CEILING = 95;
const TICK_MS = 200;

// After these many seconds, reassure the user the check is still running, so a
// slow AI call doesn't look frozen and invite a reload (which burns a free check).
const STILL_WORKING_AFTER_S = 6;
const ALMOST_THERE_AFTER_S = 20;

/** Eases toward BAR_CEILING: ~85% at the typical duration, then crawls. */
function progressAt(seconds: number, typical: number): number {
  return BAR_CEILING * (1 - Math.exp((-2 * seconds) / typical));
}

export function CheckingState({ hasMessage = false }: { hasMessage?: boolean }) {
  const steps = [...LINK_STEPS, ...(hasMessage ? [MESSAGE_STEP] : []), SUMMARY_STEP];
  const typical = hasMessage ? TYPICAL_SECONDS_WITH_MESSAGE : TYPICAL_SECONDS_LINK_ONLY;
  const [done, setDone] = useState(0);
  const [elapsedMs, setElapsedMs] = useState(0);

  useEffect(() => {
    // The slow step is never marked done: it stays current until the response
    // actually arrives and this component unmounts. With a message that's the
    // AI message read (the real wait); otherwise it's the summary.
    const last = hasMessage ? steps.indexOf(MESSAGE_STEP) : steps.length - 1;
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) setDone(last);
    const timers = reduce
      ? []
      : steps.map((_, i) => window.setTimeout(() => setDone((d) => Math.min(last, Math.max(d, i + 1))), 450 * (i + 1)));
    const clock = window.setInterval(() => setElapsedMs((ms) => ms + TICK_MS), TICK_MS);
    return () => {
      timers.forEach(clearTimeout);
      clearInterval(clock);
    };
    // steps only depends on hasMessage, which is fixed for one check.
  }, [hasMessage]);

  const elapsed = elapsedMs / 1000;
  const percent = Math.round(progressAt(elapsed, typical));
  const hint =
    elapsed >= ALMOST_THERE_AFTER_S
      ? "Almost there. Thanks for waiting, this one is taking a little longer."
      : elapsed >= STILL_WORKING_AFTER_S
        ? hasMessage
          ? "Still working. Reading a message carefully can take up to 20 seconds."
          : "Still working. Some security checks take a few extra seconds."
        : null;

  return (
    <section className="checking" aria-live="polite" aria-busy="true">
      <div className="checking__pulse">
        <Search width={26} height={26} />
      </div>
      <p className="checking__title">Checking this link…</p>
      <div
        className="checking__bar"
        role="progressbar"
        aria-label="Checking progress"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={percent}
      >
        <span className="checking__bar-fill" style={{ width: `${percent}%` }} />
      </div>
      <ul className="checking__steps">
        {steps.map((label, i) => {
          const state = i < done ? "done" : i === done ? "active" : "pending";
          return (
            <li key={label} className={`checking__step checking__step--${state}`}>
              <span className="checking__dot">
                {state === "done" ? <Check width={15} height={15} /> : <span className="checking__marker" />}
              </span>
              <span>{label}</span>
            </li>
          );
        })}
      </ul>
      {hint && <p className="checking__hint">{hint}</p>}
    </section>
  );
}
