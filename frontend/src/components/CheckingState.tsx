import { useEffect, useState } from "react";
import { Check, Search } from "./icons";

// A calm, reassuring progress sequence shown while the request is in flight.
// The real backend runs everything in one call; this staggered reveal lowers
// anxiety during the wait and quietly teaches what's being checked.
const SCREENSHOT_STEP = "Reading your screenshot";
const LINK_STEPS = ["Reading the web address", "Checking Google Web Risk", "Checking VirusTotal"];
const MESSAGE_STEP = "Reading your message for scam tricks";
const SUMMARY_STEP = "Writing your plain-language summary";

// Typical end-to-end time, used to pace the bar. AI message analysis is the
// slow part (~10s in prod); reading a screenshot adds a few seconds before it.
const TYPICAL_SECONDS_SCREENSHOT = 16;
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

interface Props {
  hasLink?: boolean;
  hasMessage?: boolean;
  // Set when the check started from a screenshot: "reading" while it's being
  // read (link/message not known yet), then "read" once the check is running.
  screenshot?: "reading" | "read";
}

export function CheckingState({ hasLink = true, hasMessage = false, screenshot }: Props) {
  const reading = screenshot === "reading";
  const steps = [
    ...(screenshot ? [SCREENSHOT_STEP] : []),
    ...(!reading && hasLink ? LINK_STEPS : []),
    ...(!reading && hasMessage ? [MESSAGE_STEP] : []),
    SUMMARY_STEP,
  ];
  const typical = screenshot
    ? TYPICAL_SECONDS_SCREENSHOT
    : hasMessage
      ? TYPICAL_SECONDS_WITH_MESSAGE
      : TYPICAL_SECONDS_LINK_ONLY;
  const [done, setDone] = useState(0);
  const [elapsedMs, setElapsedMs] = useState(0);

  // One clock for the whole wait: it keeps running when a screenshot finishes
  // reading and the check starts, so the bar never jumps backwards.
  useEffect(() => {
    const clock = window.setInterval(() => setElapsedMs((ms) => ms + TICK_MS), TICK_MS);
    return () => clearInterval(clock);
  }, []);

  useEffect(() => {
    // The slow step is never marked done: it stays current until the response
    // actually arrives. That's the screenshot read, then the AI message read
    // when there's a message, otherwise the summary.
    const last = reading ? 0 : hasMessage ? steps.indexOf(MESSAGE_STEP) : steps.length - 1;
    const first = screenshot === "read" ? 1 : 0; // screenshot step already done
    setDone(first);
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      setDone(last);
      return;
    }
    const timers = steps
      .slice(first)
      .map((_, i) =>
        window.setTimeout(() => setDone((d) => Math.min(last, Math.max(d, first + i + 1))), 450 * (i + 1)),
      );
    return () => timers.forEach(clearTimeout);
    // steps derives from these three props.
  }, [screenshot, hasLink, hasMessage]);

  const elapsed = elapsedMs / 1000;
  const percent = Math.round(progressAt(elapsed, typical));
  const slow = Boolean(screenshot) || hasMessage;
  const hint =
    elapsed >= ALMOST_THERE_AFTER_S
      ? "Almost there. Thanks for waiting, this one is taking a little longer."
      : elapsed >= STILL_WORKING_AFTER_S
        ? slow
          ? "Still working. Reading a message carefully can take up to 20 seconds."
          : "Still working. Some security checks take a few extra seconds."
        : null;
  const title = reading
    ? "Reading your screenshot…"
    : hasLink
      ? "Checking this link…"
      : "Checking this message…";

  return (
    <section className="checking" aria-live="polite" aria-busy="true">
      <div className="checking__pulse">
        <Search width={26} height={26} />
      </div>
      <p className="checking__title">{title}</p>
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
