import { useEffect, useRef, useState } from "react";
import type { Verdict } from "../lib/types";

interface Props {
  score: number;
  verdict: Verdict;
}

const VERDICT_WORD: Record<Verdict, string> = {
  safe: "Nothing flagged",
  suspicious: "Be careful",
  dangerous: "Dangerous",
};

// 270° speedometer-style arc. Geometry: full circumference, but we draw only
// 75% of it and rotate so the 90° gap sits centered at the bottom.
const R = 78;
const STROKE = 16;
const C = 2 * Math.PI * R;
const ARC = C * 0.75;

export function RiskGauge({ score, verdict }: Props) {
  const [shown, setShown] = useState(0);
  const raf = useRef<number>();

  // Count the number up to the real score, respecting reduced-motion.
  useEffect(() => {
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) {
      setShown(score);
      return;
    }
    const start = performance.now();
    const duration = 900;
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - t, 3); // easeOutCubic
      setShown(Math.round(eased * score));
      if (t < 1) raf.current = requestAnimationFrame(tick);
    };
    raf.current = requestAnimationFrame(tick);
    return () => {
      if (raf.current) cancelAnimationFrame(raf.current);
    };
  }, [score]);

  // Drive the arc from the animated number so the sweep and count-up stay in sync.
  const pct = Math.max(0, Math.min(100, shown)) / 100;
  const offset = ARC * (1 - pct);

  return (
    <div className="gauge" data-verdict={verdict}>
      <svg viewBox="0 0 200 200" className="gauge__svg" role="img"
           aria-label={`Risk score ${score} out of 100`}>
        <g transform="rotate(135 100 100)">
          <circle
            className="gauge__track"
            cx="100" cy="100" r={R}
            strokeWidth={STROKE}
            strokeDasharray={`${ARC} ${C}`}
            strokeLinecap="round"
          />
          <circle
            className="gauge__value"
            cx="100" cy="100" r={R}
            strokeWidth={STROKE}
            strokeDasharray={`${ARC} ${C}`}
            strokeDashoffset={offset}
            strokeLinecap="round"
          />
        </g>
      </svg>
      <div className="gauge__center">
        <span className="gauge__number">{shown}</span>
        <span className="gauge__scale">risk / 100</span>
        <span className="gauge__word">{VERDICT_WORD[verdict]}</span>
      </div>
    </div>
  );
}
