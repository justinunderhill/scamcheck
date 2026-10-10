import type { Verdict } from "../lib/types";

// Plain-language actions per verdict. "safe" stays honest: nothing was found,
// which is not a guarantee — so it still nudges the user to stay careful.
const STEPS: Record<Verdict, { title: string; items: string[] }> = {
  dangerous: {
    title: "What to do now",
    items: [
      "Don’t open the link, and don’t enter passwords, card details or one-time PINs.",
      "Already clicked or typed something in? Change that password using the official app or website, and call your bank if you shared payment details.",
      "Delete the message, and warn anyone it may have been forwarded to.",
    ],
  },
  suspicious: {
    title: "Before you click",
    items: [
      "Contact the company directly using its official app or a number you already trust — not the one in the message.",
      "Never share one-time PINs or passwords, whatever the message says.",
      "If it pressures you to act fast, slow down. Real companies give you time.",
    ],
  },
  safe: {
    title: "Stay careful",
    items: [
      "Nothing flagged this link, but brand-new scams may not be known yet.",
      "Still check who sent it, and don’t share one-time PINs or passwords.",
    ],
  },
};

export function NextSteps({ verdict }: { verdict: Verdict }) {
  const { title, items } = STEPS[verdict];
  return (
    <section className="next-steps">
      <h2 className="next-steps__title">{title}</h2>
      <ul className="next-steps__list">
        {items.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>
    </section>
  );
}
