import type { Verdict } from "../lib/types";

type Steps = Record<Verdict, { title: string; items: string[] }>;

// Plain-language actions per verdict. "safe" stays honest: nothing was found,
// which is not a guarantee — so it still nudges the user to stay careful.
const STEPS: Steps = {
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

// A message with no link: the risk is replying, paying or sharing, not clicking.
const MESSAGE_STEPS: Steps = {
  dangerous: {
    title: "What to do now",
    items: [
      "Don’t reply, pay, or share any codes or personal details.",
      "Already paid or shared something? Call your bank straight away, using the number on your card.",
      "Block the sender, and warn anyone the message may have been sent to.",
    ],
  },
  suspicious: {
    title: "Before you reply",
    items: [
      "Don’t send money, codes or personal details until you’ve checked it’s real.",
      "Contact the person or company on a number you already know — not one in the message.",
      "If it pressures you to act fast, slow down. Real people and companies give you time.",
    ],
  },
  safe: STEPS.safe,
};

export function NextSteps({ verdict, messageOnly = false }: { verdict: Verdict; messageOnly?: boolean }) {
  const { title, items } = (messageOnly ? MESSAGE_STEPS : STEPS)[verdict];
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
