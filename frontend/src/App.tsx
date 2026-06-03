import { useState } from "react";
import { UrlInput } from "./components/UrlInput";
import { VerdictCard } from "./components/VerdictCard";
import { FindingsList } from "./components/FindingsList";
import { SourcesNote } from "./components/SourcesNote";
import { CheckingState } from "./components/CheckingState";
import { ShieldCheck } from "./components/icons";
import { ApiError, checkUrl } from "./lib/api";
import type { CheckResponse } from "./lib/types";

export function App() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<CheckResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleCheck(url: string) {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      setResult(await checkUrl({ url }));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Something went wrong. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="page" data-verdict={result ? result.verdict : "none"}>
      <div className="page__glow" aria-hidden="true" />
      <main className="app">
        <header className="masthead">
          <div className="masthead__brand">
            <ShieldCheck width={26} height={26} aria-hidden="true" />
            <span>ScamCheck</span>
          </div>
          <h1 className="masthead__title">Is this link safe?</h1>
          <p className="masthead__lede">
            Paste a suspicious link and get a clear, plain-language answer —
            checked against multiple security sources in seconds.
          </p>
          <p className="masthead__trust">Free · No account needed · We never open the link for you</p>
        </header>

        <UrlInput onCheck={handleCheck} loading={loading} />

        {error && (
          <p className="app__error" role="alert">
            {error}
          </p>
        )}

        {loading && <CheckingState />}

        {!loading && result && (
          <section className="result" key={result.input_url + result.score}>
            <VerdictCard result={result} />
            <h2 className="result__heading">Why we say this</h2>
            <FindingsList findings={result.findings} />
            <SourcesNote result={result} />
          </section>
        )}

        <footer className="colophon">
          <p>
            ScamCheck analyses links — it never visits them on your behalf.
            A “safe” result means no known threats were found, not a guarantee.
          </p>
        </footer>
      </main>
    </div>
  );
}
