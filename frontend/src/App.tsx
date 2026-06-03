import { useState } from "react";
import { UrlInput } from "./components/UrlInput";
import { VerdictCard } from "./components/VerdictCard";
import { FindingsList } from "./components/FindingsList";
import { SourcesNote } from "./components/SourcesNote";
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
    <main className="app">
      <header className="app__header">
        <h1>ScamCheck</h1>
        <p>Paste a suspicious link and get a clear, plain-language safety check.</p>
      </header>

      <UrlInput onCheck={handleCheck} loading={loading} />

      {error && <p className="app__error" role="alert">{error}</p>}

      {result && (
        <section className="result">
          <VerdictCard result={result} />
          <h2 className="result__heading">Why we say this</h2>
          <FindingsList findings={result.findings} />
          <SourcesNote result={result} />
        </section>
      )}
    </main>
  );
}
