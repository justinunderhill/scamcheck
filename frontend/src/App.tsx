import { useEffect, useRef, useState } from "react";
import { UrlInput } from "./components/UrlInput";
import { VerdictCard } from "./components/VerdictCard";
import { FindingsList } from "./components/FindingsList";
import { SourcesNote } from "./components/SourcesNote";
import { NextSteps } from "./components/NextSteps";
import { CheckingState } from "./components/CheckingState";
import { Refresh, ShieldCheck } from "./components/icons";
import { ApiError, checkUrl, readScreenshot } from "./lib/api";
import { prepareScreenshot } from "./lib/screenshot";
import type { CheckResponse } from "./lib/types";

export function App() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<CheckResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  // What the in-flight check covers, so the progress steps match it.
  const [checking, setChecking] = useState({ hasLink: true, hasMessage: false });
  // Set while a check that started from a screenshot is running.
  const [screenshot, setScreenshot] = useState<"reading" | "read" | undefined>();
  // Bumping the key remounts UrlInput; `prefill` seeds it (empty clears it).
  const [formKey, setFormKey] = useState(0);
  const [prefill, setPrefill] = useState({ url: "", message: "" });
  const resultRef = useRef<HTMLElement>(null);

  // Bring a fresh result into view (the form above it can be tall on mobile).
  useEffect(() => {
    if (result) resultRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [result]);

  function begin() {
    setLoading(true);
    setError(null);
    setResult(null);
  }

  function fail(e: unknown) {
    setError(e instanceof ApiError ? e.message : "Something went wrong. Please try again.");
  }

  async function runCheck(url?: string, message?: string) {
    setChecking({ hasLink: Boolean(url), hasMessage: Boolean(message) });
    setResult(await checkUrl({ url, message }));
  }

  async function handleCheck(url?: string, message?: string) {
    begin();
    setScreenshot(undefined);
    try {
      await runCheck(url, message);
    } catch (e) {
      fail(e);
    } finally {
      setLoading(false);
    }
  }

  // Read the screenshot, show what was read in the boxes, then check it straight
  // away. One continuous loading state covers both steps.
  async function handleScreenshot(file: File) {
    begin();
    setScreenshot("reading");
    try {
      const read = await readScreenshot(await prepareScreenshot(file));
      const url = read.url ?? undefined;
      const message = read.message ?? undefined;
      setPrefill({ url: url ?? "", message: message ?? "" });
      setFormKey((k) => k + 1);
      setScreenshot("read");
      await runCheck(url, message);
    } catch (e) {
      fail(e);
    } finally {
      setLoading(false);
      setScreenshot(undefined);
    }
  }

  function startOver() {
    setResult(null);
    setError(null);
    setPrefill({ url: "", message: "" });
    setFormKey((k) => k + 1);
    window.scrollTo({ top: 0, behavior: "smooth" });
    // Wait for the remount before focusing the fresh input.
    setTimeout(() => document.getElementById("url")?.focus(), 50);
  }

  const canReset = !loading && (result !== null || error !== null);

  return (
    <div className="page" data-verdict={result ? result.verdict : "none"}>
      <div className="page__glow" aria-hidden="true" />

      <nav className="topbar">
        <button type="button" className="topbar__brand" onClick={startOver} aria-label="ScamCheck home">
          <ShieldCheck width={24} height={24} aria-hidden="true" />
          <span>ScamCheck</span>
        </button>
        {canReset && (
          <button type="button" className="btn btn--ghost" onClick={startOver}>
            <Refresh width={17} height={17} aria-hidden="true" />
            New check
          </button>
        )}
      </nav>

      <main className="app">
        <header className="masthead">
          <h1 className="masthead__title">Is this link safe?</h1>
          <p className="masthead__lede">
            Paste a suspicious link or message, or upload a screenshot, and get a
            clear, plain-language answer, checked against multiple security sources.
          </p>
          <p className="masthead__trust">Free · No account needed · We never open the link for you</p>
        </header>

        <UrlInput
          key={formKey}
          onCheck={handleCheck}
          onScreenshot={handleScreenshot}
          loading={loading}
          initialUrl={prefill.url}
          initialMessage={prefill.message}
        />

        {error && (
          <div className="app__error" role="alert">
            <p>{error}</p>
            <button type="button" className="btn btn--ghost" onClick={startOver}>
              <Refresh width={17} height={17} aria-hidden="true" />
              Start over
            </button>
          </div>
        )}

        {loading && <CheckingState {...checking} screenshot={screenshot} />}

        {!loading && result && (
          <section className="result" ref={resultRef} key={(result.input_url ?? "message") + result.score}>
            <VerdictCard result={result} />
            <NextSteps verdict={result.verdict} messageOnly={!result.final_url} />
            <h2 className="result__heading">Why we say this</h2>
            <FindingsList findings={result.findings} />
            <SourcesNote result={result} />
            <div className="result__again">
              <button type="button" className="btn btn--primary" onClick={startOver}>
                <Refresh width={18} height={18} aria-hidden="true" />
                Check something else
              </button>
            </div>
          </section>
        )}

        <footer className="colophon">
          <p>
            ScamCheck analyses links — it never visits them on your behalf.
            A “safe” result means no known threats were found, not a guarantee.
          </p>
          <p className="colophon__credit">
            I hope this helps someone —{" "}
            <a href="https://www.justinunderhill.com/" target="_blank" rel="noopener noreferrer">
              Justin Underhill
            </a>
          </p>
        </footer>
      </main>
    </div>
  );
}
