import { useState, type FormEvent } from "react";
import { ArrowRight, Search } from "./icons";

interface Props {
  onCheck: (url: string) => void;
  loading: boolean;
}

const EXAMPLES = [
  { label: "A safe site", url: "https://github.com" },
  { label: "A known scam (Google test)", url: "http://testsafebrowsing.appspot.com/s/phishing.html" },
  { label: "A lookalike", url: "https://royalmail-redelivery-fee.online/pay" },
];

export function UrlInput({ onCheck, loading }: Props) {
  const [value, setValue] = useState("");

  function submit(url: string) {
    const trimmed = url.trim();
    if (trimmed && !loading) onCheck(trimmed);
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    submit(value);
  }

  return (
    <div className="url-input">
      <form onSubmit={handleSubmit}>
        <label htmlFor="url" className="url-input__label">
          Paste a link to check
        </label>
        <div className="url-input__field">
          <Search className="url-input__icon" width={22} height={22} aria-hidden="true" />
          <input
            id="url"
            name="url"
            type="text"
            inputMode="url"
            autoComplete="off"
            autoCapitalize="none"
            spellCheck={false}
            placeholder="example.com/login"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            disabled={loading}
          />
          <button type="submit" className="url-input__button" disabled={loading || !value.trim()}>
            <span>{loading ? "Checking…" : "Check"}</span>
            {!loading && <ArrowRight width={18} height={18} aria-hidden="true" />}
          </button>
        </div>
      </form>

      <div className="url-input__examples">
        <span className="url-input__examples-label">Try one:</span>
        {EXAMPLES.map((ex) => (
          <button
            key={ex.url}
            type="button"
            className="chip"
            disabled={loading}
            onClick={() => {
              setValue(ex.url);
              submit(ex.url);
            }}
          >
            {ex.label}
          </button>
        ))}
      </div>
    </div>
  );
}
