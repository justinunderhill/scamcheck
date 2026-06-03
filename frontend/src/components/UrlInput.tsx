import { useState, type FormEvent } from "react";

interface Props {
  onCheck: (url: string) => void;
  loading: boolean;
}

export function UrlInput({ onCheck, loading }: Props) {
  const [value, setValue] = useState("");

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const url = value.trim();
    if (url && !loading) onCheck(url);
  }

  return (
    <form className="url-input" onSubmit={handleSubmit}>
      <label htmlFor="url" className="url-input__label">
        Paste a link to check
      </label>
      <div className="url-input__row">
        <input
          id="url"
          name="url"
          type="text"
          inputMode="url"
          autoComplete="off"
          autoCapitalize="none"
          spellCheck={false}
          className="url-input__field"
          placeholder="example.com/login"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          disabled={loading}
        />
        <button type="submit" className="url-input__button" disabled={loading || !value.trim()}>
          {loading ? "Checking…" : "Check link"}
        </button>
      </div>
      <p className="url-input__hint">
        We only look at the link — we never open it for you.
      </p>
    </form>
  );
}
