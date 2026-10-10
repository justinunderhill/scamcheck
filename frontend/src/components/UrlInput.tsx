import { useRef, useState, type ClipboardEvent, type DragEvent, type FormEvent } from "react";
import { ArrowRight, Close, ImageUp, Search } from "./icons";

interface Props {
  onCheck: (url?: string, message?: string) => void;
  onScreenshot: (file: File) => void;
  loading: boolean;
  // Pre-filled after a screenshot is read, so the user sees what we checked.
  initialUrl?: string;
  initialMessage?: string;
}

const EXAMPLES = [
  { label: "A safe site", url: "https://github.com" },
  { label: "A known scam (Google test)", url: "http://testsafebrowsing.appspot.com/s/phishing.html" },
  { label: "A lookalike", url: "https://royalmail-redelivery-fee.online/pay" },
];

function imageFrom(items: DataTransferItemList | null | undefined): File | null {
  for (const item of Array.from(items ?? [])) {
    if (item.kind === "file" && item.type.startsWith("image/")) return item.getAsFile();
  }
  return null;
}

export function UrlInput({ onCheck, onScreenshot, loading, initialUrl = "", initialMessage = "" }: Props) {
  const [value, setValue] = useState(initialUrl);
  const [message, setMessage] = useState(initialMessage);
  const [dragging, setDragging] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const canSubmit = !loading && Boolean(value.trim() || message.trim());

  function submit(url: string, msg?: string) {
    const trimmed = url.trim();
    const trimmedMsg = (msg ?? "").trim();
    if ((trimmed || trimmedMsg) && !loading) onCheck(trimmed || undefined, trimmedMsg || undefined);
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    submit(value, message);
  }

  function takeFile(file: File | null | undefined) {
    if (file && !loading) onScreenshot(file);
  }

  // Pasting a copied screenshot anywhere in the form reads it. Text pastes are
  // left alone.
  function handlePaste(e: ClipboardEvent) {
    const file = imageFrom(e.clipboardData?.items);
    if (file) {
      e.preventDefault();
      takeFile(file);
    }
  }

  function handleDrop(e: DragEvent) {
    e.preventDefault();
    setDragging(false);
    takeFile(e.dataTransfer.files?.[0]);
  }

  return (
    <div
      className="url-input panel"
      data-dragging={dragging || undefined}
      onDragOver={(e) => {
        if (Array.from(e.dataTransfer.types).includes("Files")) {
          e.preventDefault();
          setDragging(true);
        }
      }}
      onDragLeave={(e) => {
        if (!e.currentTarget.contains(e.relatedTarget as Node | null)) setDragging(false);
      }}
      onDrop={handleDrop}
    >
      <form onSubmit={handleSubmit} onPaste={handlePaste}>
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
          {value && !loading && (
            <button
              type="button"
              className="url-input__clear"
              aria-label="Clear link"
              onClick={() => {
                setValue("");
                document.getElementById("url")?.focus();
              }}
            >
              <Close width={18} height={18} aria-hidden="true" />
            </button>
          )}
          <button type="submit" className="url-input__button" disabled={!canSubmit}>
            <span>{loading ? "Checking…" : "Check"}</span>
            {!loading && <ArrowRight width={18} height={18} aria-hidden="true" />}
          </button>
        </div>

        <label htmlFor="message" className="url-input__message-label">
          Got it in a text, email, or DM? Paste the whole message too, and we’ll
          check the wording for scam tactics. No link? The message on its own is fine.
        </label>
        <textarea
          id="message"
          name="message"
          className="url-input__message"
          rows={3}
          placeholder="e.g. “Royal Mail: your parcel is held pending a £1.99 fee. Pay within 24 hours to avoid return: …”"
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          disabled={loading}
        />

        <div className="url-input__upload">
          <button
            type="button"
            className="btn btn--ghost url-input__upload-button"
            onClick={() => fileRef.current?.click()}
            disabled={loading}
          >
            <ImageUp width={19} height={19} aria-hidden="true" />
            Or upload a screenshot
          </button>
          <span className="url-input__upload-note">
            We read the text and check it. Your screenshot isn’t saved.
          </span>
          <input
            ref={fileRef}
            type="file"
            accept="image/*"
            hidden
            onChange={(e) => {
              takeFile(e.target.files?.[0]);
              e.target.value = ""; // allow choosing the same file again
            }}
          />
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
