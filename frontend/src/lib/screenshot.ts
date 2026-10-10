import { ApiError } from "./api";
import type { ScreenshotRequest } from "./types";

// Claude reads images at roughly 1.15 megapixels, so anything bigger only costs
// upload time. Capping total pixels (not the long edge) keeps tall phone
// screenshots legible. Re-encoding as JPEG also strips EXIF metadata such as
// location, and keeps the body well under Vercel's 4.5 MB request limit.
const MAX_PIXELS = 1_150_000;
const JPEG_QUALITY = 0.85;

/** Shrink and re-encode a picture in the browser, ready for POST /api/extract. */
export async function prepareScreenshot(file: File): Promise<ScreenshotRequest> {
  if (!file.type.startsWith("image/")) {
    throw new ApiError("That file isn't a picture. Please choose a screenshot.");
  }

  const image = await decode(file);
  const { width, height } = image;
  const scale = Math.min(1, Math.sqrt(MAX_PIXELS / (width * height)));
  const canvas = document.createElement("canvas");
  canvas.width = Math.max(1, Math.round(width * scale));
  canvas.height = Math.max(1, Math.round(height * scale));
  const ctx = canvas.getContext("2d");
  if (!ctx) throw new ApiError("We couldn't open that picture. Please try another screenshot.");
  // JPEG has no transparency: paint white first so transparent PNGs stay readable.
  ctx.fillStyle = "#fff";
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.drawImage(image, 0, 0, canvas.width, canvas.height);
  if ("close" in image) image.close();

  const blob = await new Promise<Blob | null>((resolve) =>
    canvas.toBlob(resolve, "image/jpeg", JPEG_QUALITY),
  );
  if (!blob) throw new ApiError("We couldn't open that picture. Please try another screenshot.");
  return { image: await toBase64(blob), media_type: "image/jpeg" };
}

async function decode(file: File): Promise<ImageBitmap | HTMLImageElement> {
  try {
    return await createImageBitmap(file);
  } catch {
    // Some browsers can't build a bitmap from every format; an <img> often can.
    const url = URL.createObjectURL(file);
    try {
      const img = new Image();
      img.src = url;
      await img.decode();
      return img;
    } catch {
      throw new ApiError("We couldn't open that picture. Please try a PNG or JPG screenshot.");
    } finally {
      URL.revokeObjectURL(url);
    }
  }
}

function toBase64(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result).split(",", 2)[1] ?? "");
    reader.onerror = () => reject(new ApiError("We couldn't open that picture. Please try another screenshot."));
    reader.readAsDataURL(blob);
  });
}
