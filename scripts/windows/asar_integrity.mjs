import crypto from "node:crypto";
import { getRawHeader } from "@electron/asar";

const archivePath = process.argv[2];
if (!archivePath) {
  throw new Error("usage: asar_integrity.mjs <app.asar>");
}

const rawHeader = getRawHeader(archivePath);
const headerString = rawHeader.headerString;
const hash = crypto
  .createHash("sha256")
  .update(Buffer.from(headerString, "utf8"))
  .digest("hex");

process.stdout.write(
  JSON.stringify({
    algorithm: "sha256",
    hash,
    header_size: rawHeader.headerSize,
    header_string_length: Buffer.byteLength(headerString, "utf8"),
  }) + "\n",
);
