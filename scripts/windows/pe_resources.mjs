import fs from "node:fs";
import { NtExecutable, NtExecutableResource } from "pe-library";

const RESOURCE_TYPE = "INTEGRITY";
const RESOURCE_ID = "ELECTRONASAR";

function isMatch(value, expected) {
  return typeof value === "string" && value.toUpperCase() === expected;
}

function bufferFromArrayBuffer(value) {
  return Buffer.from(new Uint8Array(value));
}

function parsePayload(buffer) {
  const utf8 = buffer.toString("utf8").replace(/\u0000+$/u, "");
  let parsed = null;
  let parseError = null;
  try {
    parsed = JSON.parse(utf8);
  } catch (error) {
    parseError = String(error);
  }
  return { utf8, parsed, parse_error: parseError };
}

function openResources(path) {
  const executable = NtExecutable.from(fs.readFileSync(path), { ignoreCert: true });
  return {
    executable,
    resources: NtExecutableResource.from(executable, true),
  };
}

function describeEntry(entry, index) {
  const payload = parsePayload(bufferFromArrayBuffer(entry.bin));
  return {
    index,
    type: entry.type,
    id: entry.id,
    lang: entry.lang,
    codepage: entry.codepage,
    ...payload,
  };
}

function matchingEntries(resources) {
  return resources.entries
    .map((entry, index) => ({ entry, index }))
    .filter(({ entry }) => isMatch(entry.type, RESOURCE_TYPE) && isMatch(entry.id, RESOURCE_ID));
}

function read(path) {
  const { resources } = openResources(path);
  const matches = matchingEntries(resources);
  return {
    resource_entry_count: resources.entries.length,
    resources: matches.map(({ entry, index }) => describeEntry(entry, index)),
  };
}

function exactArrayBuffer(value) {
  return Uint8Array.from(Buffer.from(value, "utf8")).buffer;
}

function update(path, payload) {
  const { executable, resources } = openResources(path);
  const matches = matchingEntries(resources);
  if (matches.length === 0) {
    throw new Error("INTEGRITY/ELECTRONASAR resource is absent");
  }
  for (const { entry } of matches) {
    resources.replaceResourceEntry({
      type: entry.type,
      id: entry.id,
      lang: entry.lang,
      codepage: entry.codepage,
      bin: exactArrayBuffer(payload),
    });
  }
  resources.outputResource(executable);
  fs.writeFileSync(path, Buffer.from(executable.generate()));
  return read(path);
}

function fixture(path, payload) {
  const executable = NtExecutable.createEmpty(false, false);
  const resources = NtExecutableResource.from(executable, true);
  resources.replaceResourceEntryFromString(RESOURCE_TYPE, RESOURCE_ID, 1033, payload);
  resources.outputResource(executable);
  fs.writeFileSync(path, Buffer.from(executable.generate()));
  return read(path);
}

const [command, path] = process.argv.slice(2);
if (!command || !path) {
  throw new Error("usage: pe_resources.mjs <read|update|fixture> <executable>");
}

let result;
if (command === "read") {
  result = read(path);
} else if (command === "update") {
  result = update(path, fs.readFileSync(0, "utf8"));
} else if (command === "fixture") {
  result = fixture(path, fs.readFileSync(0, "utf8"));
} else {
  throw new Error(`unknown command: ${command}`);
}
process.stdout.write(JSON.stringify(result) + "\n");
