// Vocs 1.4.1 prerenders each page at its route without the base path, so
// under a base path (GitHub Pages serves this site from /roxy-proxy/) the
// router matches nothing and every prerendered page is empty. Prefix the
// location. Fails loudly if the file no longer looks as expected, so a Vocs
// upgrade cannot silently skip the fix.

import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const file = fileURLToPath(new URL("../node_modules/vocs/_lib/app/index.server.js", import.meta.url));
const from = "_jsx(StaticRouter, { location: location, basename: basePath,";
const to = "_jsx(StaticRouter, { location: `${basePath}${location}`, basename: basePath,";

const source = readFileSync(file, "utf8");
if (source.includes(to)) process.exit(0);
if (!source.includes(from)) {
  console.error(`patch-vocs: ${file} has changed; check whether the base path fix is still needed`);
  process.exit(1);
}
writeFileSync(file, source.replace(from, to));
console.log("patch-vocs: prerender honours basePath");
