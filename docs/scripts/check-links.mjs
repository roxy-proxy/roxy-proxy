// Checks every link to a docs page, from the pages themselves and from the
// rest of the repository: the page must exist, and so must the heading an
// anchor names. A link to a static file must name a file in public/. Run from docs/: `npm run check-links`.

import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import GithubSlugger from "github-slugger";

const docs = fileURLToPath(new URL("..", import.meta.url));
const pagesDir = join(docs, "pages");
const repo = join(docs, "..");
const site = "https://roxy-proxy.github.io/roxy-proxy";

function walk(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? walk(path) : [path];
  });
}

// Route -> the anchors its headings produce.
const anchors = new Map();
for (const file of walk(pagesDir).filter((f) => /\.mdx?$/.test(f))) {
  const route = "/" + relative(pagesDir, file).replace(/\.mdx?$/, "").replace(/(^|\/)index$/, "");
  const slugger = new GithubSlugger();
  const set = new Set();
  let code = false;
  for (const line of readFileSync(file, "utf8").split("\n")) {
    if (line.startsWith("```")) code = !code;
    const m = !code && line.match(/^#{1,6} (.*)$/);
    if (m) set.add(slugger.slug(m[1].replace(/[`*]/g, "")));
  }
  anchors.set(route.replace(/\/$/, "") || "/", set);
}

const errors = [];
function check(source, link) {
  const [path, anchor] = link.split("#");
  // A path with an extension is a static file from public/, not a page.
  if (/\.[a-z0-9]+$/i.test(path)) {
    if (!existsSync(join(docs, "public", path))) errors.push(`${source}: ${link}: no such file in public/`);
    return;
  }
  const route = path.replace(/\/$/, "") || "/";
  const set = anchors.get(route);
  if (!set) errors.push(`${source}: ${link}: no such page`);
  else if (anchor && !set.has(anchor)) errors.push(`${source}: ${link}: no heading #${anchor}`);
}

for (const file of walk(pagesDir).filter((f) => /\.mdx?$/.test(f))) {
  const text = readFileSync(file, "utf8");
  for (const [, link] of text.matchAll(/\]\((\/[^)\s]*)\)/g)) check(relative(repo, file), link);
}

const tracked = execFileSync("git", ["-C", repo, "grep", "-lF", site, "--", ":!docs"], { encoding: "utf8" })
  .split("\n")
  .filter(Boolean);
for (const file of tracked) {
  const text = readFileSync(join(repo, file), "utf8");
  const escaped = site.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
  for (const [, link] of text.matchAll(new RegExp(`${escaped}(/[^)\\s"'>]*)?`, "g"))) check(file, link ?? "/");
}

if (errors.length) {
  console.error(errors.join("\n"));
  process.exit(1);
}
console.log(`links ok: ${anchors.size} pages`);
