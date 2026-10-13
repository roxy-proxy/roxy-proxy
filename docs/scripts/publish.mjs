// Publishes a docs build into a checkout of the gh-pages branch, which holds
// the whole Pages site: main at the root and each release under vX.Y/. The
// Docs workflow runs it from docs/ as
// `node scripts/publish.mjs <ref-type> <ref-name> <site-dir>`, then pushes
// the checkout and deploys it.

import { execFileSync } from "node:child_process";
import { appendFileSync, cpSync, readdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

export const siteUrl = "https://roxy-proxy.github.io/roxy-proxy";

const versionDir = /^v(\d+)\.(\d+)$/;

// Where a ref's docs live on the site, relative to its root: "" for main,
// "vX.Y" for a release tag vX.Y.Z, null for anything else (a pre-release
// tag such as v0.2.0-rc.1 is not published).
export function releaseDir(refType, refName) {
  if (refType === "branch" && refName === "main") return "";
  const m = refType === "tag" && refName.match(/^v(\d+)\.(\d+)\.\d+$/);
  return m ? `v${m[1]}.${m[2]}` : null;
}

// Release directory names, newest first.
export function sortVersions(names) {
  return [...names].sort((a, b) => {
    const [, aMajor, aMinor] = a.match(versionDir).map(Number);
    const [, bMajor, bMinor] = b.match(versionDir).map(Number);
    return bMajor - aMajor || bMinor - aMinor;
  });
}

// The release directories in a site checkout, newest first.
export function publishedVersions(siteDir) {
  return sortVersions(
    readdirSync(siteDir, { withFileTypes: true })
      .filter((e) => e.isDirectory() && versionDir.test(e.name))
      .map((e) => e.name),
  );
}

// Replaces one version's pages in the site checkout with a build. At the
// root everything but the release directories (and .git) is replaced, so a
// page removed from main disappears while the releases stay.
export function sync(buildDir, siteDir, dir) {
  const target = join(siteDir, dir);
  if (dir === "") {
    for (const e of readdirSync(siteDir, { withFileTypes: true })) {
      if (e.name === ".git" || (e.isDirectory() && versionDir.test(e.name))) continue;
      rmSync(join(siteDir, e.name), { recursive: true });
    }
  } else {
    rmSync(target, { recursive: true, force: true });
  }
  cpSync(buildDir, target, { recursive: true });
}

function main([refType, refName, siteDir]) {
  const output = (line) => process.env.GITHUB_OUTPUT && appendFileSync(process.env.GITHUB_OUTPUT, `${line}\n`);
  const dir = releaseDir(refType, refName);
  if (dir === null) {
    console.log(`${refType} ${refName} is not published`);
    output("published=false");
    return;
  }
  const docs = fileURLToPath(new URL("..", import.meta.url));
  const versions = sortVersions(new Set([...publishedVersions(siteDir), dir].filter(Boolean)));
  const base = new URL(siteUrl).pathname;
  const env = {
    ...process.env,
    ROXY_DOCS_BASE: dir ? `${base}/${dir}` : base,
    ROXY_DOCS_VERSION: dir || "edge",
    ROXY_DOCS_VERSIONS: versions.join(" "),
  };
  console.log(`building ${env.ROXY_DOCS_VERSION} at ${env.ROXY_DOCS_BASE}; versions: ${env.ROXY_DOCS_VERSIONS}`);
  execFileSync("npm", ["run", "build"], { cwd: docs, env, stdio: "inherit" });
  sync(join(docs, "dist", "public"), siteDir, dir);
  output("published=true");
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main(process.argv.slice(2));
