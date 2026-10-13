import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { publishedVersions, releaseDir, sortVersions, sync } from "./publish.mjs";

test("releaseDir", () => {
  assert.equal(releaseDir("branch", "main"), "");
  assert.equal(releaseDir("tag", "v0.1.1"), "v0.1");
  assert.equal(releaseDir("tag", "v12.34.56"), "v12.34");
  assert.equal(releaseDir("tag", "v0.2.0-rc.1"), null);
  assert.equal(releaseDir("tag", "0.1.0"), null);
  assert.equal(releaseDir("tag", "v0.1"), null);
  assert.equal(releaseDir("branch", "v0.1.0"), null);
  assert.equal(releaseDir("branch", "feature"), null);
});

test("sortVersions orders numerically, newest first", () => {
  assert.deepEqual(sortVersions(["v0.9", "v1.2", "v0.10", "v1.0"]), ["v1.2", "v1.0", "v0.10", "v0.9"]);
});

function site(entries) {
  const dir = mkdtempSync(join(tmpdir(), "site-"));
  for (const e of entries) {
    if (e.endsWith("/")) mkdirSync(join(dir, e), { recursive: true });
    else writeFileSync(join(dir, e), e);
  }
  return dir;
}

test("publishedVersions lists only release directories", () => {
  const dir = site(["v0.9/", "v1.2/", "v2/", "v1.2.3/", "v1.0", "index.html", "guides/"]);
  assert.deepEqual(publishedVersions(dir), ["v1.2", "v0.9"]);
});

test("sync at the root replaces main but keeps releases", () => {
  const build = site(["index.html", "guides/"]);
  writeFileSync(join(build, "guides", "run.html"), "new");
  const dir = site([".git/", "index.html", "stale.html", "guides/", "v0.1/"]);
  writeFileSync(join(dir, "guides", "stale.html"), "old");
  writeFileSync(join(dir, "v0.1", "index.html"), "release");
  sync(build, dir, "");
  assert.deepEqual(readdirSync(dir).sort(), [".git", "guides", "index.html", "v0.1"]);
  assert.deepEqual(readdirSync(join(dir, "guides")), ["run.html"]);
  assert.deepEqual(readdirSync(join(dir, "v0.1")), ["index.html"]);
});

test("sync of a release replaces only its directory", () => {
  const build = site(["index.html"]);
  const dir = site(["index.html", "v0.1/", "v0.2/"]);
  writeFileSync(join(dir, "v0.1", "stale.html"), "old");
  sync(build, dir, "v0.1");
  assert.deepEqual(readdirSync(dir).sort(), ["index.html", "v0.1", "v0.2"]);
  assert.deepEqual(readdirSync(join(dir, "v0.1")), ["index.html"]);
});

test("sync creates a release directory that does not exist yet", () => {
  const build = site(["index.html"]);
  const dir = site(["index.html"]);
  sync(build, dir, "v0.3");
  assert.deepEqual(readdirSync(join(dir, "v0.3")), ["index.html"]);
});
