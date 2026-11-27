// Copyright (c) 2026 Clark Rawlins
// SPDX-License-Identifier: Apache-2.0

// Loaded by mocha before ioredis's own functional tests in the client-suite
// run (services/redis/docker/clients/run.sh). It points ioredis's defaults
// at the Kythira cluster, with the credentials Kythira requires (ioredis's
// tests construct `new Redis()` and expect an open localhost:6379), and
// skips every test that ioredis.txt does not list.

import { readFileSync } from "fs";
import { DEFAULT_REDIS_OPTIONS } from "../../lib/redis/RedisOptions";

const env = process.env;
DEFAULT_REDIS_OPTIONS.host = env.KYTHIRA_REDIS_HOST || "localhost";
DEFAULT_REDIS_OPTIONS.port = Number(env.KYTHIRA_REDIS_PORT || 6379);
DEFAULT_REDIS_OPTIONS.username = env.KYTHIRA_REDIS_USER;
DEFAULT_REDIS_OPTIONS.password = env.KYTHIRA_REDIS_PASSWORD;

const list = env.KYTHIRA_IOREDIS_TESTS;
const selected = list
  ? new Set(
      readFileSync(list, "utf8")
        .split("\n")
        .map((l) => l.trim())
        .filter((l) => l && !l.startsWith("#"))
    )
  : null;

beforeEach(function () {
  const title = this.currentTest ? this.currentTest.fullTitle() : "";
  if (selected && !selected.has(title)) {
    this.skip();
  }
});
