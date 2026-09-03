import assert from "node:assert/strict";
import { startApp } from "../src/app";

export async function testGreeting(): Promise<void> {
  const result = await startApp("test");
  assert.match(result, /^Hello, test on port /);
}
