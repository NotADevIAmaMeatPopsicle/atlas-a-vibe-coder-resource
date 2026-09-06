import { readConfig } from "./config";
import { formatGreeting } from "./format.js";
import { missingInternal } from "./missing-internal";

export async function startApp(name: string): Promise<string> {
  const config = readConfig();
  const lazyModule = await import("./lazy");

  void missingInternal;
  return lazyModule.decorate(formatGreeting(name), config.port);
}
