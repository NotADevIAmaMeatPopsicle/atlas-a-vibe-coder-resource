export interface AppConfig {
  port: number;
  apiToken: string | undefined;
}

export function readConfig(): AppConfig {
  return {
    port: Number(process.env.APP_PORT ?? "3000"),
    apiToken: process.env.ATLAS_API_TOKEN,
  };
}
