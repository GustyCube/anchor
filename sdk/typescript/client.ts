export class AnchorProtocolHttpClient {
  private readonly baseUrl: string;
  private readonly fetchFn: typeof fetch;

  constructor(baseUrl: string, fetchFn: typeof fetch) {
    if (!baseUrl || baseUrl.trim().length === 0) {
      throw new Error("baseUrl is required");
    }
    if (!fetchFn) {
      throw new Error("fetchFn is required");
    }
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.fetchFn = fetchFn;
  }

  async postJSON(path: string, payload: unknown, expectedStatus: number): Promise<unknown> {
    const response = await this.fetchFn(`${this.baseUrl}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (response.status !== expectedStatus) {
      throw new Error(`Unexpected status (${response.status}): ${await response.text()}`);
    }
    return await response.json();
  }
}
