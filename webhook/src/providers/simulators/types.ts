export interface UpstreamRequest {
  method: string;
  url: URL;
  /** Lower-case header names. */
  headers: Record<string, string>;
  body?: string;
}

export interface UpstreamResponse {
  status: number;
  /** Parsed JSON body. */
  body: unknown;
}

/** An in-process stand-in for an upstream API host, used in mock mode. */
export type Simulator = (req: UpstreamRequest) => Promise<UpstreamResponse>;
