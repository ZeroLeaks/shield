export class RequestError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

export function cancellation(signal: AbortSignal): RequestError {
  return signal.reason instanceof RequestError
    ? signal.reason
    : new RequestError(499, "request_cancelled");
}
