import { cancellation, RequestError } from "./request-error";

interface Waiting {
  grant(): void;
  reject(error: RequestError): void;
}

export interface CapacityMetrics {
  active: number;
  queued: number;
  completed: number;
  rejected: number;
  failed: number;
  queue_wait_ms_total: number;
  inference_ms_total: number;
}

export class Capacity {
  private active = 0;
  private readonly waiting: Waiting[] = [];
  private readonly idle: (() => void)[] = [];
  private draining = false;
  private completed = 0;
  private rejected = 0;
  private failed = 0;
  private queueWaitMs = 0;
  private inferenceMs = 0;
  private readonly limit: number;
  private readonly maxQueue: number;
  private readonly timeoutMs: number;

  constructor(limit: number, maxQueue: number, timeoutMs: number) {
    if (
      !Number.isSafeInteger(limit) ||
      limit < 1 ||
      !Number.isSafeInteger(maxQueue) ||
      maxQueue < 0 ||
      !Number.isSafeInteger(timeoutMs) ||
      timeoutMs < 1
    ) {
      throw new Error("Invalid private server capacity");
    }
    this.limit = limit;
    this.maxQueue = maxQueue;
    this.timeoutMs = timeoutMs;
  }

  snapshot(): CapacityMetrics {
    return {
      active: this.active,
      queued: this.waiting.length,
      completed: this.completed,
      rejected: this.rejected,
      failed: this.failed,
      queue_wait_ms_total: Math.round(this.queueWaitMs),
      inference_ms_total: Math.round(this.inferenceMs),
    };
  }

  finish(success: boolean, elapsedMs: number): void {
    if (success) {
      this.completed++;
    } else {
      this.failed++;
    }
    this.inferenceMs += elapsedMs;
  }

  async acquire(signal: AbortSignal): Promise<() => void> {
    const started = performance.now();
    try {
      if (signal.aborted) {
        throw cancellation(signal);
      }
      if (this.draining) {
        throw new RequestError(503, "server_draining");
      }
      if (this.active < this.limit) {
        this.active++;
      } else {
        if (this.waiting.length >= this.maxQueue) {
          throw new RequestError(503, "server_busy");
        }
        await this.enqueue(signal);
      }
    } catch (error) {
      this.rejected++;
      throw error;
    } finally {
      this.queueWaitMs += performance.now() - started;
    }
    let released = false;
    return () => {
      if (!released) {
        released = true;
        this.release();
      }
    };
  }

  async drain(): Promise<void> {
    this.draining = true;
    for (const waiting of [...this.waiting]) {
      waiting.reject(new RequestError(503, "server_draining"));
    }
    if (this.active > 0) {
      await new Promise<void>((resolve) => this.idle.push(resolve));
    }
  }

  private enqueue(signal: AbortSignal): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      const remove = (): void => {
        const index = this.waiting.indexOf(waiting);
        if (index >= 0) {
          this.waiting.splice(index, 1);
        }
        clearTimeout(timer);
        signal.removeEventListener("abort", cancel);
      };
      const waiting: Waiting = {
        grant: () => {
          remove();
          resolve();
        },
        reject: (error) => {
          remove();
          reject(error);
        },
      };
      const cancel = (): void => waiting.reject(cancellation(signal));
      const timer = setTimeout(
        () => waiting.reject(new RequestError(503, "queue_timeout")),
        this.timeoutMs
      );
      signal.addEventListener("abort", cancel, { once: true });
      this.waiting.push(waiting);
    });
  }

  private release(): void {
    const next = this.waiting[0];
    if (next) {
      next.grant();
    } else {
      this.active--;
    }
    if (this.active === 0) {
      for (const resolve of this.idle.splice(0)) {
        resolve();
      }
    }
  }
}
