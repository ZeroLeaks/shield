interface Waiting {
  grant(): void;
  cancel(): void;
}

/** One native CPU batch at a time within a reserved execution lane. */
export class InferenceGate {
  private active = false;
  private readonly waiting: Waiting[] = [];

  acquire(signal?: AbortSignal): Promise<() => void> {
    return new Promise((resolve, reject) => {
      if (signal?.aborted) {
        reject(signal.reason);
        return;
      }
      const waiting: Waiting = {
        grant: () => {
          signal?.removeEventListener("abort", waiting.cancel);
          this.active = true;
          let released = false;
          resolve(() => {
            if (released) {
              return;
            }
            released = true;
            this.active = false;
            this.waiting.shift()?.grant();
          });
        },
        cancel: () => {
          const index = this.waiting.indexOf(waiting);
          if (index >= 0) {
            this.waiting.splice(index, 1);
          }
          signal?.removeEventListener("abort", waiting.cancel);
          reject(signal?.reason);
        },
      };
      if (this.active) {
        this.waiting.push(waiting);
        signal?.addEventListener("abort", waiting.cancel, { once: true });
      } else {
        waiting.grant();
      }
    });
  }
}
