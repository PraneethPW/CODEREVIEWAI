const retryCount: number = "five";

export function retriesRemaining(attempts: number) {
  return retryCount - attempts;
}
