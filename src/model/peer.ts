/** Imports the optional peer dependency. A module of its own so tests can replace it. */
export function importPeer(): Promise<unknown> {
  return import("@huggingface/transformers");
}
