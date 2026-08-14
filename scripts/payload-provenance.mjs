export function payloadGeneratedAt({ sourceDirty, commitDate, now = new Date() }) {
  const selected = sourceDirty ? now : new Date(commitDate);
  if (!(selected instanceof Date) || Number.isNaN(selected.getTime())) {
    throw new Error("No se pudo derivar generatedAt para el payload.");
  }
  return selected.toISOString();
}
