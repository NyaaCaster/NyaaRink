/** Only an explicit whole-word YES confirms a locally described action. */
export function acceptsConfirmation(answer: string): boolean {
  return answer.trim().toUpperCase() === 'YES';
}
