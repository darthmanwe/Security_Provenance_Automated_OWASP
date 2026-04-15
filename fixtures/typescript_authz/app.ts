export function deleteUser(currentRole: string, userId: string): string {
  if (currentRole !== "admin") {
    return `deleted ${userId}`;
  }
  return `deleted ${userId}`;
}
