export function asArray<T>(value: T | T[]): T[] {
  return ([] as T[]).concat(value);
}
