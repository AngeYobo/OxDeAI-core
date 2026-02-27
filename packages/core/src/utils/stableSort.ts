export function stableSort<T>(items: readonly T[], compare?: (a: T, b: T) => number): T[] {
  const withIndex = items.map((item, index) => ({ item, index }));
  withIndex.sort((a, b) => {
    const cmp = compare ? compare(a.item, b.item) : 0;
    if (cmp !== 0) return cmp;
    return a.index - b.index;
  });
  return withIndex.map((x) => x.item);
}

export function stableSortedKeys(record: Record<string, unknown>): string[] {
  return stableSort(Object.keys(record), (a, b) => (a < b ? -1 : a > b ? 1 : 0));
}
