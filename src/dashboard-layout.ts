export type DashboardLayout = {
  columns: number;
  rows: number;
  pageSize: number;
};

export type DashboardPage<T> = {
  page: number;
  pageCount: number;
  start: number;
  end: number;
  items: T[];
};

const clamp = (value: number, minimum: number, maximum: number): number =>
  Math.min(maximum, Math.max(minimum, value));

export function dashboardLayout(viewportWidth: number, viewportHeight: number, sidebarCollapsed: boolean): DashboardLayout {
  const sidebarWidth = sidebarCollapsed ? 64 : viewportWidth <= 1120 ? 190 : 218;
  const usableWidth = Math.max(0, viewportWidth - sidebarWidth - 36);
  const columns = clamp(Math.floor((usableWidth + 12) / 352), 1, 3);
  const usableHeight = Math.max(0, viewportHeight - 180);
  const rows = clamp(Math.floor((usableHeight + 12) / 282), 1, 3);

  return { columns, rows, pageSize: columns * rows };
}

export function dashboardPage<T>(items: readonly T[], requestedPage: number, requestedPageSize: number): DashboardPage<T> {
  const pageSize = Math.max(1, Math.floor(Number.isFinite(requestedPageSize) ? requestedPageSize : 1));
  const pageCount = Math.max(1, Math.ceil(items.length / pageSize));
  const page = clamp(Math.floor(Number.isFinite(requestedPage) ? requestedPage : 0), 0, pageCount - 1);
  const start = page * pageSize;
  const end = Math.min(start + pageSize, items.length);

  return { page, pageCount, start, end, items: items.slice(start, end) };
}
