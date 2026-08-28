// Self-contained SVG chart primitives — no external libraries (the WebView2 CSP blocks remote
// scripts, exactly like an Artifact). Every helper returns an SVG *string* so it composes with the
// existing string-template rendering in main.ts. Colors come from CSS classes so the charts follow
// the light/dark theme; only geometry lives here.

export const CHART_W = 300;
export const CHART_H = 90;

export interface SeriesPoint {
  /// Monotonic x (typically epoch milliseconds); mapped linearly across the plot width.
  x: number;
  y: number;
}

export interface ThresholdBand {
  /// Band extent in y-value units (e.g. 75..90). Clamped to the chart's y-domain.
  from: number;
  to: number;
  className: string;
}

export interface AxisMarker {
  /// Vertical marker at this x (e.g. a quota reset boundary).
  x: number;
  className?: string;
  title?: string;
}

export interface LineChartOptions {
  points: SeriesPoint[];
  /// y-domain. Defaults to the data range, padded; pass explicit bounds for percent charts (0..100).
  yMin?: number;
  yMax?: number;
  bands?: ThresholdBand[];
  markers?: AxisMarker[];
  /// Optional forward projection (e.g. a burn-rate line to 100%): extends the x-domain to include
  /// this point and draws a dashed connector from the last datum to it, with a hollow target marker.
  projection?: { x: number; y: number; className?: string };
  area?: boolean;
  /// Extra class on the <svg> so callers can theme a series (e.g. balance vs usage).
  className?: string;
  ariaLabel: string;
  /// Formats the y of the trailing point for its hover title.
  valueFormat?: (y: number) => string;
}

/// Compact "month/day hour:minute" label, used for both the static axis ticks and the hover
/// tooltip — good enough resolution across all four history ranges (24h..90d) without the chart
/// needing to know which range produced its points.
function formatAxisTime(ms: number): string {
  return new Intl.DateTimeFormat(undefined, { month: "numeric", day: "numeric", hour: "2-digit", minute: "2-digit" }).format(
    ms,
  );
}

/// A responsive line (optionally area) chart. Renders at a fixed 300×90 viewBox and scales with
/// `width:100%` in CSS, so circles and strokes stay undistorted (unlike non-uniform stretching).
/// Always draws min/max axis labels plus a hidden hover crosshair/tooltip that main.ts's delegated
/// mousemove handler shows and repositions using the `data-hover-points` hit-test data below —
/// charts.ts only ever emits markup and geometry, never wires events itself.
export function lineChart(options: LineChartOptions): string {
  const { points, bands = [], markers = [], area = false, className = "", ariaLabel, valueFormat } = options;
  if (points.length === 0) return "";

  const projection = options.projection;
  const xs = points.map((point) => point.x);
  const ys = points.map((point) => point.y);
  // The projected target participates in the domain so the dashed connector stays inside the frame.
  const domainX = projection ? [...xs, projection.x] : xs;
  const domainY = projection ? [...ys, projection.y] : ys;
  const xMin = Math.min(...domainX);
  const xMax = Math.max(...domainX);
  const dataMin = Math.min(...domainY);
  const dataMax = Math.max(...domainY);
  // Default y-domain hugs the data with a little headroom; an explicit domain (percent charts) wins.
  const yMin = options.yMin ?? (dataMin === dataMax ? dataMin - 1 : dataMin - (dataMax - dataMin) * 0.1);
  const yMax = options.yMax ?? (dataMin === dataMax ? dataMax + 1 : dataMax + (dataMax - dataMin) * 0.1);
  const formatY = (y: number): string => (valueFormat ? valueFormat(y) : `${Math.round(y)}`);

  const pad = 6;
  // Sized from the actual min/max label text (percent labels are short; currency labels vary a lot,
  // e.g. "$51.80" vs "$1,234.56") rather than a fixed guess, so long labels widen the gutter instead
  // of clipping against the left edge — the chart area shrinks a little instead of the text.
  const longestYLabel = Math.max(formatY(yMax).length, formatY(yMin).length);
  const yGutter = Math.max(20, longestYLabel * 4.5 + 6);
  const xGutter = 11; // room for the first/last time labels along the bottom edge
  const left = pad + yGutter;
  const right = CHART_W - pad;
  const top = pad;
  const bottom = CHART_H - pad - xGutter;

  const xAt = (x: number): number =>
    xMax === xMin ? (left + right) / 2 : left + ((x - xMin) / (xMax - xMin)) * (right - left);
  const yAt = (y: number): number => {
    const clamped = Math.max(yMin, Math.min(yMax, y));
    return yMax === yMin ? (top + bottom) / 2 : bottom - ((clamped - yMin) / (yMax - yMin)) * (bottom - top);
  };

  const bandRects = bands
    .map((band) => {
      const yTop = yAt(Math.max(band.from, band.to));
      const yBottom = yAt(Math.min(band.from, band.to));
      const height = Math.max(0, yBottom - yTop);
      if (height <= 0) return "";
      return `<rect class="${band.className}" x="${left}" y="${yTop.toFixed(1)}" width="${right - left}" height="${height.toFixed(1)}" />`;
    })
    .join("");
  // Threshold bands already give the percent chart a horizontal reference; a chart with no bands
  // (balance) gets one faint midline instead so there's still something to read the curve against.
  const midGrid =
    bands.length === 0
      ? `<line class="chart-grid" x1="${left}" y1="${yAt((yMin + yMax) / 2).toFixed(1)}" x2="${right}" y2="${yAt((yMin + yMax) / 2).toFixed(1)}" />`
      : "";

  const markerLines = markers
    .map((marker) => {
      if (marker.x < xMin || marker.x > xMax) return "";
      const x = xAt(marker.x).toFixed(1);
      const title = marker.title ? `<title>${escapeText(marker.title)}</title>` : "";
      return `<line class="chart-marker ${marker.className ?? ""}" x1="${x}" y1="${top}" x2="${x}" y2="${bottom}">${title}</line>`;
    })
    .join("");

  const coords = points.map((point) => `${xAt(point.x).toFixed(1)},${yAt(point.y).toFixed(1)}`);
  const last = points[points.length - 1];
  const lastX = xAt(last.x).toFixed(1);
  const lastY = yAt(last.y).toFixed(1);

  const areaPath =
    area && points.length > 1
      ? `<polygon class="chart-area" points="${left},${bottom} ${coords.join(" ")} ${right},${bottom}" />`
      : "";
  const line =
    points.length > 1 ? `<polyline class="chart-line" fill="none" points="${coords.join(" ")}" />` : "";
  const dotTitle = valueFormat ? `<title>${escapeText(valueFormat(last.y))}</title>` : "";
  const dot = `<circle class="chart-dot" cx="${lastX}" cy="${lastY}" r="2.6">${dotTitle}</circle>`;

  const projectionShape = projection
    ? `<line class="chart-projection ${projection.className ?? ""}" x1="${lastX}" y1="${lastY}" x2="${xAt(projection.x).toFixed(1)}" y2="${yAt(projection.y).toFixed(1)}" /><circle class="chart-projection-dot ${projection.className ?? ""}" cx="${xAt(projection.x).toFixed(1)}" cy="${yAt(projection.y).toFixed(1)}" r="2.6" fill="none" />`
    : "";

  // The only always-visible numbers on the chart: min/max on the left, first/last time on the
  // bottom. Anchors flip (start/end) at each edge so the labels never run outside the viewBox.
  const yAxisLabels = `<text class="chart-axis-label" x="${(left - 4).toFixed(1)}" y="${yAt(yMax).toFixed(1)}" text-anchor="end" dominant-baseline="central">${escapeText(formatY(yMax))}</text><text class="chart-axis-label" x="${(left - 4).toFixed(1)}" y="${yAt(yMin).toFixed(1)}" text-anchor="end" dominant-baseline="central">${escapeText(formatY(yMin))}</text>`;
  const xTickY = (bottom + xGutter - 2).toFixed(1);
  const xAxisLabels =
    points.length > 1
      ? `<text class="chart-axis-label" x="${xAt(points[0].x).toFixed(1)}" y="${xTickY}" text-anchor="start">${escapeText(formatAxisTime(points[0].x))}</text><text class="chart-axis-label" x="${lastX}" y="${xTickY}" text-anchor="end">${escapeText(formatAxisTime(last.x))}</text>`
      : `<text class="chart-axis-label" x="${lastX}" y="${xTickY}" text-anchor="middle">${escapeText(formatAxisTime(last.x))}</text>`;

  // Per-point hit-test data for the hover crosshair: pixel position plus a pre-formatted label, so
  // the delegated mousemove handler in main.ts only ever does a nearest-x scan — it never re-fetches
  // series data or re-runs valueFormat/date formatting outside of this render pass.
  const hoverPoints = points.map((point) => [
    Number(xAt(point.x).toFixed(1)),
    Number(yAt(point.y).toFixed(1)),
    `${formatY(point.y)} · ${formatAxisTime(point.x)}`,
  ]);
  const hoverLayer =
    `<g class="chart-hover" data-active="false">` +
    `<line class="chart-hover-line" x1="0" y1="${top}" x2="0" y2="${bottom}" />` +
    `<circle class="chart-hover-dot" cx="0" cy="0" r="2.8" />` +
    `<g class="chart-hover-tip"><rect class="chart-hover-tip-bg" x="0" y="0" width="0" height="0" rx="3" />` +
    `<text class="chart-hover-tip-text" x="0" y="0" dominant-baseline="central"></text></g></g>`;

  return `<svg class="chart ${className}" viewBox="0 0 ${CHART_W} ${CHART_H}" preserveAspectRatio="xMidYMid meet" role="img" aria-label="${escapeText(ariaLabel)}" data-hover-points="${escapeText(JSON.stringify(hoverPoints))}">${bandRects}${midGrid}${areaPath}${line}${markerLines}${projectionShape}${dot}${yAxisLabels}${xAxisLabels}${hoverLayer}</svg>`;
}

export interface RingOptions {
  /// Fraction elapsed, 0..1. 0 = full window remaining, 1 = about to reset.
  fraction: number;
  ariaLabel: string;
  /// Short centered text, e.g. "3h".
  label?: string;
  className?: string;
}

/// A small progress ring for a quota-reset countdown. The arc fills clockwise as the window elapses.
export function ring(options: RingOptions): string {
  const { fraction, ariaLabel, label = "", className = "" } = options;
  const clamped = Math.max(0, Math.min(1, fraction));
  const size = 34;
  const stroke = 4;
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const dash = clamped * circumference;
  const center = size / 2;
  const text = label
    ? `<text class="ring-label" x="${center}" y="${center}" text-anchor="middle" dominant-baseline="central">${escapeText(label)}</text>`
    : "";
  return `<svg class="ring ${className}" viewBox="0 0 ${size} ${size}" role="img" aria-label="${escapeText(ariaLabel)}">
    <circle class="ring-track" cx="${center}" cy="${center}" r="${radius}" fill="none" stroke-width="${stroke}" />
    <circle class="ring-value" cx="${center}" cy="${center}" r="${radius}" fill="none" stroke-width="${stroke}"
      stroke-dasharray="${dash.toFixed(2)} ${(circumference - dash).toFixed(2)}" stroke-dashoffset="0"
      transform="rotate(-90 ${center} ${center})" stroke-linecap="round" />
    ${text}
  </svg>`;
}

function escapeText(value: string): string {
  return value.replace(/[&<>"']/g, (character) =>
    character === "&"
      ? "&amp;"
      : character === "<"
        ? "&lt;"
        : character === ">"
          ? "&gt;"
          : character === '"'
            ? "&quot;"
            : "&#39;",
  );
}
