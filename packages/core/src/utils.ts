import { Point } from "@tkey-mpc/common-types";
import type { PointHex } from "@toruslabs/rss-client";

export function pointToHex(p: Point): PointHex {
  return { x: p.x.toString(16, 64), y: p.y.toString(16, 64) };
}
