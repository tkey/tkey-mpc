import BN from "bn.js";
import { ec as EC } from "elliptic";

import { BNString, IPoint, StringifiedType } from "../baseTypes/commonTypes";

class Point implements IPoint {
  x: BN;

  y: BN;

  constructor(x: BNString, y: BNString) {
    this.x = new BN(x, "hex");
    this.y = new BN(y, "hex");
  }

  // complies with EC and elliptic pub key types
  encode(enc: string, params?: any): Buffer {
    switch (enc) {
      case "arr":
        return Buffer.concat([Buffer.from("0x04", "hex"), Buffer.from(this.x.toString("hex"), "hex"), Buffer.from(this.y.toString("hex"), "hex")]);
      case "elliptic-compressed": {
        const ec = params.ec as EC;
        const key = ec.keyFromPublic({ x: this.x.toString("hex"), y: this.y.toString("hex") }, "hex");
        return Buffer.from(key.getPublic(true, "hex"));
      }
      default:
        throw new Error("encoding doesnt exist in Point");
    }
  }

  toJSON(): StringifiedType {
    return {
      x: this.x.toString("hex"),
      y: this.y.toString("hex"),
    };
  }

  static fromJSON(value: StringifiedType): Point {
    const { x, y } = value;
    return new Point(x, y);
  }
}

export default Point;
