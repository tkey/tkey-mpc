import { ShareTransferStorePointerArgs } from "@tkey-mpc/common-types";
import BN from "bn.js";

export class ShareTransferStorePointer {
  pointer: BN;

  constructor({ pointer }: ShareTransferStorePointerArgs) {
    this.pointer = new BN(pointer, "hex");
  }
}
