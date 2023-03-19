import { decrypt as ecDecrypt, encrypt as ecEncrypt, generatePrivate as ecGeneratePrivate, getPublic as ecGetPublic } from "@toruslabs/eccrypto";
import BN from "bn.js";
import { curve, ec as EC } from "elliptic";
import { serializeError } from "serialize-error";
import { keccak256, toChecksumAddress } from "web3-utils";

import { EncryptedMessage } from "./baseTypes/commonTypes";

// TODO remove the following two functions?
// const privKeyBnToEcc = (bnPrivKey) => {
//   return bnPrivKey.toBuffer("be", 32);
// };

// const privKeyBnToPubKeyECC = (bnPrivKey) => {
//   return getPublic(privKeyBnToEcc(bnPrivKey));
// };

// TODO: Use curve ed25519
//
// We want to use ed25519 for everything except encryption. Encryption relies on
// package `eccrypto` which uses curve secp256k1. Check for every usage of
// `encrypt` and `decrypt` if supplied keys are on curve secp256k1. Generate
// encryption using function `genEncKeyPair` defined below.
//
// All other curve usage should rely on package `elliptic` instantiated with the
// desired curve (e.g., ed25519). Ideally instantiate elliptic only once in a
// central location and use this instance across the whole codebase to avoid
// mixing different curves by mistake.
//
// In particular this means:
//
// Replace the usage of import { generatePrivate } from "@toruslabs/eccrypto";
// with function `generateScalar()` defined above, which uses elliptic's
// curve.genKeyPair().getPrivate().
//
// Replace the usage of import { getPublic } from "@toruslabs/eccrypto"; with
// with function `scalarBaseMul()` defined above, which uses elliptic's
// key.getPublic().
//
// Point normalization: Furthermore, check codebase for usage of EllipticPoint.x
// and EllipticPoint.y, where EllipticPoint refers to a curve point from package
// `elliptic`. These produce coordinates that are potentially not normalized and
// therefore most likely not suitable for serialization or point comparison.
// They are also not exposed by the interface curve.base.BasePoint, which should
// be as the point type. Instead, use the interface methods BasePoint.getX() and
// BasePoint.getY(). Moreover, for comparison, instead of comparing the x and y
// coordinates, use function BasePoint.eq(otherPoint).
//
// Point serialization: There is usually a standardized way how to encode curve
// points. This encoding may be different for different curves. Ensure that
// point encoding is suitable for the target use case.

const ec = new EC("ed25519");
export const ecCurve = ec;
export function generateScalar() {
  const k = ecCurve.genKeyPair();
  return k.getPrivate();
}
export function scalarBaseMul(s: BN) {
  return ec.keyFromPrivate(s.toString(16)).getPublic();
}

export type EncryptionKey = Buffer;
export type DecryptionKey = Buffer;

export type EncryptionKeyPair = {
  sk: EncryptionKey;
  pk: DecryptionKey;
};

export function genEncKeyPair(): EncryptionKeyPair {
  const sk = ecGeneratePrivate();
  const pk = ecGetPublic(sk);
  return { sk, pk };
}

// Wrappers around ECC encrypt/decrypt to use the hex serialization
// TODO: refactor to take BN
export async function encrypt(publicKey: Buffer, msg: Buffer): Promise<EncryptedMessage> {
  const encryptedDetails = await ecEncrypt(publicKey, msg);

  return {
    ciphertext: encryptedDetails.ciphertext.toString("hex"),
    ephemPublicKey: encryptedDetails.ephemPublicKey.toString("hex"),
    iv: encryptedDetails.iv.toString("hex"),
    mac: encryptedDetails.mac.toString("hex"),
  };
}

export async function decrypt(privKey: Buffer, msg: EncryptedMessage): Promise<Buffer> {
  const bufferEncDetails = {
    ciphertext: Buffer.from(msg.ciphertext, "hex"),
    ephemPublicKey: Buffer.from(msg.ephemPublicKey, "hex"),
    iv: Buffer.from(msg.iv, "hex"),
    mac: Buffer.from(msg.mac, "hex"),
  };

  return ecDecrypt(privKey, bufferEncDetails);
}

export function isEmptyObject(obj: unknown): boolean {
  return Object.keys(obj).length === 0 && obj.constructor === Object;
}

export const isErrorObj = (err: Error): boolean => err && err.stack && err.message !== "";

export function prettyPrintError(error: Error): string {
  if (isErrorObj(error)) {
    return error.message;
  }
  return JSON.stringify(serializeError(error));
}

export function generateAddressFromPublicKey(publicKey: Buffer): string {
  const ethAddressLower = `0x${keccak256(publicKey.toString("hex")).slice(64 - 38)}`;
  return toChecksumAddress(ethAddressLower);
}

export function normalize(input: number | string): string {
  if (!input) {
    return undefined;
  }
  let hexString;

  if (typeof input === "number") {
    hexString = input.toString(16);
    if (hexString.length % 2) {
      hexString = `0${hexString}`;
    }
  }

  if (typeof input === "string") {
    hexString = input.toLowerCase();
  }

  return `0x${hexString}`;
}

export function generatePrivateExcludingIndexes(shareIndexes: Array<BN>): BN {
  const key = generateScalar();
  if (shareIndexes.find((el) => el.eq(key))) {
    return generatePrivateExcludingIndexes(shareIndexes);
  }
  return key;
}

export const KEY_NOT_FOUND = "KEY_NOT_FOUND";
export const SHARE_DELETED = "SHARE_DELETED";

export function derivePubKeyXFromPolyID(polyID: string): string {
  return polyID.split("|")[0].slice(2);
}

export function stripHexPrefix(str: string): string {
  if (str.slice(0, 2) === "0x") return str.slice(2);
  return str;
}

export function generateID(): string {
  // Math.random should be unique because of its seeding algorithm.
  // Convert it to base 36 (numbers + letters), and grab the first 9 characters
  // after the decimal.
  return `${Math.random().toString(36).substr(2, 9)}`;
}
