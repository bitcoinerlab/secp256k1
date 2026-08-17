/*
 * Copyright (c) 2023 Jose-Luis Landabaso
 * Distributed under the MIT software license.
 *
 * This file includes code from the following sources:
 *  * Paul Miller's @noble/secp256k1 (specifically, the privateAdd,
 *    privateNegate, pointAddScalar, and pointMultiply functions).
 *  * Some pieces from tiny-secp256k1
 *    (https://github.com/bitcoinjs/tiny-secp256k1)
 *  * It also uses code from BitGo's BitGoJS library
 *    (https://github.com/BitGo/BitGoJS)
 *
 * This package's tests are based on modified versions of tests from
 * tiny-secp256k1 (https://github.com/bitcoinjs/tiny-secp256k1/tests).
 */

import { secp256k1, schnorr } from "@noble/curves/secp256k1.js";
import * as utils from "@noble/curves/utils.js";

const Point = secp256k1.Point;
const Fn = Point.Fn;

const THROW_BAD_PRIVATE = "Expected Private";
const THROW_BAD_POINT = "Expected Point";
const THROW_BAD_TWEAK = "Expected Tweak";
const THROW_BAD_HASH = "Expected Hash";
const THROW_BAD_SIGNATURE = "Expected Signature";
const THROW_BAD_EXTRA_DATA = "Expected Extra Data (32 bytes)";
const THROW_BAD_SCALAR = "Expected Scalar";
const THROW_BAD_RECOVERY_ID = "Bad Recovery Id";

const HASH_SIZE = 32;
const TWEAK_SIZE = 32;
const BN32_N = new Uint8Array([
  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
  254, 186, 174, 220, 230, 175, 72, 160, 59, 191, 210, 94, 140, 208, 54, 65, 65,
]);
const EXTRA_DATA_SIZE = 32;
const BN32_ZERO = new Uint8Array(32);
const BN32_P_MINUS_N = new Uint8Array([
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 69, 81, 35, 25, 80, 183, 95,
  196, 64, 45, 161, 114, 47, 201, 186, 238,
]);
const _0n = BigInt(0);

function isUint8Array(value) {
  return value instanceof Uint8Array;
}

function cmpBN32(data1, data2) {
  for (let i = 0; i < 32; ++i) {
    if (data1[i] !== data2[i]) {
      return data1[i] < data2[i] ? -1 : 1;
    }
  }
  return 0;
}

function isZero(x) {
  return cmpBN32(x, BN32_ZERO) === 0;
}

function isTweak(tweak) {
  if (
    !(tweak instanceof Uint8Array) ||
    tweak.length !== TWEAK_SIZE ||
    cmpBN32(tweak, BN32_N) >= 0
  ) {
    return false;
  }
  return true;
}

function isSignature(signature) {
  return (
    signature instanceof Uint8Array &&
    signature.length === 64 &&
    cmpBN32(signature.subarray(0, 32), BN32_N) < 0 &&
    cmpBN32(signature.subarray(32, 64), BN32_N) < 0
  );
}

function isSigrLessThanPMinusN(signature) {
  return (
    isUint8Array(signature) &&
    signature.length === 64 &&
    cmpBN32(signature.subarray(0, 32), BN32_P_MINUS_N) < 0
  );
}

function isSignatureNonzeroRS(signature) {
  return !(
    isZero(signature.subarray(0, 32)) || isZero(signature.subarray(32, 64))
  );
}

function isHash(h) {
  return h instanceof Uint8Array && h.length === HASH_SIZE;
}

function isExtraData(e) {
  return (
    e === undefined || (e instanceof Uint8Array && e.length === EXTRA_DATA_SIZE)
  );
}

function normalizeScalar(scalar) {
  let num;
  if (typeof scalar === "bigint") {
    num = scalar;
  } else if (
    typeof scalar === "number" &&
    Number.isSafeInteger(scalar) &&
    scalar >= 0
  ) {
    num = BigInt(scalar);
  } else if (typeof scalar === "string") {
    if (scalar.length !== 64)
      throw new Error("Expected 32 bytes of private scalar");
    num = utils.hexToNumber(scalar);
  } else if (scalar instanceof Uint8Array) {
    if (scalar.length !== 32)
      throw new Error("Expected 32 bytes of private scalar");
    num = utils.bytesToNumberBE(scalar);
  } else {
    throw new TypeError("Expected valid private scalar");
  }
  if (num < 0) throw new Error("Expected private scalar >= 0");
  return num;
}

function normalizePrivateKey(privateKey) {
  return Fn.fromBytes(privateKey);
}

function _privateAdd(privateKey, tweak) {
  const p = normalizePrivateKey(privateKey);
  const t = normalizeScalar(tweak);
  const add = Fn.add(p, t);
  return Fn.isValidNot0(add) ? Fn.toBytes(add) : null;
}

function _privateSub(privateKey, tweak) {
  const p = normalizePrivateKey(privateKey);
  const t = normalizeScalar(tweak);
  const sub = Fn.sub(p, t);
  return Fn.isValidNot0(sub) ? Fn.toBytes(sub) : null;
}

function _privateNegate(privateKey) {
  const p = normalizePrivateKey(privateKey);
  return Fn.toBytes(Fn.neg(p));
}

function _pointAddScalar(p, tweak, isCompressed) {
  const P = fromHex(p);
  const t = normalizeScalar(tweak);
  const Q = t === _0n ? P : Point.BASE.multiply(t).add(P);
  if (Q.is0()) throw new Error("Tweaked point at infinity");
  return Q.toBytes(isCompressed);
}

function _pointMultiply(p, tweak, isCompressed) {
  const P = fromHex(p);
  const h = typeof tweak === "string" ? tweak : utils.bytesToHex(tweak);
  const t = utils.hexToNumber(h);
  return P.multiply(t).toBytes(isCompressed);
}

function assumeCompression(compressed, p) {
  if (compressed === undefined) {
    return p !== undefined ? isPointCompressed(p) : true;
  }
  return !!compressed;
}

function throwToNull(fn) {
  try {
    return fn();
  } catch (e) {
    return null;
  }
}

function fromXOnly(bytes) {
  return schnorr.utils.lift_x(utils.bytesToNumberBE(bytes));
}

function fromHex(bytes) {
  return bytes.length === 32 ? fromXOnly(bytes) : Point.fromBytes(bytes);
}

function _isPoint(p, xOnly) {
  if ((p.length === 32) !== xOnly) return false;
  try {
    if (xOnly) return !!fromXOnly(p);
    else return !!Point.fromBytes(p);
  } catch (e) {
    return false;
  }
}

export function isPoint(p) {
  return _isPoint(p, false);
}

export function isPointCompressed(p) {
  const PUBLIC_KEY_COMPRESSED_SIZE = 33;
  return _isPoint(p, false) && p.length === PUBLIC_KEY_COMPRESSED_SIZE;
}

export function isPrivate(d) {
  return secp256k1.utils.isValidSecretKey(d);
}

export function isXOnlyPoint(p) {
  return _isPoint(p, true);
}

export function xOnlyPointAddTweak(p, tweak) {
  if (!isXOnlyPoint(p)) {
    throw new Error(THROW_BAD_POINT);
  }
  if (!isTweak(tweak)) {
    throw new Error(THROW_BAD_TWEAK);
  }
  return throwToNull(() => {
    const P = _pointAddScalar(p, tweak, true);
    const parity = P[0] % 2 === 1 ? 1 : 0;
    return { parity, xOnlyPubkey: P.slice(1) };
  });
}

export function xOnlyPointFromPoint(p) {
  if (!isPoint(p)) {
    throw new Error(THROW_BAD_POINT);
  }
  return p.slice(1, 33);
}

export function pointFromScalar(sk, compressed) {
  if (!isPrivate(sk)) {
    throw new Error(THROW_BAD_PRIVATE);
  }
  return throwToNull(() =>
    secp256k1.getPublicKey(sk, assumeCompression(compressed)),
  );
}

export function xOnlyPointFromScalar(d) {
  if (!isPrivate(d)) {
    throw new Error(THROW_BAD_PRIVATE);
  }
  return xOnlyPointFromPoint(pointFromScalar(d));
}

export function pointCompress(p, compressed) {
  if (!isPoint(p)) {
    throw new Error(THROW_BAD_POINT);
  }
  return fromHex(p).toBytes(assumeCompression(compressed, p));
}

export function pointMultiply(a, tweak, compressed) {
  if (!isPoint(a)) {
    throw new Error(THROW_BAD_POINT);
  }
  if (!isTweak(tweak)) {
    throw new Error(THROW_BAD_TWEAK);
  }
  return throwToNull(() =>
    _pointMultiply(a, tweak, assumeCompression(compressed, a)),
  );
}

export function pointAdd(a, b, compressed) {
  if (!isPoint(a) || !isPoint(b)) {
    throw new Error(THROW_BAD_POINT);
  }
  return throwToNull(() => {
    const A = fromHex(a);
    const B = fromHex(b);
    if (A.equals(B.negate())) {
      return null;
    } else {
      return A.add(B).toBytes(assumeCompression(compressed, a));
    }
  });
}

export function pointAddScalar(p, tweak, compressed) {
  if (!isPoint(p)) {
    throw new Error(THROW_BAD_POINT);
  }
  if (!isTweak(tweak)) {
    throw new Error(THROW_BAD_TWEAK);
  }
  return throwToNull(() =>
    _pointAddScalar(p, tweak, assumeCompression(compressed, p)),
  );
}

export function privateAdd(d, tweak) {
  if (!isPrivate(d)) {
    throw new Error(THROW_BAD_PRIVATE);
  }
  if (!isTweak(tweak)) {
    throw new Error(THROW_BAD_TWEAK);
  }
  return throwToNull(() => _privateAdd(d, tweak));
}

export function privateSub(d, tweak) {
  if (!isPrivate(d)) {
    throw new Error(THROW_BAD_PRIVATE);
  }
  if (!isTweak(tweak)) {
    throw new Error(THROW_BAD_TWEAK);
  }
  return throwToNull(() => _privateSub(d, tweak));
}

export function privateNegate(d) {
  if (!isPrivate(d)) {
    throw new Error(THROW_BAD_PRIVATE);
  }
  return _privateNegate(d);
}

export function sign(h, d, e) {
  if (!isPrivate(d)) {
    throw new Error(THROW_BAD_PRIVATE);
  }
  if (!isHash(h)) {
    throw new Error(THROW_BAD_SCALAR);
  }
  if (!isExtraData(e)) {
    throw new Error(THROW_BAD_EXTRA_DATA);
  }
  return secp256k1.sign(h, d, {
    prehash: false,
    lowS: true,
    format: "compact",
    extraEntropy: e,
  });
}

export function signRecoverable(h, d, e) {
  if (!isPrivate(d)) {
    throw new Error(THROW_BAD_PRIVATE);
  }
  if (!isHash(h)) {
    throw new Error(THROW_BAD_SCALAR);
  }
  if (!isExtraData(e)) {
    throw new Error(THROW_BAD_EXTRA_DATA);
  }
  const sig = secp256k1.sign(h, d, {
    prehash: false,
    lowS: true,
    format: "recovered",
    extraEntropy: e,
  });
  return {
    signature: sig.slice(1),
    recoveryId: sig[0],
  };
}

export function signSchnorr(h, d, e) {
  if (!isPrivate(d)) {
    throw new Error(THROW_BAD_PRIVATE);
  }
  if (!isHash(h)) {
    throw new Error(THROW_BAD_SCALAR);
  }
  if (!isExtraData(e)) {
    throw new Error(THROW_BAD_EXTRA_DATA);
  }
  return schnorr.sign(h, d, e);
}

export function recover(h, signature, recoveryId, compressed) {
  if (!isHash(h)) {
    throw new Error(THROW_BAD_HASH);
  }

  if (!isSignature(signature) || !isSignatureNonzeroRS(signature)) {
    throw new Error(THROW_BAD_SIGNATURE);
  }

  if (recoveryId & 2) {
    if (!isSigrLessThanPMinusN(signature))
      throw new Error(THROW_BAD_RECOVERY_ID);
  }
  if (!isXOnlyPoint(signature.subarray(0, 32))) {
    throw new Error(THROW_BAD_SIGNATURE);
  }

  const s =
    secp256k1.Signature.fromBytes(signature, "compact").addRecoveryBit(
      recoveryId,
    );
  const Q = s.recoverPublicKey(h);
  if (!Q) throw new Error(THROW_BAD_SIGNATURE);
  return Q.toBytes(assumeCompression(compressed));
}

export function verify(h, Q, signature, strict) {
  if (!isPoint(Q)) {
    throw new Error(THROW_BAD_POINT);
  }
  if (!isSignature(signature)) {
    throw new Error(THROW_BAD_SIGNATURE);
  }
  if (!isHash(h)) {
    throw new Error(THROW_BAD_SCALAR);
  }
  return secp256k1.verify(signature, h, Q, {
    prehash: false,
    lowS: strict,
    format: "compact",
  });
}

export function verifySchnorr(h, Q, signature) {
  if (!isXOnlyPoint(Q)) {
    throw new Error(THROW_BAD_POINT);
  }
  if (!isSignature(signature)) {
    throw new Error(THROW_BAD_SIGNATURE);
  }
  if (!isHash(h)) {
    throw new Error(THROW_BAD_SCALAR);
  }
  return schnorr.verify(signature, h, Q);
}
