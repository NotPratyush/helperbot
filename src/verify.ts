import tweetnacl from "tweetnacl";

function valueToUint8Array(
  value: Uint8Array | ArrayBuffer | Buffer | string,
  format?: string
): Uint8Array {
  if (value === null) return new Uint8Array();

  if (typeof value === "string") {
    if (format === "hex") {
      let matches = value.match(/.{1,2}/g);
      let hexVal = matches.map((byte: string) => parseInt(byte, 16));
      return new Uint8Array(hexVal);
    } else {
      return new TextEncoder().encode(value);
    }
  }

  try {
    if (Buffer.isBuffer(value)) {
      return new Uint8Array(value);
    }
  } catch {}

  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value);
  }

  if (value instanceof Uint8Array) {
    return value;
  }
}

function concatUint8Arrays(arr1: Uint8Array, arr2: Uint8Array): Uint8Array {
  let merged = new Uint8Array(arr1.length + arr2.length);
  merged.set(arr1);
  merged.set(arr2, arr1.length);
  return merged;
}

function verifyInteraction(
  body: Uint8Array | ArrayBuffer | Buffer | string,
  signature: Uint8Array | ArrayBuffer | Buffer | string,
  timestamp: Uint8Array | ArrayBuffer | Buffer | string,
  clientPublicKey: Uint8Array | ArrayBuffer | Buffer | string
): boolean {
  try {
    let timestampData = valueToUint8Array(timestamp);
    let bodyData = valueToUint8Array(body);
    let message = concatUint8Arrays(timestampData, bodyData);

    let signatureData = valueToUint8Array(signature, "hex");
    let publicKeyData = valueToUint8Array(clientPublicKey, "hex");
    return tweetnacl.sign.detached.verify(
      message,
      signatureData,
      publicKeyData
    );
  } catch {
    return false;
  }
}

export default verifyInteraction;
