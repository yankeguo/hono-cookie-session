import { Context, Env, Input } from "hono";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";
import { CookieOptions } from "hono/utils/cookie";
import {
  encode as msgPackEncode,
  decode as msgPackDecode,
} from "@msgpack/msgpack";
import {
  fromUint8Array as base64Encode,
  toUint8Array as base64Decode,
} from "js-base64";

interface _EncryptedBox {
  salt: Uint8Array;
  iv: Uint8Array; // 12 bytes
  enc: Uint8Array;
}

interface _ExpirableBox<T> {
  exp: number;
  val: T;
}

/*
 * session <--> expirableBox <--> encryptedBox <--> base64 <--> cookie
 */

/**
 * Encrypted session.
 *
 * T is the session value type.
 */
export class EncryptedSession<
  T,
  E extends Env = any,
  P extends string = any,
  I extends Input = {},
> {
  private rootKey?: CryptoKey;

  /**
   *
   * @param ctx hono context
   * @param rootKeyRaw raw key for encryption
   * @param name name of the cookie
   * @param cookieOptions cookie options
   */
  constructor(
    public readonly ctx: Context<E, P, I>,
    public readonly rootKeyRaw: string,
    public readonly name: string,
    public readonly cookieOptions?: CookieOptions,
  ) {}

  private async _deriveKey(salt: Uint8Array): Promise<CryptoKey> {
    if (!this.rootKey) {
      this.rootKey = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(this.rootKeyRaw),
        "PBKDF2",
        false,
        ["deriveKey"],
      );
    }

    return await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt,
        iterations: 100000,
        hash: "SHA-256",
      } as Pbkdf2Params,
      this.rootKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
  }

  /**
   * Get the session value, return null if not exists or invalid.
   * @returns session value or null
   */
  public async get(): Promise<T | null> {
    try {
      return await this.mustGet();
    } catch (e) {
      return null;
    }
  }

  /**
   * Get the session value, throw error if not exists or invalid.
   * @returns session value
   */
  public async mustGet(): Promise<T> {
    const cookie = getCookie(this.ctx, this.name);
    if (!cookie) {
      throw new Error("session not found: cookie not found");
    }

    const encryptedBox = msgPackDecode(base64Decode(cookie)) as _EncryptedBox;

    // validate encrypted box
    if (!encryptedBox) {
      throw new Error("session not found: encrypted box not found");
    }

    if (!(encryptedBox.iv instanceof Uint8Array)) {
      throw new Error("session malformed: encrypted box iv malformed");
    }
    if (!(encryptedBox.enc instanceof Uint8Array)) {
      throw new Error("session malformed: encrypted box encrypted malformed");
    }
    if (!(encryptedBox.salt instanceof Uint8Array)) {
      throw new Error("session malformed: encrypted box salt malformed");
    }

    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: encryptedBox.iv },
      await this._deriveKey(encryptedBox.salt),
      encryptedBox.enc,
    );

    const expirableBox = msgPackDecode(decrypted) as _ExpirableBox<T>;

    // validate expirable box
    if (!expirableBox) {
      throw new Error("session not found");
    }
    if (typeof expirableBox.exp !== "number") {
      throw new Error("session malformed");
    }
    if (expirableBox.exp < Date.now()) {
      this.delete();
      throw new Error("session expired");
    }
    if (!expirableBox.val) {
      throw new Error("session malformed");
    }

    return expirableBox.val;
  }

  /**
   * Set the session value.
   * @param value session value
   */
  public async set(value: T) {
    const expiresAt = this.cookieOptions?.maxAge
      ? Date.now() + this.cookieOptions?.maxAge * 1000
      : this.cookieOptions?.expires
        ? this.cookieOptions?.expires.getTime()
        : Number.MAX_SAFE_INTEGER;
    const expirableBox: _ExpirableBox<T> = { exp: expiresAt, val: value };

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv } as AesGcmParams,
      await this._deriveKey(salt),
      msgPackEncode(expirableBox),
    );
    const encryptedBox: _EncryptedBox = {
      iv,
      salt,
      enc: new Uint8Array(encrypted),
    };

    setCookie(
      this.ctx,
      this.name,
      base64Encode(msgPackEncode(encryptedBox)),
      this.cookieOptions,
    );
  }

  /**
   * Delete the session.
   */
  public async delete() {
    deleteCookie(this.ctx, this.name);
  }
}
