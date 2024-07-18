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
  private key?: CryptoKey;

  /**
   *
   * @param ctx hono context
   * @param rawKey raw key for encryption
   * @param name name of the cookie
   * @param cookieOptions cookie options
   */
  constructor(
    public readonly ctx: Context<E, P, I>,
    public readonly rawKey: string,
    public readonly name: string,
    public readonly cookieOptions?: CookieOptions,
  ) {}

  private async _getKey(): Promise<CryptoKey> {
    if (this.key) {
      return this.key;
    }
    this.key = await crypto.subtle.importKey(
      "raw",
      await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(this.rawKey),
      ),
      { name: "AES-GCM" },
      true,
      ["encrypt", "decrypt"],
    );
    return this.key;
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
      throw new Error("session not found");
    }
    const key = await this._getKey();
    const decrypted = await crypto.subtle.decrypt(
      "AES-GCM",
      key,
      base64Decode(cookie),
    );
    const decoded = msgPackDecode(new Uint8Array(decrypted)) as {
      expiresAt: number;
      value: T;
    };
    if (!decoded) {
      throw new Error("session not found");
    }
    if (typeof decoded.expiresAt !== "number") {
      throw new Error("session malformed");
    }
    if (decoded.expiresAt < Date.now()) {
      this.delete();
      throw new Error("session expired");
    }
    if (!decoded.value) {
      throw new Error("session malformed");
    }

    return decoded.value;
  }

  /**
   * Set the session value.
   * @param value session value
   */
  public async set(value: T) {
    const key = await this._getKey();
    const expiresAt = this.cookieOptions?.maxAge
      ? Date.now() + this.cookieOptions?.maxAge * 1000
      : this.cookieOptions?.expires
        ? this.cookieOptions?.expires.getTime()
        : Number.MAX_SAFE_INTEGER;
    const encoded = msgPackEncode({ expiresAt, value });
    const encrypted = await crypto.subtle.encrypt("AES-GCM", key, encoded);
    const encodedBase64 = base64Encode(new Uint8Array(encrypted));
    setCookie(this.ctx, this.name, encodedBase64, this.cookieOptions);
  }

  /**
   * Delete the session.
   */
  public async delete() {
    deleteCookie(this.ctx, this.name);
  }
}
