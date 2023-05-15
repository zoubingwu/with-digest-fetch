/// !-----------------------------------------------------------------------------------------------------------
/// |
//  |  `digest-fetch` is a wrapper of `node-fetch` or `fetch` to provide http digest authentication boostraping.
//  |
/// !-----------------------------------------------------------------------------------------------------------

import md5 from "md5";
import js256 from "js-sha256";
import js512 from "js-sha512";
import base64 from "base-64";

const sha256 = js256.sha256;
const sha512256 = js512.sha512_256;

const supported_algorithms = [
  "MD5",
  "MD5-sess",
  "SHA-256",
  "SHA-256-sess",
  "SHA-512-256",
  "SHA-512-256-sess",
] as const;

const parse = (raw: string, field: string, trim: boolean = true) => {
  const regex = new RegExp(`${field}=("[^"]*"|[^,]*)`, "i");
  const match = regex.exec(raw);
  if (match) return trim ? match[1].replace(/[\s"]/g, "") : match[1];
  return null;
};

// export function withDigestFetch(
//   fetch = globalThis.fetch
// ): typeof globalThis.fetch {
//   return (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
//     return fetch(url, this.addAuth(url, options));
//   };
// }

export interface Options {
  algorithm?: (typeof supported_algorithms)[number];
  logger?: {
    warn(message: string): void;
  };
  precomputedHash?: boolean;
  cnonceSize?: number;
  statusCode?: number;
  basic?: boolean;
  factory?: () => RequestInit;
}

function setHeader(headers: HeadersInit, key: string, value: string) {
  if (Array.isArray(headers)) {
    headers.push([key, value]);
  } else if (headers instanceof Headers) {
    headers.set(key, value);
  } else {
    headers[key] = value;
  }
  return headers;
}

export class DigestClient {
  private hashFunc: (message: Buffer | string | Uint8Array) => string;
  private nonceRaw = "abcdef0123456789";
  private logger: Options["logger"];
  private precomputedHash: Options["precomputedHash"];
  private digest: Record<string, any> = {};
  private hasAuth: boolean = false;
  private cnonceSize: number;
  private statusCode: number;
  private basic: boolean;

  constructor(
    private user: string,
    private password: string,
    options: Options = {}
  ) {
    this.user = user;
    this.hashFunc = md5;
    this.password = password;

    this.logger = options.logger;
    this.precomputedHash = options.precomputedHash ?? false;

    let algorithm = options.algorithm || "MD5";
    if (!supported_algorithms.includes(algorithm)) {
      if (this.logger)
        this.logger.warn(
          `Unsupported algorithm ${algorithm}, will try with MD5`
        );
      algorithm = "MD5";
    } else if (algorithm.startsWith("SHA-256")) {
      this.hashFunc = sha256;
    } else if (algorithm.startsWith("SHA-512-256")) {
      this.hashFunc = sha512256;
    }
    this.digest = { nc: 0, algorithm, realm: "" };
    this.cnonceSize = options.cnonceSize ?? 32; // cnonce length 32 as default

    // Custom authentication failure code for avoiding browser prompt:
    // https://stackoverflow.com/questions/9859627/how-to-prevent-browser-to-invoke-basic-auth-popup-and-handle-401-error-using-jqu
    this.statusCode = options.statusCode ?? 401;
    this.basic = options.basic || false;
  }

  async fetch(
    url: RequestInfo | URL,
    options: RequestInit & Pick<Options, "factory"> = {}
  ) {
    const fetch = globalThis.fetch;

    if (this.basic) {
      return fetch(url, this.addBasicAuth(options));
    }

    const resp = await fetch(url, this.addAuth(url, options));
    if (resp.status === this.statusCode) {
      this.hasAuth = false;
      this.parseAuth(resp.headers.get("www-authenticate"));

      if (this.hasAuth) {
        const respFinal = await fetch(url, this.addAuth(url, options));
        if (respFinal.status === 401 || respFinal.status == this.statusCode) {
          this.hasAuth = false;
        } else {
          this.digest.nc++;
        }
        return respFinal;
      }
    } else {
      this.digest.nc++;
    }
    return resp;
  }

  addBasicAuth(options: RequestInit & Pick<Options, "factory"> = {}) {
    let _options = {} as typeof options;
    if (typeof options.factory == "function") {
      _options = options.factory();
    } else {
      _options = options;
    }

    const auth = "Basic " + base64.encode(this.user + ":" + this.password);
    _options.headers = _options.headers || ({} as Record<string, string>);
    setHeader(_options.headers, "Authorization", auth);
    return _options;
  }

  computeHash(user: any, realm: any, password: any) {
    return this.hashWithAlgorithm(`${user}:${realm}:${password}`);
  }

  hashWithAlgorithm(data: any) {
    return this.hashFunc(data);
  }

  addAuth(url: any, options: any) {
    if (typeof options.factory == "function") {
      options = options.factory();
    }
    if (!this.hasAuth) {
      return options;
    }

    const isRequest = typeof url === "object" && typeof url.url === "string";
    const urlStr = isRequest ? url.url : url;
    const _url = urlStr.replace("//", "");
    const uri = _url.indexOf("/") == -1 ? "/" : _url.slice(_url.indexOf("/"));
    const method = options.method ? options.method.toUpperCase() : "GET";

    let ha1 = this.precomputedHash
      ? this.password
      : this.computeHash(this.user, this.digest.realm, this.password);
    if (this.digest.algorithm.endsWith("-sess")) {
      ha1 = this.hashWithAlgorithm(
        `${ha1}:${this.digest.nonce}:${this.digest.cnonce}`
      );
    }

    // optional Hash(entityBody) for 'auth-int'
    let _ha2 = "";
    if (this.digest.qop === "auth-int") {
      // not implemented for auth-int
      if (this.logger)
        this.logger.warn("Sorry, auth-int is not implemented in this plugin");
      // const entityBody = xxx
      // _ha2 = ':' + hash(entityBody)
    }
    const ha2 = this.hashWithAlgorithm(`${method}:${uri}${_ha2}`);

    const ncString = ("00000000" + this.digest.nc).slice(-8);

    let _response = `${ha1}:${this.digest.nonce}:${ncString}:${this.digest.cnonce}:${this.digest.qop}:${ha2}`;
    if (!this.digest.qop) _response = `${ha1}:${this.digest.nonce}:${ha2}`;
    const response = this.hashWithAlgorithm(_response);

    const opaqueString =
      this.digest.opaque !== null ? `opaque="${this.digest.opaque}",` : "";
    const qopString = this.digest.qop ? `qop=${this.digest.qop},` : "";
    const digest = `${this.digest.scheme} username="${this.user}",realm="${this.digest.realm}",\
nonce="${this.digest.nonce}",uri="${uri}",${opaqueString}${qopString}\
algorithm=${this.digest.algorithm},response="${response}",nc=${ncString},cnonce="${this.digest.cnonce}"`;
    options.headers = options.headers || {};
    options.headers.Authorization = digest;
    if (typeof options.headers.set == "function") {
      options.headers.set("Authorization", digest);
    }

    // const {factory, ..._options} = options
    const _options = {};
    Object.assign(_options, options);
    return _options;
  }

  parseAuth(h: string | null) {
    if (!h || h.length < 5) {
      this.hasAuth = false;
      return;
    }

    this.hasAuth = true;
    this.digest.scheme = h.split(/\s/)[0];
    this.digest.realm = (parse(h, "realm", false) || "").replace(/["]/g, "");
    this.digest.qop = this.parseQop(h);
    this.digest.opaque = parse(h, "opaque");
    this.digest.nonce = parse(h, "nonce") || "";
    this.digest.cnonce = this.makeNonce();
    this.digest.nc++;
  }

  parseQop(rawAuth: any) {
    // Following https://en.wikipedia.org/wiki/Digest_access_authentication
    // to parse valid qop
    // Samples
    // : qop="auth,auth-init",realm=
    // : qop=auth,realm=
    const _qop = parse(rawAuth, "qop");

    if (_qop !== null) {
      const qops = _qop.split(",");
      if (qops.includes("auth")) return "auth";
      else if (qops.includes("auth-int")) return "auth-int";
    }
    // when not specified
    return null;
  }

  makeNonce() {
    let uid = "";
    for (let i = 0; i < this.cnonceSize; ++i) {
      uid += this.nonceRaw[Math.floor(Math.random() * this.nonceRaw.length)];
    }
    return uid;
  }

  static parse(...args: Parameters<typeof parse>) {
    return parse(...args);
  }
}

export default DigestClient;
