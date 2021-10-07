import base64url from "base64url";

interface Base {
  sign(
    payload: Record<string, any>,
    options: { expires?: Date }
  ): Promise<string>;

  verify(jwt: string): Promise<boolean>;

  parse(jwt: string): {
    header: Record<any, string>;
    payload: Record<any, string>;
    signature: string;
    message: string;
  };
}

export class BaseClass implements Base {
  protected getBody(
    alg: "CGP" | "AWS",
    payload: Record<string, any>,
    options: { expires?: Date } = {}
  ) {
    const header = {
      alg,
      typ: "JWT",
    };

    payload = {
      ...payload,
      iat: Math.floor(Date.now() / 1000),
      ...(options.expires
        ? { exp: Math.ceil(options.expires.getTime() / 1000) }
        : {}),
    };

    const header64 = base64url(JSON.stringify(header));
    const payload64 = base64url(JSON.stringify(payload));

    return `${header64}.${payload64}`;
  }

  sign(
    payload: Record<string, any>,
    options: { expires?: Date },
    config?: any
  ): Promise<string> {
    throw new Error("Not implemented");
  }

  verify(jwt: string): Promise<boolean> {
    throw new Error("Not implemented");
  }

  parse(jwt: string): {
    header: Record<any, string>;
    payload: Record<any, string>;
    signature: string;
    message: string;
  } {
    if (!jwt || !jwt.split) {
      throw new Error("Invalid Token");
    }

    const [header, payload, signature] = jwt.split(".");

    try {
      return {
        message: `${header}.${payload}`,
        header: JSON.parse(base64url.decode(header)),
        payload: JSON.parse(base64url.decode(payload)),
        signature,
      };
    } catch (err) {
      throw err; //new Error("Invalid Token");
    }
  }

  private checkIssuedTime(issuedAt: string) {
    if (issuedAt) {
      const iat = new Date(
        parseInt(issuedAt) * 1000 - 1000 * 60 * 5 // 10 min diff
      ).getTime();

      if (iat >= Date.now()) {
        throw new Error("Token was issued after the current time");
      }
    }
  }

  private checkExpiration(expiresAt: string) {
    if (expiresAt) {
      const exp = new Date(parseInt(expiresAt) * 1000).getTime();

      if (exp < Date.now()) {
        throw new Error("Token is expired");
      }
    }
  }
}
