import base64url from "base64url";
import { z } from "zod";

const Payload = z
  .object({
    iat: z
      .number()
      .transform((iat) => {
        return new Date(
          iat * 1000 - 1000 * 60 * 5 // 5 min diff
        );
      })
      .refine(
        (iat) => {
          return iat.getTime() < Date.now();
        },
        {
          message: "Token was issued after the current time",
        }
      ),
    exp: z.optional(
      z
        .number()
        .transform((exp) => {
          return new Date(exp * 1000);
        })
        .refine(
          (exp) => {
            return exp.getTime() >= Date.now();
          },
          {
            message: "Token is expired",
          }
        )
    ),
  })
  .passthrough(); // allows unknown keys

type Payload = z.infer<typeof Payload> & { [key: string]: any };

const Header = z.object({
  alg: z.enum(["GCP", "AWS"]),
  typ: z.literal("JWT"),
});

type Header = z.infer<typeof Header>;

interface Base {
  sign(payload: Payload, options: { exp?: Date }): Promise<string>;

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
    alg: Header["alg"],
    payload: Record<string, any>,
    options: { exp?: Date } = {}
  ) {
    const header: Header = {
      alg,
      typ: "JWT",
    };

    payload = {
      ...payload,
      iat: Math.floor(Date.now() / 1000),
      ...(options.exp ? { exp: Math.ceil(options.exp.getTime() / 1000) } : {}),
    };

    const header64 = base64url(JSON.stringify(header));
    const payload64 = base64url(JSON.stringify(payload));

    return `${header64}.${payload64}`;
  }

  sign(
    payload: Record<string, any>,
    options: { exp?: Date },
    config?: any
  ): Promise<string> {
    throw new Error("Not implemented");
  }

  verify(jwt: string): Promise<boolean> {
    throw new Error("Not implemented");
  }

  parse(jwt: string): {
    header: Record<any, string>;
    payload: Payload;
    signature: string;
    message: string;
  } {
    if (!jwt || !jwt.split) {
      throw new Error("Invalid Token");
    }

    const [rawHeader, rawPayload, signature] = jwt.split(".");

    const jsonPayload = JSON.parse(base64url.decode(rawPayload));
    const payload = Payload.parse(jsonPayload);

    try {
      return {
        message: `${rawHeader}.${rawPayload}`,
        header: JSON.parse(base64url.decode(rawHeader)),
        payload,
        signature,
      };
    } catch (err) {
      throw err; //new Error("Invalid Token");
    }
  }
}
