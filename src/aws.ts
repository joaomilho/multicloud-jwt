import { KMS } from "aws-sdk";
import base64url from "base64url";
import { BaseClass } from "./Base";

export class AWS extends BaseClass {
  kms: KMS;
  keyId: string;

  constructor(props: { keyId: string } & KMS.ClientConfiguration) {
    super();
    this.keyId = props.keyId;
    this.kms = new KMS(props);
  }

  async sign(
    payload: Record<string, any>,
    options: { exp?: Date } = {},
    signReq?: Omit<KMS.SignRequest, "Message" | "KeyId">
  ): Promise<string> {
    const body = this.getBody("AWS", payload, options);

    const result = await this.kms
      .sign({
        SigningAlgorithm: "RSASSA_PSS_SHA_256",
        ...signReq,
        Message: body,
        KeyId: this.keyId,
      })
      .promise();

    const signature64 = base64url(Buffer.from(result.Signature as string));

    return `${body}.${signature64}`;
  }

  async verify(jwt: string): Promise<boolean> {
    const jwtData = this.parse(jwt);

    try {
      const result = await this.kms
        .verify({
          KeyId: this.keyId,
          Message: jwtData.message,
          Signature: Buffer.from(jwtData.signature, "base64"),
          SigningAlgorithm: "RSASSA_PSS_SHA_256",
        })
        .promise();

      return !!result.SignatureValid;
    } catch (e) {
      return false;
    }
  }
}
