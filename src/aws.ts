import { KMS } from "aws-sdk";
import base64url from "base64url";
import { BaseClass } from "./Base";

export class AWS extends BaseClass {
  kms: KMS;

  constructor(
    public masterKeyAlias: string,
    clientConfig: KMS.ClientConfiguration
  ) {
    super();
    this.kms = new KMS(clientConfig);
  }

  async sign(
    payload: Record<string, any>,
    options: { expires?: Date } = {},
    signReq?: KMS.SignRequest
  ): Promise<string> {
    const body = this.getBody("AWS", payload, options);

    const result = await this.kms
      .sign({
        SigningAlgorithm: "RSASSA_PSS_SHA_256",
        ...signReq,
        Message: body,
        KeyId: this.masterKeyAlias,
      })
      .promise();

    const signature64 = base64url(Buffer.from(result.Signature as string));

    return `${body}.${signature64}`;
  }

  async verify(jwt: string): Promise<boolean> {
    const jwtData = this.getJwtData(jwt);

    const result = await this.kms
      .verify({
        KeyId: this.masterKeyAlias,
        Message: jwtData.message,
        Signature: Buffer.from(jwtData.signature, "base64"),
        SigningAlgorithm: "RSASSA_PSS_SHA_256",
      })
      .promise();

    return !!result.SignatureValid;
  }
}
