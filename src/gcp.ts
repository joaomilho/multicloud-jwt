import { KeyManagementServiceClient as KMS } from "@google-cloud/kms";
import base64url from "base64url";
import * as crypto from "crypto";
import { BaseClass } from "./Base";

export class GCP extends BaseClass {
  kms: KMS;

  constructor(
    public props: {
      projectId: string;
      locationId: string;
      keyRingId: string;
      keyId: string;
      keyVersion: string;
    }
  ) {
    super();
    this.kms = new KMS({
      // TODO opts
    });
  }

  private get versionName(): string {
    return this.kms.cryptoKeyVersionPath(
      this.props.projectId,
      this.props.locationId,
      this.props.keyRingId,
      this.props.keyId,
      this.props.keyVersion
    );
  }

  async sign(
    payload: Record<string, any>,
    options: { expires?: Date } = {}
  ): Promise<string> {
    const body = this.getBody("CGP", payload, options);

    const sha256 = crypto.createHash("sha256").update(body).digest("base64");

    const result = await this.kms.asymmetricSign({
      name: this.versionName,
      digest: { sha256 },
    });

    const signatureString = result["0"].signature;
    if (!signatureString) {
      throw new Error("No sig");
    }

    const signature64 = base64url(Buffer.from(signatureString));

    return `${body}.${signature64}`;
  }

  async verify(jwt: string) {
    const jwtData = this.getJwtData(jwt);

    const [publicKey] = await this.kms.getPublicKey({
      name: this.versionName,
    });

    if (!publicKey) {
      throw new Error("Public key not found");
    }

    const verify = crypto.createVerify("sha256");
    verify.update(jwtData.message);
    verify.end();

    const verified = verify.verify(
      { key: publicKey.pem as string },
      Buffer.from(jwtData.signature, "base64")
    );

    return verified;
  }
}
