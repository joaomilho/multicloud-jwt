import * as crypto from "crypto";

const signer = crypto.createSign("sha256");

const keyPair = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: {
    type: "spki",
    format: "pem",
  },
  privateKeyEncoding: {
    type: "pkcs8",
    format: "pem",
    // cipher: "aes-256-cbc",
    // passphrase: "top secret",
  },
});

jest.mock("@google-cloud/kms", () => {
  return {
    KeyManagementServiceClient: class {
      cryptoKeyVersionPath() {
        return "path";
      }

      asymmetricSign(props: { name: string; digest: { sha256: string } }) {
        // TODO base64 this?
        signer.update(props.digest.sha256);
        // "base64"
        const signature = signer.sign(keyPair.privateKey);

        return [{ signature }];
      }

      getPublicKey() {
        return [{ pem: keyPair.publicKey }];
      }
    },
  };
});
// import { KeyManagementServiceClient as KMS } from "@google-cloud/kms";

import { GCP } from "./GCP";

describe("AWS", () => {
  let gcp: GCP;

  beforeAll(async () => {
    gcp = new GCP({
      projectId: "project-id",
      locationId: "location-id",
      keyRingId: "key-ring-id",
      keyId: "key-id",
      keyVersion: "key-version",
    });
  });

  test("sign & verify", async () => {
    const jwt = await gcp.sign({ test: "payload" });

    const parsed = gcp.parse(jwt);

    expect(parsed).toEqual({
      header: {
        alg: "GCP",
        typ: "JWT",
      },
      message: expect.any(String),
      payload: {
        iat: expect.any(Date),
        test: "payload",
      },
      signature: expect.any(String),
    });

    await expect(gcp.verify(jwt)).resolves.toBe(true);

    // const wrongKey = await kms
    //   .createKey({
    //     CustomerMasterKeySpec: "RSA_2048",
    //     KeyUsage: "SIGN_VERIFY",
    //   })
    //   .promise();

    // if (!wrongKey.KeyMetadata?.KeyId) {
    //   throw new Error("Failed to create wrongKey");
    // }

    // const aws2 = new AWS({
    //   keyId: wrongKey.KeyMetadata?.KeyId,
    //   endpoint: "http://localhost:8081",
    //   region: "us-east-1",
    // });

    // await expect(aws2.verify(jwt)).resolves.toBe(false);
  });
});
