import { AWS } from "./AWS";
import { KMS } from "aws-sdk";

describe("AWS", () => {
  let kms: KMS;
  let aws: AWS;

  beforeAll(async () => {
    kms = new KMS({
      endpoint: "http://localhost:8081",
      region: "us-east-1",
    });

    const key = await kms
      .createKey({
        CustomerMasterKeySpec: "RSA_2048",
        KeyUsage: "SIGN_VERIFY",
      })
      .promise();

    if (!key.KeyMetadata?.KeyId) {
      throw new Error("Failed to create key");
    }

    aws = new AWS({
      keyId: key.KeyMetadata?.KeyId,
      endpoint: "http://localhost:8081",
      region: "us-east-1",
    });
  });

  test("sign & verify", async () => {
    const jwt = await aws.sign({ test: "payload" });

    expect(aws.parse(jwt)).toEqual({
      header: {
        alg: "AWS",
        typ: "JWT",
      },
      message: expect.any(String),
      payload: {
        iat: expect.any(Date),
        test: "payload",
      },
      signature: expect.any(String),
    });

    await expect(aws.verify(jwt)).resolves.toBe(true);

    const wrongKey = await kms
      .createKey({
        CustomerMasterKeySpec: "RSA_2048",
        KeyUsage: "SIGN_VERIFY",
      })
      .promise();

    if (!wrongKey.KeyMetadata?.KeyId) {
      throw new Error("Failed to create wrongKey");
    }

    const aws2 = new AWS({
      keyId: wrongKey.KeyMetadata?.KeyId,
      endpoint: "http://localhost:8081",
      region: "us-east-1",
    });

    await expect(aws2.verify(jwt)).resolves.toBe(false);
  });

  test("sign & verify with exp", async () => {
    const jwt = await aws.sign(
      { test: "payload" },
      { exp: new Date(new Date().getTime() + 1000) }
    );

    expect(aws.parse(jwt)).toEqual({
      header: {
        alg: "AWS",
        typ: "JWT",
      },
      message: expect.any(String),
      payload: {
        iat: expect.any(Date),
        exp: expect.any(Date),
        test: "payload",
      },
      signature: expect.any(String),
    });

    await expect(aws.verify(jwt)).resolves.toBe(true);
  });

  test("fail parse with expired token", async () => {
    const jwt = await aws.sign(
      { test: "payload" },
      { exp: new Date(new Date().getTime() - 1000) }
    );

    expect(() => aws.parse(jwt)).toThrow("Token is expired");
  });
});
