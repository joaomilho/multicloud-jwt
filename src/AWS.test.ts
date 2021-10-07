import { AWS } from "./AWS";
import { KMS } from "aws-sdk";

test("AWS", async () => {
  const kms = new KMS({
    endpoint: "http://localhost:8081",
    region: "us-east-1",
  });

  const key = await kms
    .createKey({
      CustomerMasterKeySpec: "RSA_2048",
      KeyUsage: "SIGN_VERIFY",
    })
    .promise();

  const keyId = key.KeyMetadata.KeyId;

  const aws = new AWS({
    keyId,
    endpoint: "http://localhost:8081",
    region: "us-east-1",
  });

  const jwt = await aws.sign({ test: "payload" });

  expect(aws.parse(jwt)).toEqual({
    header: {
      alg: "AWS",
      typ: "JWT",
    },
    message: expect.any(String),
    payload: {
      iat: expect.any(Number),
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

  const wrongKeyId = wrongKey.KeyMetadata.KeyId;

  const aws2 = new AWS({
    keyId: wrongKeyId,
    endpoint: "http://localhost:8081",
    region: "us-east-1",
  });

  await expect(aws2.verify(jwt)).resolves.toBe(false);
});
