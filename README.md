# multicloud-jwt

A lib to _sign_ JWT tokens using keys in AWS and GCP's KMS.

## Usage

```ts
// AWS
import { AWS } from 'multicloud-jwt'

const aws = new AWS(...props)

const jwt = aws.sign({ my: "payload" })

aws.verify(jwt) // true

// GCP
import { GCP } from 'multicloud-jwt'

const gcp = new GCP(...props)

const jwt = gcp.sign({ my: "payload" })

gcp.verify(jwt) // true
```