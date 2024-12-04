import { GetPublicKeyCommand, GetPublicKeyCommandOutput, KMSClient } from '@aws-sdk/client-kms';
import assert from 'assert';
import { APIGatewayEvent, APIGatewayProxyResult, Context } from 'aws-lambda';
import { JSONWebKeySet, JWK } from 'jose';
import forge from 'node-forge';

export const handler = async (event: APIGatewayEvent, context: Context): Promise<APIGatewayProxyResult> => {
  const region = process.env.API_ID ?? 'us-west-2';
  const keyManagerClient = new KMSClient({ region: region })
  const keyId = getKeyId(event)
  const publicKeyGetCommand = new GetPublicKeyCommand({ KeyId: keyId })
  const publicKeyCommandResult: GetPublicKeyCommandOutput = await keyManagerClient.send(publicKeyGetCommand)
  const publicKeyAsDer = publicKeyCommandResult.PublicKey
  assert(publicKeyAsDer, "A Der Encoded Public key must be present in the Keygetcommand result")

  // Convert Uint8Array to Buffer
  const derBuffer = Buffer.from(publicKeyAsDer);

  // Decode the ASN.1 structure of the public key
  const asn1 = forge.asn1.fromDer(derBuffer.toString('binary'));

  // Convert to an RSA public key object
  const rsaKey = forge.pki.publicKeyFromAsn1(asn1) as forge.pki.rsa.PublicKey

  const n = toBase64Url(Buffer.from(rsaKey.n.toByteArray()));
  const e = toBase64Url(Buffer.from(rsaKey.e.toByteArray()));

  const publicJwk: JWK = {
    kty: 'RSA',
    n,
    e,
    "key_ops": [
      "verify"
    ],
    "ext": true,
  };

  const jwkSet: JSONWebKeySet = {
    keys: [
      {
        ...publicJwk,
        alg: "RS384",
        kid: keyId,
      }
    ]
  };
  return {
    statusCode: 200,
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(jwkSet),
  };
};

function getKeyId(event: APIGatewayEvent) {
  const resource = event.resource;
  const pathParams = event.pathParameters
  assert(resource, 'Resource must be present in the API gateway event object')
  const proxy = pathParams ? pathParams['proxy'] : undefined
  const keyId = proxy ?? resource.split('/').pop()
  return keyId;
}

// Helper function to convert Uint8Array to Base64 URL encoding
function toBase64Url(array: Uint8Array): string {
  return Buffer.from(array)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}