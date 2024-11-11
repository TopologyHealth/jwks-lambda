import { GetPublicKeyCommand, GetPublicKeyCommandOutput, KMSClient } from '@aws-sdk/client-kms';
import assert from 'assert';
import { APIGatewayEvent, APIGatewayProxyResult, Context } from 'aws-lambda';
import { JSONWebKeySet, JWK } from 'jose';
import forge from 'node-forge';

export const handler = async (event: APIGatewayEvent, context: Context): Promise<APIGatewayProxyResult> => {
  const keyManagerClient = new KMSClient({ region: 'us-east-2' })
  const keyId = getKeyId(event)
  const publicKeyGetCommand = new GetPublicKeyCommand({ KeyId: keyId })
  const publicKeyCommandResult: GetPublicKeyCommandOutput = await keyManagerClient.send(publicKeyGetCommand)
  const publicKeyAsDer = publicKeyCommandResult.PublicKey
  assert(publicKeyAsDer, "A Der Encoded Public key must be present in the Keygetcommand result")
  // const pemPublicKey: string = derToPem(Buffer.from(publicKeyAsDer))
  // const publicKey = await importSPKI(pemPublicKey, 'RS256', { extractable: true })
  // const publicJwk = await exportJWK(publicKey)

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
  assert(resource, 'Resource must be present in the API gateway event object')
  const keyId = resource.split('/').pop()
  return keyId;
}

/**
 * Converts DER-encoded public key to PEM format using node-forge.
 * @param der Public key in DER format as a Buffer or Uint8Array.
 * @returns PEM-encoded public key as a string.
 */
function derToPem(der: Buffer): string {
  // Convert DER to Forge's Asn1 format
  const asn1 = forge.asn1.fromDer(der.toString('binary'));

  // Convert Asn1 to public key object
  const publicKey = forge.pki.publicKeyFromAsn1(asn1);

  // Convert public key to PEM format
  const pem = forge.pki.publicKeyToPem(publicKey);
  return pem;
}

// Helper function to convert Uint8Array to Base64 URL encoding
function toBase64Url(array: Uint8Array): string {
  return Buffer.from(array)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}