import { GetPublicKeyCommand, GetPublicKeyCommandOutput, KMSClient } from '@aws-sdk/client-kms';
import assert from 'assert';
import { APIGatewayEvent, APIGatewayProxyResult, Context } from 'aws-lambda';
import { exportJWK, importSPKI, JSONWebKeySet } from 'jose';
import forge from 'node-forge';

export const handler = async (event: APIGatewayEvent, context: Context): Promise<APIGatewayProxyResult> => {
  const keyManagerClient = new KMSClient({ region: 'us-east-2' })
  const keyId = getKeyId(event)
  const publicKeyGetCommand = new GetPublicKeyCommand({ KeyId: keyId })
  const publicKeyCommandResult: GetPublicKeyCommandOutput = await keyManagerClient.send(publicKeyGetCommand)
  const publicKeyAsDer = publicKeyCommandResult.PublicKey
  assert(publicKeyAsDer, "A Der Encoded Public key must be present in the Keygetcommand result")
  const pemPublicKey: string = derToPem(Buffer.from(publicKeyAsDer))
  const publicKey = await importSPKI(pemPublicKey, 'RS256', { extractable: true })
  const publicJwk = await exportJWK(publicKey)
  const jwkSet: JSONWebKeySet = {
    keys: [
      {
        ...publicJwk,
        alg: "RS256",
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
  const keyId = resource.replace('/', '')
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