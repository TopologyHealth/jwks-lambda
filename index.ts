import { APIGatewayEvent, APIGatewayProxyResult, Context } from 'aws-lambda';
import { GetPublicKeyCommand, GetPublicKeyCommandOutput, KMS, KMSClient } from '@aws-sdk/client-kms';

export const handler = async (event: APIGatewayEvent, context: Context): Promise<APIGatewayProxyResult> => {
  // console.log(`Event: ${JSON.stringify(event, null, 2)}`);
  // console.log(`Context: ${JSON.stringify(context, null, 2)}`);

  const keyManagerClient = new KMSClient({region: 'us-east-2'})
  const keyId = getKeyId(event)

  const publicKeyGetCommand = new GetPublicKeyCommand({ KeyId: keyId })
  const publicKeyCommandResult: GetPublicKeyCommandOutput = await keyManagerClient.send(publicKeyGetCommand)
  const jwkSet = {
    keys: [
      {
        kty: "RSA",
        kid: keyId,
        // n: publicKey.PublicKey.toString('base64'), // Encode modulus
        e: 'AQAB' // Use a common exponent
      }
    ]
  };

  console.log(publicKeyCommandResult)

  return {
    statusCode: 200,
    body: JSON.stringify({
      message: 'hello world',
    }),
  };
};

function getKeyId(event: APIGatewayEvent) {
  const resource = event.resource;
  const keyId = resource.replace('/', '')
  return keyId;
}
