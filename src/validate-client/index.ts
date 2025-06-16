import { LambdaInterface } from '@aws-lambda-powertools/commons/types';
import { DynamoDBClient, GetItemCommand } from '@aws-sdk/client-dynamodb';

const dynamoDBClient = new DynamoDBClient();
const CLIENTS_TABLE_NAME = process.env.CLIENTS_TABLE_NAME || '';

export class ValidateClientFunction implements LambdaInterface {
	
	async handler(event: any): Promise<any> {
		const { client_id, client_secret, redirect_uri } = event;

		const getClientCommand = new GetItemCommand({
			TableName: CLIENTS_TABLE_NAME,
			Key: {
				client_id: { S: client_id }
			}
		});

		const clientResult = await dynamoDBClient.send(getClientCommand);

		if(!clientResult.Item) throw new Error("not-found");
		if (client_secret && clientResult.Item!.client_secret.S) {
			if (clientResult.Item!.client_secret.S !== client_secret) {
				throw new Error("invalid-client-secret");
			}
		}
		
		if(redirect_uri && !clientResult.Item!.redirect_uris.SS!.includes(redirect_uri)) {
			throw new Error("invalid-redirect-uri");

		}
		
		return {
			valid: true,
			secretClient: !!clientResult.Item!.client_secret.S,
		}

	}

}

export const handler = new ValidateClientFunction().handler.bind(new ValidateClientFunction());