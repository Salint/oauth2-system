import { LambdaInterface } from '@aws-lambda-powertools/commons/types';
import { GetParameterCommand, SSMClient } from '@aws-sdk/client-ssm';
import jwt from "jsonwebtoken";

const ssmClient = new SSMClient();

const JWT_SECRET_NAME = process.env.JWT_SECRET_NAME || '';

export class TokenFunction implements LambdaInterface {
	
	async handler(event: any): Promise<any> {

		const body = JSON.parse(event.body) || {};
		const { token } = body;

		const jwtSecretCommand = new GetParameterCommand({
			Name: JWT_SECRET_NAME,
		});

		const jwtSecret = await ssmClient.send(jwtSecretCommand);

		if (!jwtSecret.Parameter || !jwtSecret.Parameter.Value) {
			throw new Error('JWT secret not found in SSM');	
		} 

		try {
			jwt.verify(token, jwtSecret.Parameter.Value);

			return {
				statusCode: 200
			}
		}
		catch(error) {
			return {
				statuscode: 401
			}
		}
	}

}

export const handler = new TokenFunction().handler.bind(new TokenFunction());