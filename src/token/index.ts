import { LambdaInterface } from '@aws-lambda-powertools/commons/types';
import { DeleteItemCommand, DynamoDBClient, GetItemCommand, PutItemCommand } from "@aws-sdk/client-dynamodb";
import { Logger } from '@aws-lambda-powertools/logger';
import { GetParameterCommand, SSMClient } from '@aws-sdk/client-ssm';
import jwt from "jsonwebtoken";
import crypto from "crypto";

const dynamoDBClient = new DynamoDBClient();
const ssmClient = new SSMClient();

const logger = new Logger();

const CLIENTS_TABLE_NAME = process.env.CLIENTS_TABLE_NAME || '';
const AUTHCODES_TABLE_NAME = process.env.AUTHCODES_TABLE_NAME || '';
const REFRESHTOKENS_TABLE_NAME = process.env.REFRESHTOKENS_TABLE_NAME || '';
const JWT_SECRET_NAME = process.env.JWT_SECRET_NAME || '';

export class TokenFunction implements LambdaInterface {
	
	async handler(event: any): Promise<any> {

		const body = JSON.parse(event.body) || {};
		const { client_id, client_secret, grant_type } = body;

		if(!client_id || !grant_type) {
			return {
				statusCode: 400,
				body: JSON.stringify({ error: 'Missing required data' })
			}
		}

		if(grant_type === 'authorization_code') {

			const { code } = body;

			if(!code) {
				return {
					statusCode: 400,
					body: JSON.stringify({ error: 'Missing `code`' })
				};
			}

			const getClientCommand = new GetItemCommand({
				TableName: CLIENTS_TABLE_NAME,
				Key: {
					client_id: { S: client_id }
				},
			});

			try {


				const clientData = await dynamoDBClient.send(getClientCommand);

				if (!clientData.Item) {
					return {
						statusCode: 400,
						body: JSON.stringify({ error: 'Invalid client_id' })
					};
				}
				if(clientData.Item.client_secret?.S) {
					const getAuthCodeCommand = new GetItemCommand({
						TableName: AUTHCODES_TABLE_NAME,
						Key: {
							auth_code: { S: code }
						},
					});
					const authCodeData = await dynamoDBClient.send(getAuthCodeCommand);

					if (!authCodeData.Item || authCodeData.Item.client_id.S !== client_id) {
						return {
							statusCode: 400,
							body: JSON.stringify({ error: 'Invalid authorization code' })
						};
					}

					if(clientData.Item.client_secret.S !== client_secret) {
						return {
							statusCode: 403,
							body: JSON.stringify({ error: 'Invalid client_secret' })
						};
					}

					const jwtSecretCommand = new GetParameterCommand({
						Name: JWT_SECRET_NAME,
						WithDecryption: true,
					});

					const jwtSecret = await ssmClient.send(jwtSecretCommand);

					if (!jwtSecret.Parameter || !jwtSecret.Parameter.Value) {
						throw new Error('JWT secret not found in SSM');	
					} 

					const accessToken = jwt.sign(
						{
							client_id: client_id,
							scope: authCodeData.Item.scope.SS || [],
							iat: Math.floor(Date.now() / 1000),
							aud: authCodeData.Item.redirect_uri.S,
							sub: authCodeData.Item.user_id.S,
							exp: Math.floor(Date.now() / 1000) + (10 * 60),
						},
						jwtSecret.Parameter.Value
					);

					const refreshToken = crypto.randomBytes(64).toString('hex');

					const createRefreshTokenCommand = new PutItemCommand({
						TableName: REFRESHTOKENS_TABLE_NAME,
						Item: {
							refresh_token: { S: refreshToken },
							client_id: { S: client_id },
							user_id: { S: authCodeData.Item.user_id.S! },
							aud: { S: authCodeData.Item.redirect_uri.S! },
							expires_at: { N: Math.floor((Date.now() + 30 * 24 * 60 * 60 * 1000) / 1000).toString() },
							scope: { SS: authCodeData.Item.scope.SS || [] },
						}
					});
					
					const deleteAuthCodeCommand = new DeleteItemCommand({
						TableName: AUTHCODES_TABLE_NAME,
						Key: {
							auth_code: { S: code }
						}
					});

					await dynamoDBClient.send(deleteAuthCodeCommand);
					await dynamoDBClient.send(createRefreshTokenCommand);

					return {
						statusCode: 200,
						body: JSON.stringify({
							access_token: accessToken,
							refresh_token: refreshToken,
							token_type: 'Bearer',
						}),
					};
					
				}
				else {
					// TODO: PKCE
					return {
						statusCode: 400,
						body: JSON.stringify({ error: 'Client does not have secret.' })
					};
				}
			} 
			catch(error) {
				logger.error('Error processing authorization_code grant', { error });
				return {
					statusCode: 500,
					body: JSON.stringify({ error: 'Internal Server Error' })
				};
			}
		}
		else {
			return {
				statusCode: 400,
				body: JSON.stringify({ error: 'Unsupported grant_type' })
			};
		}
	}

}

export const handler = new TokenFunction().handler.bind(new TokenFunction());