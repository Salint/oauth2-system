import { LambdaInterface } from '@aws-lambda-powertools/commons/types';
import { DeleteItemCommand, DynamoDBClient, GetItemCommand, PutItemCommand } from "@aws-sdk/client-dynamodb";
import { Logger } from '@aws-lambda-powertools/logger';
import { GetParameterCommand, SSMClient } from '@aws-sdk/client-ssm';
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { LambdaClient, InvokeCommand } from '@aws-sdk/client-lambda';

const dynamoDBClient = new DynamoDBClient();
const ssmClient = new SSMClient();
const lambdaClient = new LambdaClient

const logger = new Logger();

const VALIDATECLIENTLAMBDA_FUNCTION_NAME = process.env.VALIDATECLIENTLAMBDA_FUNCTION_NAME || '';
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
				body: JSON.stringify({ error: 'Missing `code`' })
			}
		}

		const validateClientCommand = new InvokeCommand({
			FunctionName: VALIDATECLIENTLAMBDA_FUNCTION_NAME,
			Payload: JSON.stringify({
				client_id,
				client_secret
			})
		});

		const validateClientResult = await lambdaClient.send(validateClientCommand);

		if(validateClientResult.FunctionError) {
			const error = JSON.parse(new TextDecoder().decode(validateClientResult.Payload));

			if(error.errorMessage === "not-found") {
				return {
					statusCode: 400,
					body: JSON.stringify({ error: 'Invalid client_id' })
				};
			}
			else if(error.errorMessage === "invalid-redirect-uri") {
				return {
					statusCode: 400,
					body: JSON.stringify({ error: "Invalid redirect_uri" })
				}
			}
		}
		const data = JSON.parse(new TextDecoder().decode(validateClientResult.Payload));

		if(grant_type === "authorization_code") {

			const { code } = body;

			if(!code) {
				return {
					statusCode: 400,
					body: JSON.stringify({ error: 'Missing `code`' })
				};
			}

			try {

				if (data.secretClient) {
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
		else if(grant_type === "refresh_token") {

			try {
				
					
				const { refresh_token: refreshToken } = body;

				if(!refreshToken) {
					return {
						statusCode: 400,
						body: JSON.stringify({ error: 'Missing `refresh_token`' })
					}
				}


				const removeToken = new DeleteItemCommand({
					TableName: REFRESHTOKENS_TABLE_NAME,
					Key: {
						refresh_token: { S: refreshToken }
					},
					ConditionExpression: "client_id = :clientId",
					ExpressionAttributeValues: {
						"clientId": client_id
					},
					ReturnValues: "ALL_OLD"
				});

				const refreshTokenResult = await dynamoDBClient.send(removeToken);

				if(!refreshTokenResult.Attributes) {
					return {
						statusCode: 401, 
						body: JSON.stringify({ error: 'Invalid refresh token' })
					}
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
						scope:refreshTokenResult.Attributes!.scope.SS!,
						iat: Math.floor(Date.now() / 1000),
						aud: refreshTokenResult.Attributes!.aud.S!,
						sub: refreshTokenResult.Attributes!.user_id.S!,
						exp: Math.floor(Date.now() / 1000) + (10 * 60),
					},
					jwtSecret.Parameter.Value
				);

				const newRefreshToken = crypto.randomBytes(64).toString('hex');

				const createRefreshTokenCommand = new PutItemCommand({
					TableName: REFRESHTOKENS_TABLE_NAME,
					Item: {
						refresh_token: { S: newRefreshToken },
						client_id: { S: client_id },
						user_id: { S: refreshTokenResult.Attributes!.user_id.S! },
						aud: { S: refreshTokenResult.Attributes!.aud.S! },
						expires_at: { N: Math.floor((Date.now() + 30 * 24 * 60 * 60 * 1000) / 1000).toString() },
						scope: { SS: refreshTokenResult.Attributes!.scope.SS! },
					}
				});

				await dynamoDBClient.send(createRefreshTokenCommand);

				return {
					statusCode: 200,
					body: JSON.stringify({
						access_token: accessToken,
						refresh_token: newRefreshToken,
						token_type: 'Bearer',
					}),
				};

			} catch(error) {
				logger.error('Error processing refresh_token grant', { error });
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