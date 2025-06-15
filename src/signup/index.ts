import { LambdaInterface } from '@aws-lambda-powertools/commons/types';
import { DynamoDBClient, GetItemCommand, PutItemCommand } from "@aws-sdk/client-dynamodb";
import bcrypt from "bcryptjs";
import { v4 as uuid } from 'uuid';
import crypto from "crypto";
import { Logger } from '@aws-lambda-powertools/logger';

const dynamoDBClient = new DynamoDBClient();

const logger = new Logger();

const USERS_TABLE_NAME = process.env.USERS_TABLE_NAME || '';
const CLIENTS_TABLE_NAME = process.env.CLIENTS_TABLE_NAME || '';
const AUTHCODES_TABLE_NAME = process.env.AUTHCODES_TABLE_NAME || '';

export class SignupFunction implements LambdaInterface {
	
	async handler(event: any): Promise<any> {

		const { response_type, client_id, redirect_uri, scope } = event.queryStringParameters;
		const { email, password } = event.body ? JSON.parse(event.body) : {};

		if(!response_type || !client_id || !redirect_uri || !scope || !email || !password) {
			
			return {
				statusCode: 400,
				body: JSON.stringify({ error: 'Missing required data' })
			};
		}
		if (response_type === 'code') {

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

				if (clientData.Item.client_secret?.S) {
						
					if(!clientData.Item.redirect_uris?.SS?.includes(redirect_uri) ) {
						return {
							statusCode: 400,
							body: JSON.stringify({ error: 'Invalid redirect_uri' })
						};
					}
				
					if(scope != "profile") {
						return {
							statusCode: 403,
							body: JSON.stringify({ error: 'Invalid scopes' })
						}
					}

					const hashedPassword = await bcrypt.hash(password, 10);
				
					const uid = uuid();

					const createUserCommand = new PutItemCommand({
						TableName: USERS_TABLE_NAME,
						Item: {
							user_id: { S: uid },
							email: { S: email },
							password: { S: hashedPassword },
							allowed_scopes: { SS: ['profile'] },
						}
					});

					await dynamoDBClient.send(createUserCommand);
					
					const authCode = crypto.randomBytes(32).toString('hex');

					const createAuthCodeCommand = new PutItemCommand({
						TableName: AUTHCODES_TABLE_NAME,
						Item: {
							auth_code: { S: authCode },
							client_id: { S: client_id },
							redirect_uri: { S: redirect_uri },
							scope: { SS: scope.split(' ') },
							user_id: { S: uid }, 
							expires_at: { N: Math.floor((Date.now() + 300_000) / 1000).toString() }
						}
					});

					await dynamoDBClient.send(createAuthCodeCommand);

					return {
						statusCode: 201,
						body: JSON.stringify({
							authCode
						})
					}
				}
				else {
					// TODO: PKCE
					return {
						statusCode: 400,
						body: JSON.stringify({ error: 'Client does not have a client_secret' })
					};
				}

			}
			catch (error) {
				logger.error('Error processing signup', { error });
				return {
					statusCode: 500,
					body: JSON.stringify({ error: 'Internal server error' })
				};
			}

		}
		else {
			return {
				statusCode: 400,
				body: JSON.stringify({ error: 'Invalid response_type' })
			};
		}

	}
}

export const handler = new SignupFunction().handler.bind(new SignupFunction());