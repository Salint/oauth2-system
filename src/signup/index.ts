import { LambdaInterface } from '@aws-lambda-powertools/commons/types';
import { DynamoDBClient, PutItemCommand, QueryCommand } from "@aws-sdk/client-dynamodb";
import bcrypt from "bcryptjs";
import { v4 as uuid } from 'uuid';
import crypto from "crypto";
import { Logger } from '@aws-lambda-powertools/logger';
import { InvokeCommand, LambdaClient } from '@aws-sdk/client-lambda';

const dynamoDBClient = new DynamoDBClient();
const lambdaClient = new LambdaClient();

const logger = new Logger();

const USERS_TABLE_NAME = process.env.USERS_TABLE_NAME || '';
const AUTHCODES_TABLE_NAME = process.env.AUTHCODES_TABLE_NAME || '';
const VALIDATECLIENTLAMBDA_FUNCTION_NAME = process.env.VALIDATECLIENTLAMBDA_FUNCTION_NAME || '';

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

			try {
				const validateClientCommand = new InvokeCommand({
					FunctionName: VALIDATECLIENTLAMBDA_FUNCTION_NAME,
					Payload: JSON.stringify({
						client_id,
						redirect_uri
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

				if (data.secretClient) {
				
					if(scope != "profile") {
						return {
							statusCode: 403,
							body: JSON.stringify({ error: 'Invalid scopes' })
						}
					}

					const getUserCommand = new QueryCommand({
						TableName: USERS_TABLE_NAME,
						IndexName: "email-index",
						KeyConditionExpression: "email = :email",
						ExpressionAttributeValues: {
							":email": { S: email }
						},
						Limit: 1
					});

					const existingUser = await dynamoDBClient.send(getUserCommand);

					if (existingUser.Items?.length != 0) {
						return {
							statusCode: 409,
							body: JSON.stringify({ error: 'User already exists' })
						};
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