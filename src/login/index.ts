import { LambdaInterface } from '@aws-lambda-powertools/commons/types';
import { DynamoDBClient, PutItemCommand, QueryCommand } from "@aws-sdk/client-dynamodb";
import { LambdaClient, InvokeCommand } from "@aws-sdk/client-lambda"; 
import bcrypt from "bcryptjs";
import crypto from "crypto";
import { Logger } from '@aws-lambda-powertools/logger';

const dynamoDBClient = new DynamoDBClient();
const lambdaClient = new LambdaClient();

const logger = new Logger();

const USERS_TABLE_NAME = process.env.USERS_TABLE_NAME || '';
const AUTHCODES_TABLE_NAME = process.env.AUTHCODES_TABLE_NAME || '';
const VALIDATECLIENTLAMBDA_FUNCTION_NAME = process.env.VALIDATECLIENTLAMBDA_FUNCTION_NAME || '';

export class LoginFunction implements LambdaInterface {
	
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

				if (existingUser.Count == 0) {
					return {
						statusCode: 401,
						body: JSON.stringify({ error: 'Invalid username or password.' })
					};
				}

				const isMatching = await bcrypt.compare(password, existingUser.Items![0].password.S!);
			
				if(!isMatching) {
					return {
						statusCode: 401,
						body: JSON.stringify({ error: 'Invalid username or password.' })
					};
				}
			
				const scopes = scope.split(" ").filter(item => existingUser.Items![0].allowed_scopes.SS!.includes(item));
	
				const authCode = crypto.randomBytes(32).toString('hex');

				let itemObject: { [key: string]: any } = {
					auth_code: { S: authCode },
					client_id: { S: client_id },
					redirect_uri: { S: redirect_uri },
					scope: { SS: scopes },
					user_id: { S: existingUser.Items![0].user_id.S! }, 
					expires_at: { N: Math.floor((Date.now() + 300_000) / 1000).toString() }
				};

				if (!data.secretClient) {
					const { code_challenge, code_challenge_method } = event.queryStringParameters;

					if(!code_challenge || !code_challenge_method) {
						return {
							statusCode: 400,
							body: JSON.stringify({ error: 'Missing `code_challenge` or `code_challenge_method`' })
						}
					}

					if(!["S256", "plain"].includes(code_challenge_method)) {
						return {
							statusCode: 400,
							body: JSON.stringify({ error: 'Invalid `code_challenge_method' })
						}
					}

					itemObject.code_challenge = { S: code_challenge };
					itemObject.code_challenge_method = { S: code_challenge_method };

				}
				const createAuthCodeCommand = new PutItemCommand({
					TableName: AUTHCODES_TABLE_NAME,
					Item: itemObject
				});

				await dynamoDBClient.send(createAuthCodeCommand);

				return {
					statusCode: 200,
					body: JSON.stringify({
						authCode
					})
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

export const handler = new LoginFunction().handler.bind(new LoginFunction());