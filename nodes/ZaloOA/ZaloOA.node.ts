import {
	IDataObject,
	IExecuteFunctions,
	INodeExecutionData,
	INodeType,
	INodeTypeDescription,
	NodeConnectionType,
	NodeOperationError,
} from 'n8n-workflow';

/**
 * Zalo OA API v3.0 Implementation
 *
 * Changes from v2.0 to v3.0:
 * - MessageV2 API has been deprecated and shut down
 * - MessageV3 API requires specifying the message type in the endpoint:
 *   - Customer Service: /message/cs
 *   - Transaction: /message/transaction
 *   - Promotion: /message/promotion
 *
 * This implementation uses the v3.0 API base URL and proper message endpoints
 * with the required message types passed as parameters.
 */

import { zaloOAOperations, zaloOAFields } from './ZaloOADescription';
import axios from 'axios';
import FormData from 'form-data';
import { ZaloOATokenClient } from './shared/ZaloOATokenClient';

export class ZaloOA implements INodeType {
	description: INodeTypeDescription = {
		displayName: 'Zalo OA',
		name: 'zaloOA',
		icon: 'file:zalooa.svg',
		group: ['transform'],
		version: 1,
		subtitle: '={{$parameter["operation"] + ": " + $parameter["resource"]}}',
		description: 'Tương tác với Zalo Official Account API',
		defaults: {
			name: 'Zalo OA',
		},
		inputs: [NodeConnectionType.Main],
		outputs: [NodeConnectionType.Main],
		credentials: [
			{
				name: 'zaloOAApi',
				required: true,
			},
		],
		properties: [
			{
				displayName: 'Resource',
				name: 'resource',
				type: 'options',
				noDataExpression: true,
				options: [
					{
						name: 'Zalo OA',
						value: 'zaloOA',
					},
				],
				default: 'zaloOA',
			},
			...zaloOAOperations,
			...zaloOAFields,
		],
	};

	async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
		const items = this.getInputData();
		const returnData: INodeExecutionData[] = [];
		const resource = this.getNodeParameter('resource', 0) as string;
		const operation = this.getNodeParameter('operation', 0) as string;
		const credentials = await this.getCredentials('zaloOAApi');

		const tokenClient = new ZaloOATokenClient(this, credentials as unknown as IDataObject);
		const baseUrl = 'https://openapi.zalo.me/v3.0/oa';

		// Xử lý các operations khác nhau
		for (let i = 0; i < items.length; i++) {
			try {
				if (resource === 'zaloOA') {
					// Gửi tin nhắn văn bản
					if (operation === 'sendTextMessage') {
						const userId = this.getNodeParameter('userId', i) as string;
						const text = this.getNodeParameter('text', i) as string;

						// Get message type (cs, transaction, promotion)
						const messageType = this.getNodeParameter('messageType', i) as string || "cs";

						// MessageV3 API format
						const response = await tokenClient.request({
							method: 'POST',
							url: `${baseUrl}/message/${messageType}`,
							data: {
								recipient: {
									user_id: userId,
								},
								message: {
									text,
								},
							},
							headers: {
								'Content-Type': 'application/json',
							},
						});

						returnData.push({
							json: response.data,
							pairedItem: {
								item: i,
							},
						});
					}

					// Gửi tin nhắn hình ảnh
					else if (operation === 'sendImageMessage') {
						const userId = this.getNodeParameter('userId', i) as string;
						const imageType = this.getNodeParameter('imageType', i) as string;
						let attachment;

						if (imageType === 'imageUrl') {
							const imageUrl = this.getNodeParameter('imageUrl', i) as string;
							attachment = {
								type: 'template',
								payload: {
									template_type: 'media',
									elements: [
										{
											media_type: 'image',
											url: imageUrl,
										},
									],
								},
							};
						} else {
							const imageId = this.getNodeParameter('imageId', i) as string;
							attachment = {
								type: 'template',
								payload: {
									template_type: 'media',
									elements: [
										{
											media_type: 'image',
											attachment_id: imageId,
										},
									],
								},
							};
						}

						// Get message type (cs, transaction, promotion)
						const messageType = this.getNodeParameter('messageType', i) as string;

						// MessageV3 API format
						const response = await tokenClient.request({
							method: 'POST',
							url: `${baseUrl}/message/${messageType}`,
							data: {
								recipient: {
									user_id: userId,
								},
								message: {
									attachment,
								},
							},
							headers: {
								'Content-Type': 'application/json',
							},
						});

						returnData.push({
							json: response.data,
							pairedItem: {
								item: i,
							},
						});
					}

					// Gửi tin nhắn file
					else if (operation === 'sendFileMessage') {
						const userId = this.getNodeParameter('userId', i) as string;
						const fileId = this.getNodeParameter('fileId', i) as string;

						// Get message type (cs, transaction, promotion)
						const messageType = this.getNodeParameter('messageType', i) as string;

						// MessageV3 API format
						const response = await tokenClient.request({
							method: 'POST',
							url: `${baseUrl}/message/${messageType}`,
							data: {
								recipient: {
									user_id: userId,
								},
								message: {
									attachment: {
										type: 'file',
										payload: {
											token: fileId,
										},
									},
								},
							},
							headers: {
								'Content-Type': 'application/json',
							},
						});

						returnData.push({
							json: response.data,
							pairedItem: {
								item: i,
							},
						});
					}

					// Gửi tin nhắn danh sách
					else if (operation === 'sendListMessage') {
						const userId = this.getNodeParameter('userId', i) as string;
						const listTitle = this.getNodeParameter('title', i) as string;
						const elementsCollection = this.getNodeParameter('elements', i) as {
							elementsValues: Array<{
								title: string;
								subtitle: string;
								imageUrl: string;
								defaultActionUrl: string;
							}>;
						};

						const elements = elementsCollection.elementsValues.map((element) => ({
							title: element.title,
							subtitle: element.subtitle,
							image_url: element.imageUrl,
							default_action: {
								type: 'oa.open.url',
								url: element.defaultActionUrl,
							},
						}));

						// Get message type (cs, transaction, promotion)
						const messageType = this.getNodeParameter('messageType', i) as string;

						// MessageV3 API format
						const response = await tokenClient.request({
							method: 'POST',
							url: `${baseUrl}/message/${messageType}`,
							data: {
								recipient: {
									user_id: userId,
								},
								message: {
									attachment: {
										type: 'template',
										payload: {
											template_type: 'list',
											elements,
											buttons: [
												{
													title: listTitle,
													type: 'oa.open.url',
													payload: {
														url: 'https://zalo.me',
													},
												},
											],
										},
									},
								},
							},
							headers: {
								'Content-Type': 'application/json',
							},
						});

						returnData.push({
							json: response.data,
							pairedItem: {
								item: i,
							},
						});
					}

					// Lấy thông tin người theo dõi
					else if (operation === 'getFollowerInfo') {
						const userId = this.getNodeParameter('userId', i) as string;

						try {
							// Sử dụng API v3.0 để lấy thông tin người theo dõi
							// Theo hướng dẫn của Zalo, API getprofile đã được thay thế bằng API user/detail
							const v3BaseUrl = 'https://openapi.zalo.me/v3.0/oa';

							// Tạo data parameter cho API user/detail
							const dataParam = JSON.stringify({
								user_id: userId,
							});

							// Gọi API lấy thông tin người theo dõi
							const response = await tokenClient.request({
								method: 'GET',
								url: `${v3BaseUrl}/user/detail`,
								params: {
									data: dataParam,
								},
								headers: {
									'Content-Type': 'application/json',
								},
							});

							returnData.push({
								json: response.data,
								pairedItem: {
									item: i,
								},
							});
						} catch (error) {
							// Log lỗi để debug
							console.log('Lỗi khi gọi API user/detail v3.0:', error.message);

							// Trả về lỗi để người dùng biết
							returnData.push({
								json: {
									error: true,
									message: `Lỗi khi gọi API lấy thông tin người dùng: ${error.message}`,
									note: 'Zalo đã thay đổi API getprofile sang API user/detail trong v3.0. Vui lòng kiểm tra lại cấu hình OA và quyền truy cập.',
									suggestion: 'Hãy đảm bảo rằng bạn đã cấp quyền "Quyền quản lý thông tin người dùng" cho ứng dụng và có access_token hợp lệ.',
								},
								pairedItem: {
									item: i,
								},
							});
						}
					}

					// Upload hình ảnh
					else if (operation === 'uploadImage') {
						const binaryData = this.getNodeParameter('binaryData', i) as boolean;
						let response;

						try {
							if (binaryData) {
								const binaryProperty = this.getNodeParameter('binaryProperty', i) as string;
								const binaryFile = items[i].binary![binaryProperty];

								if (binaryFile === undefined) {
									throw new NodeOperationError(
										this.getNode(),
										`No binary data property "${binaryProperty}" exists on item.`,
										{ itemIndex: i },
									);
								}

								const buffer = await this.helpers.getBinaryDataBuffer(i, binaryProperty);

								// Tạo FormData đúng cách
								const formData = new FormData();
								formData.append('file', buffer, {
									filename: binaryFile.fileName || 'image.jpg',
									contentType: binaryFile.mimeType,
								});

								// Log để debug
								console.log(`Uploading image with filename: ${binaryFile.fileName}, mime type: ${binaryFile.mimeType}`);

								// Gửi request để upload hình ảnh
								response = await tokenClient.request({
									method: 'POST',
									url: `${baseUrl}/upload/image`,
									data: formData,
									headers: {
										...formData.getHeaders(),
									},
								});
							} else {
								const imageUrl = this.getNodeParameter('imageUrl', i) as string;

								// Log để debug
								console.log(`Uploading image from URL: ${imageUrl}`);

								response = await tokenClient.request({
									method: 'POST',
									url: `${baseUrl}/upload/image`,
									data: {
										url: imageUrl,
									},
									headers: {
										'Content-Type': 'application/json',
									},
								});
							}

							// Log response để debug
							console.log('Upload image response:', JSON.stringify(response.data));

							returnData.push({
								json: response.data,
								pairedItem: {
									item: i,
								},
							});
						} catch (error) {
							// Log lỗi chi tiết để debug
							console.log('Lỗi khi upload hình ảnh:', error.message);
							if (error.response) {
								console.log('Response status:', error.response.status);
								console.log('Response data:', JSON.stringify(error.response.data));
							}

							// Trả về lỗi để người dùng biết
							returnData.push({
								json: {
									error: true,
									message: `Lỗi khi upload hình ảnh: ${error.message}`,
									response: error.response?.data || {},
									suggestion: 'Hãy kiểm tra định dạng hình ảnh và quyền truy cập của OA.',
								},
								pairedItem: {
									item: i,
								},
							});
						}
					}

					// Upload file
					else if (operation === 'uploadFile') {
						const binaryData = this.getNodeParameter('binaryData', i) as boolean;
						let response;

						try {
							if (binaryData) {
								const binaryProperty = this.getNodeParameter('binaryProperty', i) as string;
								const binaryFile = items[i].binary?.[binaryProperty];

								if (binaryFile === undefined) {
									throw new NodeOperationError(
										this.getNode(),
										`No binary data property "${binaryProperty}" exists on item.`,
										{ itemIndex: i },
									);
								}

								const buffer = await this.helpers.getBinaryDataBuffer(i, binaryProperty);

								// Create FormData
								const formData = new FormData();
								formData.append('file', buffer, {
									filename: binaryFile.fileName || 'file.pdf',
									contentType: binaryFile.mimeType,
								});

								// Log for debugging
								console.log(`Uploading file with filename: ${binaryFile.fileName}, mime type: ${binaryFile.mimeType}`);

								// Send request to upload file
								response = await tokenClient.request({
									method: 'POST',
									url: `${baseUrl}/upload/file`,
									data: formData,
									headers: {
										...formData.getHeaders(),
									},
								});
							} else {
								const fileUrl = this.getNodeParameter('fileUrl', i) as string;

								// Log for debugging
								console.log(`Uploading file from URL: ${fileUrl}`);

								response = await tokenClient.request({
									method: 'POST',
									url: `${baseUrl}/upload/file`,
									data: {
										url: fileUrl,
									},
									headers: {
										'Content-Type': 'application/json',
									},
								});
							}

							// Log response for debugging
							console.log('Upload file response:', JSON.stringify(response.data));

							returnData.push({
								json: response.data,
								pairedItem: {
									item: i,
								},
							});
						} catch (error) {
							// Log detailed error for debugging
							console.log('Error uploading file:', error.message);
							if (error.response) {
								console.log('Response status:', error.response.status);
								console.log('Response data:', JSON.stringify(error.response.data));
							}

							// Return error to user
							returnData.push({
								json: {
									error: true,
									message: `Error uploading file: ${error.message}`,
									response: error.response?.data || {},
									suggestion: 'Please check the file format and OA access permissions.',
								},
								pairedItem: {
									item: i,
								},
							});
						}
					}

					// Lấy danh sách tag
					else if (operation === 'getTags') {
						const offset = this.getNodeParameter('offset', i) as number;
						const count = this.getNodeParameter('count', i) as number;

						try {
							// Log để debug
							console.log(`Lấy danh sách tag với offset: ${offset}, count: ${count}`);

							// Thử gọi API v3.0 trước
							const response = await tokenClient.request({
								method: 'GET',
								url: `${baseUrl}/tag/gettagsofoa`,
								params: {
									offset,
									count,
								},
							});

							// Log response để debug
							console.log('Kết quả lấy danh sách tag:', JSON.stringify(response.data));

							// Xử lý dữ liệu trả về để hiển thị rõ ràng tag_id và tag_name
							let processedData: any = response.data;

							// Kiểm tra nếu có dữ liệu tags trong response
							if (processedData.data && Array.isArray(processedData.data.tags)) {
								// Thêm trường display_info để hiển thị thông tin rõ ràng
								processedData.data.tags = processedData.data.tags.map((tag: any) => {
									// Đảm bảo tag có cả tag_id và tag_name
									const tagId = tag.tag_id || tag.id || '';
									const tagName = tag.tag_name || tag.name || '';

									return {
										...tag,
										tag_id: tagId,
										tag_name: tagName,
										display_info: `ID: ${tagId} - Name: ${tagName}`
									};
								});

								// Thêm hướng dẫn sử dụng
								processedData.usage_guide = {
									message: 'Sử dụng tag_id hoặc tag_name trong các node gắn tag hoặc xóa tag',
									example: 'Khi gắn tag cho người dùng, hãy sử dụng giá trị tag_id hoặc tag_name từ danh sách này'
								};
							}

							returnData.push({
								json: processedData,
								pairedItem: {
									item: i,
								},
							});
						} catch (error) {
							// Log lỗi để debug
							console.log('Lỗi khi gọi API gettagsofoa v3.0:', error.message);
							if (error.response) {
								console.log('Response status:', error.response.status);
								console.log('Response data:', JSON.stringify(error.response.data));
							}
							console.log('Đang thử lại với API v2.0...');

							try {
								// Nếu API v3.0 thất bại, thử gọi API v2.0
								const v2BaseUrl = 'https://openapi.zalo.me/v2.0/oa';
								const response = await tokenClient.request({
									method: 'GET',
									url: `${v2BaseUrl}/tag/gettagsofoa`,
									params: {
										offset,
										count,
									},
								});

								// Log response để debug
								console.log('Kết quả lấy danh sách tag (API v2.0):', JSON.stringify(response.data));

								// Xử lý dữ liệu trả về để hiển thị rõ ràng tag_id và tag_name
								let processedData: any = response.data;

								// Kiểm tra nếu có dữ liệu tags trong response
								if (processedData.data && Array.isArray(processedData.data.tags)) {
									// Thêm trường display_info để hiển thị thông tin rõ ràng
									processedData.data.tags = processedData.data.tags.map((tag: any) => {
										// Đảm bảo tag có cả tag_id và tag_name
										const tagId = tag.tag_id || tag.id || '';
										const tagName = tag.tag_name || tag.name || '';

										return {
											...tag,
											tag_id: tagId,
											tag_name: tagName,
											display_info: `ID: ${tagId} - Name: ${tagName}`
										};
									});

									// Thêm hướng dẫn sử dụng
									processedData.usage_guide = {
										message: 'Sử dụng tag_id hoặc tag_name trong các node gắn tag hoặc xóa tag',
										example: 'Khi gắn tag cho người dùng, hãy sử dụng giá trị tag_id hoặc tag_name từ danh sách này'
									};
								}

								returnData.push({
									json: processedData,
									pairedItem: {
										item: i,
									},
								});
							} catch (innerError) {
								// Log lỗi chi tiết để debug
								console.log('Lỗi khi gọi API gettagsofoa v2.0:', innerError.message);
								if (innerError.response) {
									console.log('Response status:', innerError.response.status);
									console.log('Response data:', JSON.stringify(innerError.response.data));
								}

								// Trả về lỗi để người dùng biết
								returnData.push({
									json: {
										error: true,
										message: `Lỗi khi lấy danh sách tag: ${innerError.message}`,
										response: innerError.response?.data || {},
										suggestion: 'Vui lòng kiểm tra lại quyền truy cập của OA và access_token.',
									},
									pairedItem: {
										item: i,
									},
								});
							}
						}
					}

					// Gán tag cho người theo dõi
					else if (operation === 'assignTag') {
						try {
							const userId = this.getNodeParameter('userId', i) as string;
							const tagId = this.getNodeParameter('tagId', i) as string;

							// Log để debug
							console.log(`Gán tag cho người dùng với user_id: ${userId}, tag_id: ${tagId}`);

							// Trong API v3, endpoint vẫn là /tag/taguser nhưng cần sử dụng tag_name thay vì tag_id
							// Vì hiện tại chúng ta đang sử dụng tag_id, chúng ta sẽ thử cả hai cách

							// Cách 1: Sử dụng tag_id (cách cũ)
							try {
								const response = await tokenClient.request({
									method: 'POST',
									url: `${baseUrl}/tag/taguser`,
									data: {
										user_id: userId,
										tag_id: tagId,
									},
									headers: {
										'Content-Type': 'application/json',
									},
								});

								// Log response để debug
								console.log('Kết quả gán tag (sử dụng tag_id):', JSON.stringify(response.data));

								returnData.push({
									json: response.data,
									pairedItem: {
										item: i,
									},
								});
								// Nếu thành công, bỏ qua cách 2
								break;
							} catch (error) {
								// Log lỗi để debug
								console.log('Lỗi khi gán tag sử dụng tag_id:', error.message);
								if (error.response) {
									console.log('Response status:', error.response.status);
									console.log('Response data:', JSON.stringify(error.response.data));
								}
								// Tiếp tục thử cách 2
							}

							// Cách 2: Sử dụng tag_name (cách mới trong API v3)
							try {
								const response = await tokenClient.request({
									method: 'POST',
									url: `${baseUrl}/tag/taguser`,
									data: {
										user_id: userId,
										tag_name: tagId, // Sử dụng tagId như là tag_name
									},
									headers: {
										'Content-Type': 'application/json',
									},
								});

								// Log response để debug
								console.log('Kết quả gán tag (sử dụng tag_name):', JSON.stringify(response.data));

								returnData.push({
									json: response.data,
									pairedItem: {
										item: i,
									},
								});
							} catch (error) {
								// Log lỗi để debug
								console.log('Lỗi khi gán tag sử dụng tag_name:', error.message);
								if (error.response) {
									console.log('Response status:', error.response.status);
									console.log('Response data:', JSON.stringify(error.response.data));
								}

								// Trả về lỗi để người dùng biết
								returnData.push({
									json: {
										error: true,
										message: `Lỗi khi gán tag cho người dùng: ${error.message}`,
										response: error.response?.data || {},
										suggestion: 'Vui lòng kiểm tra lại user_id và tag_id/tag_name. API v3 yêu cầu sử dụng tag_name thay vì tag_id.',
									},
									pairedItem: {
										item: i,
									},
								});
							}
						} catch (error) {
							// Log lỗi chi tiết để debug
							console.log('Lỗi khi gán tag cho người dùng:', error.message);
							if (error.response) {
								console.log('Response status:', error.response.status);
								console.log('Response data:', JSON.stringify(error.response.data));
							}

							// Trả về lỗi để người dùng biết
							returnData.push({
								json: {
									error: true,
									message: `Lỗi khi gán tag cho người dùng: ${error.message}`,
									response: error.response?.data || {},
									suggestion: 'Vui lòng kiểm tra lại user_id và tag_id/tag_name. API v3 yêu cầu sử dụng tag_name thay vì tag_id.',
								},
								pairedItem: {
									item: i,
								},
							});
						}
					}

					// Lấy thông tin Official Account
					else if (operation === 'getOAProfile') {
						// API GET OA Profile không cần tham số bổ sung
						try {
							// Thử gọi API v3.0 trước
							const response = await tokenClient.request({
								method: 'GET',
								url: `${baseUrl}/getoa`,
								headers: {
									'Content-Type': 'application/json',
								},
							});

							returnData.push({
								json: response.data,
								pairedItem: {
									item: i,
								},
							});
						} catch (error) {
							// Log lỗi để debug
							console.log('Lỗi khi gọi API getoa v3.0:', error.message);
							console.log('Đang thử lại với API v2.0...');

							// Nếu API v3.0 thất bại, thử gọi API v2.0
							const v2BaseUrl = 'https://openapi.zalo.me/v2.0/oa';
							const response = await tokenClient.request({
								method: 'GET',
								url: `${v2BaseUrl}/getoa`,
								headers: {
									'Content-Type': 'application/json',
								},
							});

							returnData.push({
								json: response.data,
								pairedItem: {
									item: i,
								},
							});
						}
					}

					// Lấy danh sách người theo dõi
					else if (operation === 'getFollowers') {
						const offset = this.getNodeParameter('offset', i) as number;
						const count = this.getNodeParameter('count', i) as number;

						try {
							// Sử dụng API v3.0 để lấy danh sách người theo dõi
							// Theo hướng dẫn của Zalo, API getfollowers đã được thay thế bằng API user/getlist
							const v3BaseUrl = 'https://openapi.zalo.me/v3.0/oa';

							// Tạo data parameter cho API user/getlist
							const dataParam = JSON.stringify({
								offset,
								count: Math.min(count, 50), // Giới hạn tối đa 50 người theo dõi mỗi lần gọi
								is_follower: 'true', // Chỉ lấy người dùng đang theo dõi OA
							});

							// Gọi API lấy danh sách người theo dõi
							const response = await tokenClient.request({
								method: 'GET',
								url: `${v3BaseUrl}/user/getlist`,
								params: {
									data: dataParam,
								},
								headers: {
									'Content-Type': 'application/json',
								},
							});

							returnData.push({
								json: response.data,
								pairedItem: {
									item: i,
								},
							});
						} catch (error) {
							// Log lỗi để debug
							console.log('Lỗi khi gọi API user/getlist v3.0:', error.message);

							// Trả về lỗi để người dùng biết
							returnData.push({
								json: {
									error: true,
									message: `Lỗi khi gọi API lấy danh sách người theo dõi: ${error.message}`,
									note: 'Zalo đã thay đổi API getfollowers sang API user/getlist trong v3.0. Vui lòng kiểm tra lại cấu hình OA và quyền truy cập.',
									suggestion: 'Hãy đảm bảo rằng bạn đã cấp quyền đầy đủ cho ứng dụng và có access_token hợp lệ.',
								},
								pairedItem: {
									item: i,
								},
							});
						}
					}

					// Upload GIF image
					else if (operation === 'uploadGif') {
						const binaryData = this.getNodeParameter('binaryData', i) as boolean;
						let response;

						try {
							if (binaryData) {
								const binaryProperty = this.getNodeParameter('binaryProperty', i) as string;
								const binaryFile = items[i].binary?.[binaryProperty];

								if (binaryFile === undefined) {
									throw new NodeOperationError(
										this.getNode(),
										`No binary data property "${binaryProperty}" exists on item.`,
										{ itemIndex: i },
									);
								}

								const buffer = await this.helpers.getBinaryDataBuffer(i, binaryProperty);

								// Create FormData
								const formData = new FormData();
								formData.append('file', buffer, {
									filename: binaryFile.fileName || 'image.gif',
									contentType: binaryFile.mimeType,
								});

								// Log for debugging
								console.log(`Uploading GIF with filename: ${binaryFile.fileName}, mime type: ${binaryFile.mimeType}`);

								// Send request to upload GIF
								response = await tokenClient.request({
									method: 'POST',
									url: `${baseUrl}/upload/gif`,
									data: formData,
									headers: {
										...formData.getHeaders(),
									},
								});
							} else {
								const gifUrl = this.getNodeParameter('gifUrl', i) as string;

								// Log for debugging
								console.log(`Downloading GIF from URL: ${gifUrl}`);

								// Download GIF from URL
								const gifResponse = await axios.get(gifUrl, { responseType: 'arraybuffer' });

								// Create FormData
								const formData = new FormData();
								formData.append('file', Buffer.from(gifResponse.data), {
									filename: 'image.gif',
									contentType: 'image/gif',
								});

								// Send request to upload GIF
								response = await tokenClient.request({
									method: 'POST',
									url: `${baseUrl}/upload/gif`,
									data: formData,
									headers: {
										...formData.getHeaders(),
									},
								});
							}

							// Log response for debugging
							console.log('Upload GIF response:', JSON.stringify(response.data));

							returnData.push({
								json: response.data,
								pairedItem: {
									item: i,
								},
							});
						} catch (error) {
							// Log detailed error for debugging
							console.log('Error uploading GIF:', error.message);
							if (error.response) {
								console.log('Response status:', error.response.status);
								console.log('Response data:', JSON.stringify(error.response.data));
							}

							// Return error to user
							returnData.push({
								json: {
									error: true,
									message: `Error uploading GIF: ${error.message}`,
									response: error.response?.data || {},
									suggestion: 'Please check the GIF format and OA access permissions.',
								},
								pairedItem: {
									item: i,
								},
							});
						}
					}

					// Lấy danh sách cuộc trò chuyện gần đây
					else if (operation === 'getRecentChat') {
						const offset = this.getNodeParameter('offset', i) as number;
						const count = this.getNodeParameter('count', i) as number;

						try {
							// Sử dụng API v2.0 vì API v3.0 chưa có tài liệu cho listrecentchat
							const v2BaseUrl = 'https://openapi.zalo.me/v2.0/oa';

							// Tạo data parameter cho API listrecentchat
							const dataParam = JSON.stringify({
								offset,
								count: Math.min(count, 10), // Giới hạn tối đa 10 cuộc trò chuyện mỗi lần gọi theo tài liệu
							});

							// Gọi API lấy danh sách cuộc trò chuyện gần đây
							const response = await tokenClient.request({
								method: 'GET',
								url: `${v2BaseUrl}/listrecentchat`,
								params: {
									data: dataParam,
								},
								headers: {
									'Content-Type': 'application/json',
								},
							});

							returnData.push({
								json: response.data,
								pairedItem: {
									item: i,
								},
							});
						} catch (error) {
							// Log lỗi để debug
							console.log('Lỗi khi gọi API listrecentchat:', error.message);

							// Trả về lỗi để người dùng biết
							returnData.push({
								json: {
									error: true,
									message: `Lỗi khi gọi API lấy danh sách cuộc trò chuyện gần đây: ${error.message}`,
									note: 'Vui lòng kiểm tra lại cấu hình OA và quyền truy cập.',
									suggestion: 'Hãy đảm bảo rằng bạn đã cấp quyền "Quyền quản lý tin nhắn người quan tâm" cho ứng dụng và có access_token hợp lệ.',
								},
								pairedItem: {
									item: i,
								},
							});
						}
					}

					// Lấy lịch sử hội thoại với người dùng
					else if (operation === 'getConversation') {
						const userId = this.getNodeParameter('userId', i) as string;
						const offset = this.getNodeParameter('offset', i) as number;
						const count = this.getNodeParameter('count', i) as number;

						try {
							// Sử dụng API v2.0 vì API v3.0 chưa có tài liệu cho conversation
							const v2BaseUrl = 'https://openapi.zalo.me/v2.0/oa';

							// Tạo data parameter cho API conversation
							const dataParam = JSON.stringify({
								user_id: userId,
								offset,
								count: Math.min(count, 10), // Giới hạn tối đa 10 tin nhắn mỗi lần gọi theo tài liệu
							});

							// Gọi API lấy lịch sử hội thoại với người dùng
							const response = await tokenClient.request({
								method: 'GET',
								url: `${v2BaseUrl}/conversation`,
								params: {
									data: dataParam,
								},
								headers: {
									'Content-Type': 'application/json',
								},
							});

							returnData.push({
								json: response.data,
								pairedItem: {
									item: i,
								},
							});
						} catch (error) {
							// Log lỗi để debug
							console.log('Lỗi khi gọi API conversation:', error.message);

							// Trả về lỗi để người dùng biết
							returnData.push({
								json: {
									error: true,
									message: `Lỗi khi gọi API lấy lịch sử hội thoại: ${error.message}`,
									note: 'Vui lòng kiểm tra lại cấu hình OA và quyền truy cập.',
									suggestion: 'Hãy đảm bảo rằng bạn đã cấp quyền "Quyền quản lý tin nhắn người quan tâm" cho ứng dụng và có access_token hợp lệ.',
								},
								pairedItem: {
									item: i,
								},
							});
						}
					}

					// Kiểm tra trạng thái tin nhắn
					else if (operation === 'getMessageStatus') {
						const messageId = this.getNodeParameter('messageId', i) as string;

						try {
							// Sử dụng API v3.0 để kiểm tra trạng thái tin nhắn
							// Log để debug
							console.log(`Kiểm tra trạng thái tin nhắn với message_id: ${messageId}`);

							// Trong API v3, chúng ta gửi trực tiếp message_id trong body

							// Gọi API kiểm tra trạng thái tin nhắn
							// Trong API v3, endpoint là /message/status và cần gửi dữ liệu dạng POST
							const response = await tokenClient.request({
								method: 'POST',
								url: `${baseUrl}/message/status`,
								data: {
									message_id: messageId,
								},
								headers: {
									'Content-Type': 'application/json',
								},
							});

							// Log response để debug
							console.log('Kết quả kiểm tra trạng thái tin nhắn:', JSON.stringify(response.data));

							returnData.push({
								json: response.data,
								pairedItem: {
									item: i,
								},
							});
						} catch (error) {
							// Log lỗi chi tiết để debug
							console.log('Lỗi khi gọi API message/status v3.0:', error.message);
							if (error.response) {
								console.log('Response status:', error.response.status);
								console.log('Response data:', JSON.stringify(error.response.data));
							}

							// Trả về lỗi để người dùng biết
							returnData.push({
								json: {
									error: true,
									message: `Lỗi khi gọi API kiểm tra trạng thái tin nhắn: ${error.message}`,
									response: error.response?.data || {},
									note: 'Zalo đã thay đổi API getmessagestatus sang API message/status trong v3.0 và yêu cầu sử dụng phương thức POST thay vì GET.',
									suggestion: 'Hãy đảm bảo rằng bạn đã cấp quyền "Quyền quản lý tin nhắn người quan tâm" cho ứng dụng và có access_token hợp lệ.',
								},
								pairedItem: {
									item: i,
								},
							});
						}
					}

					// Xóa tag
					else if (operation === 'removeTag') {
						const tagId = this.getNodeParameter('tagId', i) as string;

						const response = await tokenClient.request({
							method: 'POST',
							url: `${baseUrl}/tag/rmtag`,
							data: {
								tag_id: tagId,
							},
							headers: {
								'Content-Type': 'application/json',
							},
						});

						returnData.push({
							json: response.data,
							pairedItem: {
								item: i,
							},
						});
					}

					// Xóa người theo dõi khỏi tag
					else if (operation === 'removeFollowerFromTag') {
						const userId = this.getNodeParameter('userId', i) as string;
						const tagId = this.getNodeParameter('tagId', i) as string;

						const response = await tokenClient.request({
							method: 'POST',
							url: `${baseUrl}/tag/rmfollowerfromtag`,
							data: {
								user_id: userId,
								tag_id: tagId,
							},
							headers: {
								'Content-Type': 'application/json',
							},
						});

						returnData.push({
							json: response.data,
							pairedItem: {
								item: i,
							},
						});
					}

					// Cập nhật menu OA
					else if (operation === 'updateOAMenu') {
						const menuItemsCollection = this.getNodeParameter('menuItems', i) as {
							menuItemsValues: Array<{
								title: string;
								type: string;
								payload: string;
							}>;
						};

						const menuItems = menuItemsCollection.menuItemsValues.map(item => {
							let payload: string | Record<string, string>;

							// Format payload based on menu type
							if (item.type === 'oa.open.url') {
								payload = { url: item.payload };
							} else if (item.type === 'oa.open.phone') {
								payload = { phone: item.payload };
							} else if (item.type === 'oa.query.show') {
								payload = { message: item.payload };
							} else if (item.type === 'oa.open.app') {
								payload = { app: item.payload };
							} else {
								payload = item.payload;
							}

							return {
								title: item.title,
								type: item.type,
								payload,
							};
						});

						const response = await tokenClient.request({
							method: 'POST',
							url: `${baseUrl}/menu`,
							data: {
								menu_items: menuItems,
							},
							headers: {
								'Content-Type': 'application/json',
							},
						});

						returnData.push({
							json: response.data,
							pairedItem: {
								item: i,
							},
						});
					}

					// Cập nhật thông tin người theo dõi
					else if (operation === 'updateFollowerInfo') {
						try {
							const userId = this.getNodeParameter('userId', i) as string;
							const infoType = this.getNodeParameter('infoType', i) as string;
							const infoValue = this.getNodeParameter('infoValue', i) as string;

							// Trong API v3, cập nhật thông tin người theo dõi sử dụng endpoint user/update
							// và thông tin được đặt trong trường shared_info
							const sharedInfo: Record<string, string> = {};

							// Add specific field based on infoType
							switch(infoType) {
								case 'name':
									sharedInfo.name = infoValue;
									break;
								case 'phone':
									sharedInfo.phone = infoValue;
									break;
								case 'email':
									sharedInfo.email = infoValue;
									break;
								case 'address':
									sharedInfo.address = infoValue;
									break;
								case 'city':
									sharedInfo.city = infoValue;
									break;
								case 'birthday':
									sharedInfo.birthday = infoValue; // Format should be YYYY-MM-DD
									break;
								default:
									break;
							}

							// Tạo data parameter cho API user/update
							const dataParam = JSON.stringify({
								user_id: userId,
								shared_info: sharedInfo
							});

							// Log để debug
							console.log(`Cập nhật thông tin người dùng với user_id: ${userId}, thông tin: ${JSON.stringify(sharedInfo)}`);

							// Gọi API cập nhật thông tin người theo dõi
							const response = await tokenClient.request({
								method: 'POST',
								url: `${baseUrl}/user/update`,
								data: {
									data: dataParam
								},
								headers: {
									'Content-Type': 'application/json',
								},
							});

							// Log response để debug
							console.log('Kết quả cập nhật thông tin người dùng:', JSON.stringify(response.data));

							returnData.push({
								json: response.data,
								pairedItem: {
									item: i,
								},
							});
						} catch (error) {
							// Log lỗi chi tiết để debug
							console.log('Lỗi khi cập nhật thông tin người dùng:', error.message);
							if (error.response) {
								console.log('Response status:', error.response.status);
								console.log('Response data:', JSON.stringify(error.response.data));
							}

							// Trả về lỗi để người dùng biết
							returnData.push({
								json: {
									error: true,
									message: `Lỗi khi cập nhật thông tin người dùng: ${error.message}`,
									response: error.response?.data || {},
									suggestion: 'Vui lòng kiểm tra lại user_id và quyền truy cập của OA. API v3 yêu cầu định dạng dữ liệu khác với v2.',
								},
								pairedItem: {
									item: i,
								},
							});
						}
					}

					// Tạo bài viết
					else if (operation === 'createArticle') {
						try {
							// Lấy các tham số
							const title = this.getNodeParameter('title', i) as string;
							const author = this.getNodeParameter('author', i) as string;
							const description = this.getNodeParameter('description', i) as string;
							const content = this.getNodeParameter('content', i) as string;
							const coverUrl = this.getNodeParameter('coverUrl', i) as string;
							const status = this.getNodeParameter('status', i) as string || 'show';
							const comment = this.getNodeParameter('comment', i) as string || 'show';

							// Tạo cấu trúc body cho bài viết
							const body = [
								{
									type: 'text',
									content,
								},
							];

							// Tạo cấu trúc cover cho bài viết
							const cover = {
								cover_type: 'photo',
								photo_url: coverUrl,
								status: 'show',
							};

							// Log để debug
							console.log(`Creating article with title: ${title}`);

							// Sử dụng API v3.0 với endpoint article/create
							const v3BaseUrl = 'https://openapi.zalo.me/v2.0';

							// Tạo request để tạo bài viết
							const response = await tokenClient.request({
								method: 'POST',
								url: `${v3BaseUrl}/article/create`,
								data: {
									type: 'normal',
									title,
									author,
									cover,
									description,
									body,
									status,
									comment,
								},
								headers: {
									'Content-Type': 'application/json',
								},
							});

							// Log response để debug
							console.log('Create article response:', JSON.stringify(response.data));

							returnData.push({
								json: response.data,
								pairedItem: {
									item: i,
								},
							});
						} catch (error) {
							// Log lỗi chi tiết để debug
							console.log('Error creating article:', error.message);
							if (error.response) {
								console.log('Response status:', error.response.status);
								console.log('Response data:', JSON.stringify(error.response.data));
							}

							// Trả về lỗi để người dùng biết
							returnData.push({
								json: {
									error: true,
									message: `Lỗi khi tạo bài viết: ${error.message}`,
									response: error.response?.data || {},
									note: 'API article/create trong Zalo OA API v3.0 gặp lỗi.',
									suggestion: 'Vui lòng kiểm tra các tham số bài viết và quyền truy cập của OA. Đảm bảo rằng URL hình ảnh cover hợp lệ và có thể truy cập được.',
								},
								pairedItem: {
									item: i,
								},
							});
						}
					}

					// Cập nhật bài viết
					else if (operation === 'updateArticle') {
						try {
							// Lấy các tham số
							const token = this.getNodeParameter('token', i) as string;
							const title = this.getNodeParameter('title', i) as string;
							const author = this.getNodeParameter('author', i) as string;
							const description = this.getNodeParameter('description', i) as string;
							const content = this.getNodeParameter('content', i) as string;
							const coverUrl = this.getNodeParameter('coverUrl', i) as string;
							const status = this.getNodeParameter('status', i) as string || 'show';
							const comment = this.getNodeParameter('comment', i) as string || 'show';

							// Tạo cấu trúc body cho bài viết
							const body = [
								{
									type: 'text',
									content,
								},
							];

							// Tạo cấu trúc cover cho bài viết
							const cover = {
								cover_type: 'photo',
								photo_url: coverUrl,
								status: 'show',
							};

							// Log để debug
							console.log(`Updating article with token: ${token}`);

							// Sử dụng API v3.0 với endpoint article/update
							const v3BaseUrl = 'https://openapi.zalo.me/v2.0';

							// Tạo request để cập nhật bài viết
							const response = await tokenClient.request({
								method: 'POST',
								url: `${v3BaseUrl}/article/update`,
								data: {
									id: token,
									type: 'normal',
									title,
									author,
									cover,
									description,
									body,
									status,
									comment,
								},
								headers: {
									'Content-Type': 'application/json',
								},
							});

							// Log response để debug
							console.log('Update article response:', JSON.stringify(response.data));

							returnData.push({
								json: response.data,
								pairedItem: {
									item: i,
								},
							});
						} catch (error) {
							// Log lỗi chi tiết để debug
							console.log('Error updating article:', error.message);
							if (error.response) {
								console.log('Response status:', error.response.status);
								console.log('Response data:', JSON.stringify(error.response.data));
							}

							// Trả về lỗi để người dùng biết
							returnData.push({
								json: {
									error: true,
									message: `Lỗi khi cập nhật bài viết: ${error.message}`,
									response: error.response?.data || {},
									note: 'API article/update trong Zalo OA API v3.0 gặp lỗi.',
									suggestion: 'Vui lòng kiểm tra token bài viết và các tham số. Đảm bảo rằng bài viết vẫn tồn tại và URL hình ảnh cover hợp lệ.',
								},
								pairedItem: {
									item: i,
								},
							});
						}
					}

					// Xóa bài viết
					else if (operation === 'removeArticle') {
						try {
							// Lấy token của bài viết cần xóa
							const token = this.getNodeParameter('token', i) as string;

							// Log để debug
							console.log(`Removing article with token: ${token}`);

							// Sử dụng API v3.0 với endpoint article/remove
							const v3BaseUrl = 'https://openapi.zalo.me/v2.0';

							// Tạo request để xóa bài viết
							const response = await tokenClient.request({
								method: 'POST',
								url: `${v3BaseUrl}/article/remove`,
								data: {
									id: token,
								},
								headers: {
									'Content-Type': 'application/json',
								},
							});

							// Log response để debug
							console.log('Remove article response:', JSON.stringify(response.data));

							returnData.push({
								json: response.data,
								pairedItem: {
									item: i,
								},
							});
						} catch (error) {
							// Log lỗi chi tiết để debug
							console.log('Error removing article:', error.message);
							if (error.response) {
								console.log('Response status:', error.response.status);
								console.log('Response data:', JSON.stringify(error.response.data));
							}

							// Trả về lỗi để người dùng biết
							returnData.push({
								json: {
									error: true,
									message: `Lỗi khi xóa bài viết: ${error.message}`,
									response: error.response?.data || {},
									note: 'API article/remove trong Zalo OA API v3.0 gặp lỗi.',
									suggestion: 'Vui lòng kiểm tra token bài viết. Đảm bảo rằng bài viết vẫn tồn tại và bạn có quyền xóa nó.',
								},
								pairedItem: {
									item: i,
								},
							});
						}
					}

					// Lấy danh sách bài viết
					else if (operation === 'getArticleList') {
						try {
							// Lấy các tham số
							const offset = this.getNodeParameter('offset', i) as number;
							const limit = this.getNodeParameter('limit', i) as number;
							const type = this.getNodeParameter('type', i) as string; // Giá trị mặc định 'normal' đã được định nghĩa trong ZaloOADescription.ts

							// Log để debug
							console.log(`Lấy danh sách bài viết với offset: ${offset}, limit: ${limit}, type: ${type}`);

							// Sử dụng API v2.0 với endpoint article/getslice
							// Theo tài liệu Zalo OA, API article/getslice vẫn được hỗ trợ trong v2.0
							const v2BaseUrl = 'https://openapi.zalo.me/v2.0';

							// Gọi API lấy danh sách bài viết
							const response = await tokenClient.request({
								method: 'GET',
								url: `${v2BaseUrl}/article/getslice?offset=${offset}&limit=${Math.min(limit, 50)}&type=${type}`,
								headers: {
									'Content-Type': 'application/json',
								},
							});

							// Log response để debug
							console.log('Kết quả lấy danh sách bài viết:', JSON.stringify(response.data));

							// Xử lý dữ liệu trả về để hiển thị rõ ràng token bài viết
							const processedData: any = response.data;

							// Kiểm tra nếu có dữ liệu bài viết trong response
							if (processedData.data && Array.isArray(processedData.data.medias)) {
								// Thêm hướng dẫn sử dụng token bài viết
								processedData.usage_guide = {
									message: 'Sử dụng trường "id" của bài viết làm token bài viết',
									example: 'Khi lấy chi tiết bài viết, hãy sử dụng giá trị "id" của bài viết làm token'
								};
							}

							returnData.push({
								json: processedData,
								pairedItem: {
									item: i,
								},
							});
						} catch (error) {
							// Log lỗi chi tiết để debug
							console.log('Lỗi khi lấy danh sách bài viết:', error.message);
							if (error.response) {
								console.log('Response status:', error.response.status);
								console.log('Response data:', JSON.stringify(error.response.data));
							}

							// Không cần thử lại với API v2.0 vì API v2.0 đã bị tắt
							// Trả về lỗi để người dùng biết
							returnData.push({
								json: {
									error: true,
									message: `Lỗi khi lấy danh sách bài viết: ${error.message}`,
									response: error.response?.data || {},
									note: 'API article/getslice trong Zalo OA API v2.0 gặp lỗi. Theo tài liệu mới nhất, endpoint này chỉ được hỗ trợ trong v2.0.',
									suggestion: 'Vui lòng kiểm tra lại tham số type (chỉ chấp nhận giá trị "normal" hoặc "video"), quyền truy cập của OA và access_token. Nếu vẫn gặp lỗi, hãy tham khảo tài liệu API mới nhất của Zalo OA tại https://developers.zalo.me/docs.',
								},
								pairedItem: {
									item: i,
								},
							});
						}
					}

					// Lấy chi tiết bài viết
					else if (operation === 'getArticleDetail') {
						try {
							// Lấy token của bài viết
							const token = this.getNodeParameter('token', i) as string;

							// Log để debug
							console.log(`Getting article detail with token: ${token}`);

							// Sử dụng API v3.0 với endpoint article/getdetail
							const v3BaseUrl = 'https://openapi.zalo.me/v2.0';

							// Gọi API lấy chi tiết bài viết
							const response = await tokenClient.request({
								method: 'GET',
								url: `${v3BaseUrl}/article/getdetail`,
								params: {
									id: token,
								},
								headers: {
									'Content-Type': 'application/json',
								},
							});

							// Log response để debug
							console.log('Get article detail response:', JSON.stringify(response.data));

							returnData.push({
								json: response.data,
								pairedItem: {
									item: i,
								},
							});
						} catch (error) {
							// Log lỗi chi tiết để debug
							console.log('Error getting article detail:', error.message);
							if (error.response) {
								console.log('Response status:', error.response.status);
								console.log('Response data:', JSON.stringify(error.response.data));
							}

							// Trả về lỗi để người dùng biết
							returnData.push({
								json: {
									error: true,
									message: `Lỗi khi lấy chi tiết bài viết: ${error.message}`,
									response: error.response?.data || {},
									note: 'API article/getdetail trong Zalo OA API v3.0 gặp lỗi. Vui lòng kiểm tra token bài viết.',
									suggestion: 'Hãy đảm bảo rằng token bài viết chính xác và bài viết vẫn tồn tại. Nếu vẫn gặp lỗi, hãy tham khảo tài liệu API mới nhất của Zalo OA.',
								},
								pairedItem: {
									item: i,
								},
							});
						}
					}

					// Tạo sản phẩm
					else if (operation === 'createProduct') {
						try {
							// Lấy các tham số
							const name = this.getNodeParameter('name', i) as string;
							const price = this.getNodeParameter('price', i) as number;
							const description = this.getNodeParameter('description', i) as string;
							const code = this.getNodeParameter('code', i) as string;
							const categoryId = this.getNodeParameter('categoryId', i) as string;
							const status = this.getNodeParameter('status', i) as string || 'show';

							// Lấy danh sách hình ảnh
							const photosCollection = this.getNodeParameter('photos', i) as {
								photosValues: Array<{
									photoUrl: string;
								}>;
							};

							const photos = photosCollection.photosValues.map((photo) => ({
								photo_url: photo.photoUrl,
							}));

							// Log để debug
							console.log(`Creating product with name: ${name}, price: ${price}`);

							// Tạo request để tạo sản phẩm
							const response = await tokenClient.request({
								method: 'POST',
								url: `${baseUrl}/store/product/create`,
								data: {
									name,
									price,
									description,
									code,
									category_id: categoryId,
									photos,
									status,
								},
								headers: {
									'Content-Type': 'application/json',
								},
							});

							// Log response để debug
							console.log('Create product response:', JSON.stringify(response.data));

							returnData.push({
								json: response.data,
								pairedItem: {
									item: i,
								},
							});
						} catch (error) {
							// Log lỗi chi tiết để debug
							console.log('Error creating product:', error.message);
							if (error.response) {
								console.log('Response status:', error.response.status);
								console.log('Response data:', JSON.stringify(error.response.data));
							}

							// Trả về lỗi để người dùng biết
							returnData.push({
								json: {
									error: true,
									message: `Error creating product: ${error.message}`,
									response: error.response?.data || {},
									suggestion: 'Please check the product parameters and OA access permissions.',
								},
								pairedItem: {
									item: i,
								},
							});
						}
					}

					// Cập nhật sản phẩm
					else if (operation === 'updateProduct') {
						try {
							// Lấy các tham số
							const productId = this.getNodeParameter('productId', i) as string;
							const name = this.getNodeParameter('name', i) as string;
							const price = this.getNodeParameter('price', i) as number;
							const description = this.getNodeParameter('description', i) as string;
							const code = this.getNodeParameter('code', i) as string;
							const categoryId = this.getNodeParameter('categoryId', i) as string;
							const status = this.getNodeParameter('status', i) as string || 'show';

							// Lấy danh sách hình ảnh
							const photosCollection = this.getNodeParameter('photos', i) as {
								photosValues: Array<{
									photoUrl: string;
								}>;
							};

							const photos = photosCollection.photosValues.map((photo) => ({
								photo_url: photo.photoUrl,
							}));

							// Log để debug
							console.log(`Updating product with ID: ${productId}, name: ${name}`);

							// Tạo request để cập nhật sản phẩm
							const response = await tokenClient.request({
								method: 'POST',
								url: `${baseUrl}/store/product/update`,
								data: {
									id: productId,
									name,
									price,
									description,
									code,
									category_id: categoryId,
									photos,
									status,
								},
								headers: {
									'Content-Type': 'application/json',
								},
							});

							// Log response để debug
							console.log('Update product response:', JSON.stringify(response.data));

							returnData.push({
								json: response.data,
								pairedItem: {
									item: i,
								},
							});
						} catch (error) {
							// Log lỗi chi tiết để debug
							console.log('Error updating product:', error.message);
							if (error.response) {
								console.log('Response status:', error.response.status);
								console.log('Response data:', JSON.stringify(error.response.data));
							}

							// Trả về lỗi để người dùng biết
							returnData.push({
								json: {
									error: true,
									message: `Error updating product: ${error.message}`,
									response: error.response?.data || {},
									suggestion: 'Please check the product ID and parameters.',
								},
								pairedItem: {
									item: i,
								},
							});
						}
					}

					// Lấy thông tin sản phẩm
					else if (operation === 'getProductInfo') {
						try {
							// Lấy ID sản phẩm
							const productId = this.getNodeParameter('productId', i) as string;

							// Log để debug
							console.log(`Getting product info with ID: ${productId}`);

							// Tạo data parameter cho API getproduct
							const dataParam = JSON.stringify({
								id: productId,
							});

							// Gọi API lấy thông tin sản phẩm
							const response = await tokenClient.request({
								method: 'GET',
								url: `${baseUrl}/store/product/getproduct`,
								params: {
									data: dataParam,
								},
								headers: {
									'Content-Type': 'application/json',
								},
							});

							// Log response để debug
							console.log('Get product info response:', JSON.stringify(response.data));

							returnData.push({
								json: response.data,
								pairedItem: {
									item: i,
								},
							});
						} catch (error) {
							// Log lỗi chi tiết để debug
							console.log('Error getting product info:', error.message);
							if (error.response) {
								console.log('Response status:', error.response.status);
								console.log('Response data:', JSON.stringify(error.response.data));
							}

							// Trả về lỗi để người dùng biết
							returnData.push({
								json: {
									error: true,
									message: `Error getting product info: ${error.message}`,
									response: error.response?.data || {},
									suggestion: 'Please check the product ID.',
								},
								pairedItem: {
									item: i,
								},
							});
						}
					}

					// Lấy danh sách sản phẩm
					else if (operation === 'getProductList') {
						try {
							// Lấy các tham số
							const offset = this.getNodeParameter('offset', i) as number;
							const limit = this.getNodeParameter('limit', i) as number;
							const categoryId = this.getNodeParameter('categoryId', i) as string || '';

							// Log để debug
							console.log(`Getting product list with offset: ${offset}, limit: ${limit}`);

							// Tạo data parameter cho API getproductofoa
							const dataParam: Record<string, any> = {
								offset,
								limit: Math.min(limit, 50), // Giới hạn tối đa 50 sản phẩm mỗi lần gọi
							};

							// Thêm category_id nếu có
							if (categoryId) {
								dataParam.category_id = categoryId;
							}

							// Gọi API lấy danh sách sản phẩm
							const response = await tokenClient.request({
								method: 'GET',
								url: `${baseUrl}/store/product/getproductofoa`,
								params: {
									data: JSON.stringify(dataParam),
								},
								headers: {
									'Content-Type': 'application/json',
								},
							});

							// Log response để debug
							console.log('Get product list response:', JSON.stringify(response.data));

							returnData.push({
								json: response.data,
								pairedItem: {
									item: i,
								},
							});
						} catch (error) {
							// Log lỗi chi tiết để debug
							console.log('Error getting product list:', error.message);
							if (error.response) {
								console.log('Response status:', error.response.status);
								console.log('Response data:', JSON.stringify(error.response.data));
							}

							// Trả về lỗi để người dùng biết
							returnData.push({
								json: {
									error: true,
									message: `Error getting product list: ${error.message}`,
									response: error.response?.data || {},
									suggestion: 'Please check the parameters and OA access permissions.',
								},
								pairedItem: {
									item: i,
								},
							});
						}
					}

					// Tạo danh mục
					else if (operation === 'createCategory') {
						try {
							// Lấy các tham số
							const name = this.getNodeParameter('name', i) as string;
							const description = this.getNodeParameter('description', i) as string;
							const status = this.getNodeParameter('status', i) as string || 'show';
							const parentId = this.getNodeParameter('parentId', i) as string || '';

							// Tạo dữ liệu cho request
							const requestData: Record<string, any> = {
								name,
								description,
								status,
							};

							// Thêm parent_id nếu có
							if (parentId) {
								requestData.parent_id = parentId;
							}

							// Log để debug
							console.log(`Creating category with name: ${name}`);

							// Tạo request để tạo danh mục
							const response = await tokenClient.request({
								method: 'POST',
								url: `${baseUrl}/store/category/create`,
								data: requestData,
								headers: {
									'Content-Type': 'application/json',
								},
							});

							// Log response để debug
							console.log('Create category response:', JSON.stringify(response.data));

							returnData.push({
								json: response.data,
								pairedItem: {
									item: i,
								},
							});
						} catch (error) {
							// Log lỗi chi tiết để debug
							console.log('Error creating category:', error.message);
							if (error.response) {
								console.log('Response status:', error.response.status);
								console.log('Response data:', JSON.stringify(error.response.data));
							}

							// Trả về lỗi để người dùng biết
							returnData.push({
								json: {
									error: true,
									message: `Error creating category: ${error.message}`,
									response: error.response?.data || {},
									suggestion: 'Please check the category parameters and OA access permissions.',
								},
								pairedItem: {
									item: i,
								},
							});
						}
					}

					// Cập nhật danh mục
					else if (operation === 'updateCategory') {
						try {
							// Lấy các tham số
							const categoryId = this.getNodeParameter('categoryId', i) as string;
							const name = this.getNodeParameter('name', i) as string;
							const description = this.getNodeParameter('description', i) as string;
							const status = this.getNodeParameter('status', i) as string || 'show';
							const parentId = this.getNodeParameter('parentId', i) as string || '';

							// Tạo dữ liệu cho request
							const requestData: Record<string, any> = {
								id: categoryId,
								name,
								description,
								status,
							};

							// Thêm parent_id nếu có
							if (parentId) {
								requestData.parent_id = parentId;
							}

							// Log để debug
							console.log(`Updating category with ID: ${categoryId}, name: ${name}`);

							// Tạo request để cập nhật danh mục
							const response = await tokenClient.request({
								method: 'POST',
								url: `${baseUrl}/store/category/update`,
								data: requestData,
								headers: {
									'Content-Type': 'application/json',
								},
							});

							// Log response để debug
							console.log('Update category response:', JSON.stringify(response.data));

							returnData.push({
								json: response.data,
								pairedItem: {
									item: i,
								},
							});
						} catch (error) {
							// Log lỗi chi tiết để debug
							console.log('Error updating category:', error.message);
							if (error.response) {
								console.log('Response status:', error.response.status);
								console.log('Response data:', JSON.stringify(error.response.data));
							}

							// Trả về lỗi để người dùng biết
							returnData.push({
								json: {
									error: true,
									message: `Error updating category: ${error.message}`,
									response: error.response?.data || {},
									suggestion: 'Please check the category ID and parameters.',
								},
								pairedItem: {
									item: i,
								},
							});
						}
					}

					// Lấy danh sách danh mục
					else if (operation === 'getCategoryList') {
						try {
							// Lấy các tham số
							const offset = this.getNodeParameter('offset', i) as number;
							const limit = this.getNodeParameter('limit', i) as number;

							// Log để debug
							console.log(`Getting category list with offset: ${offset}, limit: ${limit}`);

							// Tạo data parameter cho API getcategoryofoa
							const dataParam = JSON.stringify({
								offset,
								limit: Math.min(limit, 50), // Giới hạn tối đa 50 danh mục mỗi lần gọi
							});

							// Gọi API lấy danh sách danh mục
							const response = await tokenClient.request({
								method: 'GET',
								url: `${baseUrl}/store/category/getcategoryofoa`,
								params: {
									data: dataParam,
								},
								headers: {
									'Content-Type': 'application/json',
								},
							});

							// Log response để debug
							console.log('Get category list response:', JSON.stringify(response.data));

							returnData.push({
								json: response.data,
								pairedItem: {
									item: i,
								},
							});
						} catch (error) {
							// Log lỗi chi tiết để debug
							console.log('Error getting category list:', error.message);
							if (error.response) {
								console.log('Response status:', error.response.status);
								console.log('Response data:', JSON.stringify(error.response.data));
							}

							// Trả về lỗi để người dùng biết
							returnData.push({
								json: {
									error: true,
									message: `Error getting category list: ${error.message}`,
									response: error.response?.data || {},
									suggestion: 'Please check the parameters and OA access permissions.',
								},
								pairedItem: {
									item: i,
								},
							});
						}
					}

					// Tạo đơn hàng
					else if (operation === 'createOrder') {
						try {
							// Lấy các tham số
							const userId = this.getNodeParameter('userId', i) as string;
							const shippingName = this.getNodeParameter('shippingName', i) as string;
							const shippingPhone = this.getNodeParameter('shippingPhone', i) as string;
							const shippingAddress = this.getNodeParameter('shippingAddress', i) as string;
							const shippingCity = this.getNodeParameter('shippingCity', i) as string;
							const shippingFee = this.getNodeParameter('shippingFee', i) as number;
							const discount = this.getNodeParameter('discount', i) as number;
							const total = this.getNodeParameter('total', i) as number;

							// Lấy danh sách sản phẩm trong đơn hàng
							const orderItemsCollection = this.getNodeParameter('orderItems', i) as {
								itemsValues: Array<{
									productId: string;
									quantity: number;
									price: number;
								}>;
							};

							const items = orderItemsCollection.itemsValues.map((item) => ({
								product_id: item.productId,
								quantity: item.quantity,
								price: item.price,
							}));

							// Tạo dữ liệu cho request
							const requestData = {
								user_id: userId,
								shipping: {
									name: shippingName,
									phone: shippingPhone,
									address: shippingAddress,
									city: shippingCity,
								},
								items,
								shipping_fee: shippingFee,
								discount,
								total,
							};

							// Log để debug
							console.log(`Creating order for user: ${userId}`);

							// Tạo request để tạo đơn hàng
							const response = await tokenClient.request({
								method: 'POST',
								url: `${baseUrl}/store/order/create`,
								data: requestData,
								headers: {
									'Content-Type': 'application/json',
								},
							});

							// Log response để debug
							console.log('Create order response:', JSON.stringify(response.data));

							returnData.push({
								json: response.data,
								pairedItem: {
									item: i,
								},
							});
						} catch (error) {
							// Log lỗi chi tiết để debug
							console.log('Error creating order:', error.message);
							if (error.response) {
								console.log('Response status:', error.response.status);
								console.log('Response data:', JSON.stringify(error.response.data));
							}

							// Trả về lỗi để người dùng biết
							returnData.push({
								json: {
									error: true,
									message: `Error creating order: ${error.message}`,
									response: error.response?.data || {},
									suggestion: 'Please check the order parameters and OA access permissions.',
								},
								pairedItem: {
									item: i,
								},
							});
						}
					}
				}
			} catch (error) {
				if (this.continueOnFail()) {
					returnData.push({
						json: {
							error: error.message,
						},
						pairedItem: {
							item: i,
						},
					});
					continue;
				}
				throw new NodeOperationError(this.getNode(), error, {
					itemIndex: i,
				});
			}
		}

		return [returnData];
	}
}
