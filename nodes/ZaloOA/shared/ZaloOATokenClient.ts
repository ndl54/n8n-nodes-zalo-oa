import axios, { AxiosRequestConfig, AxiosResponse } from 'axios';
import { IDataObject, IExecuteFunctions, NodeOperationError } from 'n8n-workflow';

type TokenRefreshResponse = {
	access_token?: string;
	refresh_token?: string;
	expires_in?: string | number;
	error?: number;
	message?: string;
};

type TokenState = {
	accessToken: string;
	refreshToken: string;
	accessTokenExpiresAt?: number;
	refreshTokenExpiresAt?: number;
};

const OAUTH_TOKEN_URL = 'https://oauth.zaloapp.com/v4/oa/access_token';
const ACCESS_TOKEN_SKEW_MS = 60_000;
const REFRESH_TOKEN_TTL_MS = 90 * 24 * 60 * 60 * 1000;

function nowMs() {
	return Date.now();
}

function parseExpiresInMs(expiresIn: unknown): number | undefined {
	if (typeof expiresIn === 'number' && Number.isFinite(expiresIn)) return expiresIn * 1000;
	if (typeof expiresIn === 'string') {
		const value = Number(expiresIn);
		if (Number.isFinite(value)) return value * 1000;
	}
	return undefined;
}

function isTokenLikelyInvalid(data: unknown, status?: number): boolean {
	if (status === 401 || status === 403) return true;

	if (!data || typeof data !== 'object') return false;
	const anyData = data as Record<string, unknown>;

	const error = anyData.error ?? anyData.error_code;
	const message = anyData.message ?? anyData.error_message;

	if (typeof message === 'string' && /access[_\s-]?token|refresh[_\s-]?token|token/i.test(message)) {
		return true;
	}

	if (typeof error === 'number' && error !== 0) {
		return typeof message === 'string' && /token/i.test(message);
	}

	return false;
}

export class ZaloOATokenClient {
	private readonly staticData: IDataObject;
	private readonly storageKey: string;
	private inflightRefresh?: Promise<TokenState>;

	constructor(
		private readonly thisArg: IExecuteFunctions,
		private readonly credentials: IDataObject,
	) {
		this.staticData = thisArg.getWorkflowStaticData('global') as IDataObject;
		const credentialId = (thisArg.getNode().credentials as IDataObject | undefined)?.zaloOAApi as
			| { id?: string | number }
			| undefined;
		const appId = String(this.credentials.appId ?? '');
		this.storageKey = `zaloOAApi:${credentialId?.id ?? appId ?? 'unknown'}`;
	}

	private readState(): TokenState | undefined {
		const existing = this.staticData[this.storageKey];
		if (!existing || typeof existing !== 'object') return undefined;
		const state = existing as Partial<TokenState>;
		if (!state.accessToken || !state.refreshToken) return undefined;
		return state as TokenState;
	}

	private writeState(state: TokenState) {
		this.staticData[this.storageKey] = state as unknown as IDataObject;
	}

	private seedStateIfMissing(): TokenState {
		const existing = this.readState();
		if (existing) return existing;

		const accessToken = String(this.credentials.accessToken ?? '');
		const refreshToken = String(this.credentials.refreshToken ?? '');
		if (!accessToken || !refreshToken) {
			throw new NodeOperationError(
				this.thisArg.getNode(),
				'Missing Zalo OA credentials: accessToken/refreshToken are required',
			);
		}

		const state: TokenState = { accessToken, refreshToken };
		this.writeState(state);
		return state;
	}

	private isAccessTokenValid(state: TokenState): boolean {
		if (!state.accessToken) return false;
		if (!state.accessTokenExpiresAt) return true;
		return nowMs() + ACCESS_TOKEN_SKEW_MS < state.accessTokenExpiresAt;
	}

	private async doRefresh(state: TokenState): Promise<TokenState> {
		const appId = String(this.credentials.appId ?? '');
		const secretKey = String(this.credentials.secretKey ?? '');

		if (!appId || !secretKey) {
			throw new NodeOperationError(
				this.thisArg.getNode(),
				'Missing Zalo OA credentials: appId/secretKey are required for token refresh',
			);
		}

		const params = new URLSearchParams();
		params.set('refresh_token', state.refreshToken);
		params.set('app_id', appId);
		params.set('grant_type', 'refresh_token');

		let response: AxiosResponse<TokenRefreshResponse>;
		try {
			response = await axios.post<TokenRefreshResponse>(OAUTH_TOKEN_URL, params.toString(), {
				headers: {
					secret_key: secretKey,
					'Content-Type': 'application/x-www-form-urlencoded',
				},
			});
		} catch (error) {
			throw new NodeOperationError(
				this.thisArg.getNode(),
				error as Error,
				{
					message:
						'Failed to refresh Zalo OA access token. Please re-authorize and update credentials (refresh_token may be expired/used).',
				},
			);
		}

		if (isTokenLikelyInvalid(response.data, response.status)) {
			throw new NodeOperationError(this.thisArg.getNode(), response.data as unknown as Error, {
				message:
					'Zalo OA token refresh was rejected. Please re-authorize and update credentials (refresh_token may be expired/used).',
			});
		}

		const accessToken = String(response.data.access_token ?? '');
		const refreshToken = String(response.data.refresh_token ?? '');
		const expiresInMs = parseExpiresInMs(response.data.expires_in);

		if (!accessToken || !refreshToken) {
			throw new NodeOperationError(this.thisArg.getNode(), 'Unexpected token refresh response from Zalo OAuth');
		}

		const updated: TokenState = {
			accessToken,
			refreshToken,
			accessTokenExpiresAt: expiresInMs ? nowMs() + expiresInMs : undefined,
			refreshTokenExpiresAt: nowMs() + REFRESH_TOKEN_TTL_MS,
		};
		this.writeState(updated);
		return updated;
	}

	async getAccessToken(): Promise<string> {
		const state = this.seedStateIfMissing();
		if (this.isAccessTokenValid(state)) return state.accessToken;
		const refreshed = await this.refreshAccessToken();
		return refreshed.accessToken;
	}

	async refreshAccessToken(): Promise<TokenState> {
		if (!this.inflightRefresh) {
			const state = this.seedStateIfMissing();
			this.inflightRefresh = this.doRefresh(state).finally(() => {
				this.inflightRefresh = undefined;
			});
		}
		return this.inflightRefresh;
	}

	async request<T = IDataObject>(
		config: AxiosRequestConfig,
	): Promise<AxiosResponse<T>> {
		const accessToken = await this.getAccessToken();
		const requestConfig: AxiosRequestConfig = {
			...config,
			headers: {
				...(config.headers ?? {}),
				access_token: accessToken,
			},
		};

		try {
			const response = await axios.request<T>(requestConfig);
			if (!isTokenLikelyInvalid(response.data, response.status)) return response;

			const refreshed = await this.refreshAccessToken();
			const retryConfig: AxiosRequestConfig = {
				...config,
				headers: {
					...(config.headers ?? {}),
					access_token: refreshed.accessToken,
				},
			};
			return await axios.request<T>(retryConfig);
		} catch (error) {
			const axiosError = error as { response?: AxiosResponse<unknown> };
			if (axiosError.response && isTokenLikelyInvalid(axiosError.response.data, axiosError.response.status)) {
				const refreshed = await this.refreshAccessToken();
				const retryConfig: AxiosRequestConfig = {
					...config,
					headers: {
						...(config.headers ?? {}),
						access_token: refreshed.accessToken,
					},
				};
				return await axios.request<T>(retryConfig);
			}
			throw error;
		}
	}
}
