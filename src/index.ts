import * as axios from "axios";
import qs from "qs";

interface OAuthToken {
  /* eslint-disable camelcase */
  access_token: string;
  token_type: string;
  expires_in: number;
  /* eslint-enable camelcase */
  scope: string;
  jti: string;
}

export interface OAuthTokenReponse {
  accessToken: string;
  tokenType: string;
  expiresIn: number;
  scope: string;
  jti: string;
  limitMinute: number;
  remainingMinute: number;
  trackId: string;
  Authorization: string;
}

type AuthReponse = BasicAuth | OAuthTokenReponse;

export interface BasicAuth {
  /**
   * Authorization Header
   */
  Authorization: string;
}

export interface AuthHeaderProvider {
  (trackId: string): Promise<AuthReponse>;
}

const basicAuthHeaderProvider = (
  _: axios.AxiosInstance,
  clientId: string,
  clientSecret: string
): AuthHeaderProvider => {
  return (_): Promise<AuthReponse> => {
    try {
      const toEncode = `${clientId}:${clientSecret}`;
      const buffer = Buffer.from(toEncode);
      return Promise.resolve({ Authorization: `Basic: ${buffer}` });
    } catch {
      throw new Error("could not generate basic authorization header");
    }
  };
};

const oauth = (
  axiosInstance: axios.AxiosInstance,
  clientId: string,
  clientSecret: string
): AuthHeaderProvider => {
  return (trackId: string): Promise<AuthReponse> => {
    return axiosInstance({
      url: "/oauth/token",
      method: "POST",
      data: qs.stringify({
        client_id: clientId,
        client_secret: clientSecret,
        grant_type: "client_credentials"
      }),
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        "Zuora-Track-Id": trackId
      }
    }).then((r: axios.AxiosResponse<OAuthToken>) => {
      const { data, headers } = r;
      const {
        expires_in: expiresIn,
        access_token: accessToken,
        jti,
        scope,
        token_type: tokenType
      } = data;

      return {
        expiresIn,
        accessToken,
        jti,
        scope,
        tokenType,
        limitMinute: headers["x-ratelimit-limit-minute"],
        remainingMinute: headers["x-ratelimit-remaining-minute"],
        trackId: headers["zuora-track-id"],
        Authorization: `Bearer: ${accessToken}`
      };
    });
  };
};

export interface HmacSignaturesRequest {
  accountKey?: string;
  method: "GET" | "POST" | "PUT" | "DELETE" | "OPTIONS";
  name?: string;
  pageId?: string;
  uri: string;
}

export interface HmacSignaturesResponse {
  signature: string;
  token: string;
  success: boolean;
}

const hmacSignatures = (
  authHeaderProvider: AuthHeaderProvider,
  axiosInstance: axios.AxiosInstance
) => {
  return {
    get: async (
      trackId: string,
      hmacSignaturesRequest: HmacSignaturesRequest
    ): Promise<HmacSignaturesResponse> => {
      const authHeader = await authHeaderProvider(trackId);
      const {
        data
      }: axios.AxiosResponse<HmacSignaturesResponse> = await axiosInstance({
        url: "/v1/hmac-signatures",
        data: hmacSignaturesRequest,
        headers: {
          ...authHeader
        }
      });
      return data;
    }
  };
};

const zuoraApi = (
  baseURL: string,
  useBasicAuth: boolean,
  clientId: string,
  clientSecret: string
) => {
  const axiosInstance = axios.default.create({ baseURL });
  const oauthEndpoint = oauth(axiosInstance, clientId, clientSecret);
  const authHeaderProvider = useBasicAuth
    ? basicAuthHeaderProvider(axiosInstance, clientId, clientSecret)
    : oauthEndpoint;

  return {
    oauth: oauthEndpoint,
    hmacSignatures: hmacSignatures(authHeaderProvider, axiosInstance)
  };
};

export default zuoraApi;
