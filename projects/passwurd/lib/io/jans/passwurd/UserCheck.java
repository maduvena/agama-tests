
package io.jans.passwurd;

import org.json.JSONObject;
import org.json.JSONArray;
import io.jans.as.common.service.common.UserService;
import io.jans.service.cdi.util.CdiUtil;
import io.jans.util.StringHelper;
import io.jans.as.common.model.common.User;

import io.jans.as.model.crypto.signature.SignatureAlgorithm;
import io.jans.as.model.crypto.AuthCryptoProvider;

import io.jans.service.custom.CustomScriptService;
import io.jans.model.custom.script.CustomScriptType;
import io.jans.model.custom.script.model.CustomScript;
import io.jans.model.SimpleExtendedCustomProperty;

import java.util.Map;
import java.util.HashMap;
import org.apache.commons.codec.binary.Base64;

import org.apache.http.client.HttpClient;
import io.jans.as.server.model.net.HttpServiceResponse;
import io.jans.as.server.service.net.HttpService2;
import org.apache.http.entity.ContentType;
import org.apache.http.HttpResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UserCheck {

	private static final Logger logger = LoggerFactory.getLogger(UserCheck.class);
	private static final UserService userService = CdiUtil.bean(UserService.class);
	private static final HttpService2 httpService = CdiUtil.bean(HttpService2);
	private static Map<String, String> configAttributes;
	private static AuthCryptoProvider cryptoProvider = null;

	public UserCheck(){}

	public static Map<String, String> initCredentialMap(Map<String, String> credentialMap) {
                logger.info("Passwurd. initCredentialMap ");
		credentialMap = new HashMap<String, String>();
		credentialMap.put("username", "");
		credentialMap.put("k_username", "");
		credentialMap.put("k_pwd", "");
		credentialMap.put("trackId", "");
		credentialMap.put("orgId", "");
	}
	public static boolean initializeFlow(Map<String, String> config) {
                logger.info("Passwurd. Initialization. ");
		configAttributes = config;
		if (configAttributes.get("AS_ENDPOINT").isBlank() ) {
			logger.debug("Passwurd. Initialization. Property AS_ENDPOINT is mandatory");
			return false;
		}
		if (configAttributes.get("AS_REDIRECT_URI").isBlank() ){
			logger.debug("Passwurd. Initialization. Property AS_REDIRECT_URI is mandatory");
			return false;
		}

		if (configAttributes.get("PORTAL_JWKS")isBlank() ) {
			logger.debug("Passwurd. Initialization. Property PORTAL_JWKS is mandatory");
			return false;
		}

		if (configAttributes.get("PASSWURD_KEY_A_KEYSTORE").isBlank() ) {
			logger.debug("Passwurd. Initialization. Property PASSWURD_KEY_A_KEYSTORE is mandatory");
			return false;
		}

		if (configAttributes.get("PASSWURD_KEY_A_PASSWORD").isBlank() ) {
			logger.debug("Passwurd. Initialization. Property PASSWURD_KEY_A_PASSWORD is mandatory");
			return false;
		} else {
			cryptoProvider = new AuthCryptoProvider(configAttributes.get("PASSWURD_KEY_A_KEYSTORE"),
					configAttributes.get("PASSWURD_KEY_A_PASSWORD"), null);
		}

		if (configAttributes.get("PASSWURD_API_URL").isBlank() ) {
			logger.debug("Passwurd. Initialization. Property PASSWURD_API_URL is mandatory");
			return false;
		}
		if (configAttributes.get("AS_SSA").isBlank() ) {
			logger.debug("Passwurd. Initialization. Property AS_SSA is mandatory");
			return false;
		}

		if (configAttributes.get("AS_CLIENT_ID").isBlank() ) {

			Map<String, String> clientRegistrationResponse = registerScanClient(configAttributes.get("AS_ENDPOINT"),
					configAttributes.get("AS_REDIRECT_URI"), configAttributes.get("AS_SSA"));
			if (clientRegistrationResponse == null)
				logger.debug("Passwurd. Unable to register client with AS");
			return false;

			configAttributes.put("AS_CLIENT_ID", clientRegistrationResponse.get("client_id"));
			configAttributes.put("AS_CLIENT_SECRET", clientRegistrationResponse.get("client_secret"));
			configAttributes.put("ORG_ID", clientRegistrationResponse.get("org_id"));
		}
                logger.info("Passwurd. Initialization. Completed");
	}

	public static Map<String, String> registerScanClient(String asBaseUrl, String asRedirectUri, String asSSA) {
		logger.debug("Passwurd. Attempting to register client");
		JSONObject body = new JSONObject();
		JSONObject header = new JSONObject();
		JSONArray redirect = new JSONArray();
		redirect.put(asRedirectUri);
		body.put("redirect_uris", redirect);
		body.put("software_statement", asSSA);
		header.put("Accept", "application/json");

		String endpointUrl = asBaseUrl + "/jans-auth/restv1/register";

		String response = null;

		try {

			HttpClient httpClient = httpService.getHttpsClient();
			HttpServiceResponse resultResponse = httpService.executePost(httpClient, endpointUrl, null,
					header.toString(), body.toString(), ContentType.APPLICATION_JSON);
			HttpResponse httpResponse = resultResponse.getHttpResponse();
			String httpResponseStatusCode = httpResponse.getStatusLine().getStatusCode();
			logger.debug("Passwurd. Get client registration response status code: " + httpResponseStatusCode);

			if (httpService.isResponseStastusCodeOk(httpResponse) == false) {
				logger.debug("Passwurd. Scan. Get invalid registration");
				httpService.consume(httpResponse);
				return null;
			}
			byte[] bytes = httpService.getResponseContent(httpResponse);

			response = httpService.convertEntityToString(bytes);
		} catch (Exception e) {
			logger.debug("Passwurd. Failed to send client registration request: ");
			e.printStackTrace();
			return null;
		}
		JSONObject response_data = new JSONObject(response);
		Map<String, String> result = new HashMap<String, String>();
		result.put("client_id", response_data.getString("client_id"));
		result.put("client_secret", response_data.getString("client_secret"));

		try {
			CustomScriptService custScriptService = CdiUtil.bean(CustomScriptService);
			CustomScript customScript = custScriptService.getScriptByDisplayName("agama");
			for (List<SimpleExtendedCustomProperty> conf : customScript.getConfigurationProperties()) {

				if (StringHelper.equalsIgnoreCase(conf.getValue1(), "AS_CLIENT_ID")) {
					conf.setValue2(response_data.getString("client_id"));
				} else if (StringHelper.equalsIgnoreCase(conf.getValue1(), "AS_CLIENT_SECRET")) {
					conf.setValue2(response_data.getString("client_secret"));
				} else if (StringHelper.equalsIgnoreCase(conf.getValue1(), "ORG_ID")) {
					conf.setValue2(response_data.getString("org_id"));
				}

			}
			custScriptService.update(customScript);

			logger.debug("Passwurd. Stored client credentials in script parameters");
		} catch (Exception e) {
			logger.error("Passwurd. Failed to store client credentials.", e);
			return null;
		}
		return result;

	}

	public static boolean userExists(String uid) {
		User resultUser = userService.getUserByAttribute("uid", uid);
		return (resultUser != null);

	}

	public String getAccessTokenJansServer() {

		HttpClient httpClient = HttpService2.getHttpsClient();

		String url = configAttributes.get("AS_ENDPOINT") + "/jans-auth/restv1/token";
		String data = "grant_type=client_credentials&scope=https://api.gluu.org/auth/scopes/scan.passwurd&redirect_uri="
				+ configAttributes.get("AS_REDIRECT_URI");
		JSONObject header = new JSONObject();
		header.put("Content-type", "application/x-www-form-urlencoded");
		header.put("Accept", "application/json");
		String encodedString = Base64.encodeBase64String(
				(configAttributes.get("AS_CLIENT_ID") + ":" + configAttributes.get("AS_CLIENT_SECRET")).getBytes());
		header.put("Authorization", "Basic " + encodedString);

		HttpServiceResponse resultResponse = null;
		try {
			resultResponse = httpService.executePost(httpClient, url, null, header.toString(), data);
			HttpResponse httpResponse = resultResponse.getHttpResponse();
			if (httpService.isResponseStastusCodeOk(httpResponse)) {
				logger.debug("Passwurd. Jans-Auth getAccessToken. Get invalid response from server: ",
						(httpResponse.getStatusLine().getStatusCode()));
				httpService.consume(httpResponse);
				return null;
			}
			byte[] response_bytes = httpService.getResponseContent(httpResponse);
			String response_string = httpService.convertEntityToString(response_bytes);
			httpService.consume(httpResponse);

			if (response_string == null) {
				logger.debug("Passwurd. getAccessToken. Got empty response from validation server");
				return null;
			}
			JSONObject response = new JSONObject(response_string);

			logger.debug("Passwurd. response access token: " + response.get("access_token"));
			return String.valueOf(response.get("access_token"));

		} catch (Exception e) {
			logger.error("Jans Auth Server - getAccessToken", e);
			return null;
		} finally {
			resultResponse.closeConnection();
		}

	}

	public static String signUid(String uid) {

		String alias = "passwurd";
		String signedUID = cryptoProvider.sign(uid, alias, null, SignatureAlgorithm.RS256);

		return signedUID;
	}

	public int validateKeystrokes(Map<String, String> credentialMap) {
		logger.debug("Passwurd. Attempting to validate keystrokes");

		try {
			String customer_sig = signUid(credentialMap.get("username"));

			String access_token = getAccessTokenJansServer();
			
			JSONObject data = new JSONObject();
			data.put("k_username", credentialMap.get("k_username"));
			data.put("k_pwd", credentialMap.get("k_pwd"));
			data.put("customer_sig", customer_sig);
			data.put("org_id", configAttributes.get("ORG_ID"));
			data.put("uid", credentialMap.get("username"));

			JSONObject headers = new JSONObject();
			headers.put("Accept", "application/json");

			headers.put("Authorization", "Bearer " + access_token);
			String endpointUrl = configAttributes.get("PASSWURD_API_URL") + "/validate";

			HttpClient httpClient = httpService.getHttpsClient();
			HttpServiceResponse resultResponse = httpService.executePost(httpClient, endpointUrl, null,
					headers.toString(), data.toString(), ContentType.APPLICATION_JSON);
			HttpResponse httpResponse = resultResponse.getHttpResponse();
			String httpResponseStatusCode = httpResponse.getStatusLine().getStatusCode();
			logger.debug("Passwurd. validate keystrokes response status code: " + httpResponseStatusCode);

			if (httpService.isResponseStastusCodeOk(httpResponse) == false) {
				logger.debug("Passwurd. Failed to validate");
				httpService.consume(httpResponse);
				return null;
			}
			byte[] bytes = httpService.getResponseContent(httpResponse);
			String response = httpService.convertEntityToString(bytes);
			data = new JSONObject(response);

			if (httpResponseStatusCode == "200" || httpResponseStatusCode == "202") {
				if (data.get("status") == "Enrollment") {
					logger.debug("Enrollment");
					return -1;
				} else if (data.get("status") == "Approved") {
					logger.debug("Approved");
					return -1;
				} else if (data.get("status") == "Denied") {
					logger.debug("Denied");
					track_id = data.get("track_id");
					return track_id;
				}
				logger.debug("Keystrokes validated successfully");
			} else if (httpResponseStatusCode == "422") {
				// in this case the password text mismatched, hence we do not offer the 2FA
				// option
				return -2;
			} else if (httpResponseStatusCode == "400") {
				logger.debug(
						"Passwurd. in this case the password text mismatched, hence we do not offer the 2FA option");
				return -2;
			} else {
				logger.debug("Failed to validate keystrokes, API returned error " + httpResponseStatusCode);
				return 0;
			}
		} catch (

		Exception e) {
			logger.debug("Passwurd. Failed to execute /validate.", e);
			return 0;
		}
	}

	public boolean notifyProfile(Map<String, String> credentialMap) {

		String access_token = getAccessTokenJansServer();

		try {

			
			JSONObject data = new JSONObject();
			data.put("uid", credentialMap.get("username"));
			data.put("track_id", credentialMap.get("trackId"));

			JSONObject headers = new JSONObject();
			headers.put("Accept", "application/json");

			headers.put("Authorization", "Bearer " + access_token);

			String endpointUrl = configAttributes.get("PASSWURD_API_URL") + "/notify";

			HttpClient httpClient = httpService.getHttpsClient();
			HttpServiceResponse resultResponse = httpService.executePost(httpClient, endpointUrl, null, headers,
					data.toString(), ContentType.APPLICATION_JSON);
			HttpResponse httpResponse = resultResponse.getHttpResponse();
			String httpResponseStatusCode = httpResponse.getStatusLine().getStatusCode();
			logger.debug("Passwurd. Notify response status code: " + httpResponseStatusCode);

			if (httpService.isResponseStastusCodeOk(httpResponse) == false) {
				logger.debug("Passwurd. Notify response invalid ");
				httpService.consume(httpResponse);
				return null;
			}
			byte[] bytes = httpService.getResponseContent(httpResponse);

			String response = httpService.convertEntityToString(bytes);
			data = new JSONObject(response);
			logger.debug(data.getString("status"));

		} catch (Exception e) {
			logger.debug("Passwurd. Failed to execute /notify.", e);
			// return true irrespective of the result
			return True;
		}
	}
}