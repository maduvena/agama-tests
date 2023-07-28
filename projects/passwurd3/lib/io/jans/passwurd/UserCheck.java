
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
import java.net.URI;
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
	private static final UserService userService = CdiUtil.bean(UserService);
	private static final HttpService2 httpService = CdiUtil.bean(HttpService2);
	private static Map<String, String> configAttributes;
	private static AuthCryptoProvider cryptoProvider = null;

	public UserCheck() {
	}

	public static Map<String, String> initCredentialMap(HashMap<String, String> credentialMap) {
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
		if (StringHelper.isEmpty(configAttributes.get("AS_ENDPOINT"))) {
			logger.info("Passwurd. Initialization. Property AS_ENDPOINT is mandatory");
			return false;
		}
		if (StringHelper.isEmpty(configAttributes.get("AS_REDIRECT_URI"))){
			logger.info("Passwurd. Initialization. Property AS_REDIRECT_URI is mandatory");
			return false;
		}

		if (StringHelper.isEmpty(configAttributes.get("PORTAL_JWKS")) ) {
			logger.info("Passwurd. Initialization. Property PORTAL_JWKS is mandatory");
			return false;
		}

		if (StringHelper.isEmpty(configAttributes.get("PASSWURD_KEY_A_KEYSTORE"))) {
			logger.info("Passwurd. Initialization. Property PASSWURD_KEY_A_KEYSTORE is mandatory");
			return false;
		}

		if (StringHelper.isEmpty(configAttributes.get("PASSWURD_KEY_A_PASSWORD")) ) {
			logger.info("Passwurd. Initialization. Property PASSWURD_KEY_A_PASSWORD is mandatory");
			return false;
		} else {
			cryptoProvider = new AuthCryptoProvider(configAttributes.get("PASSWURD_KEY_A_KEYSTORE"),
					configAttributes.get("PASSWURD_KEY_A_PASSWORD"), null);
			logger.info("Passwurd. Initialization. Keystore initialized");
		}

		if (StringHelper.isEmpty(configAttributes.get("PASSWURD_API_URL")) ) {
			logger.info("Passwurd. Initialization. Property PASSWURD_API_URL is mandatory");
			return false;
		}
		if (StringHelper.isEmpty(configAttributes.get("AS_SSA")) ) {
			logger.info("Passwurd. Initialization. Property AS_SSA is mandatory");
			return false;
		}

		if (StringHelper.isEmpty(configAttributes.get("AS_CLIENT_ID")) ) {

			Map<String, String> clientRegistrationResponse = registerScanClient(configAttributes.get("AS_ENDPOINT"),
					configAttributes.get("AS_REDIRECT_URI"), configAttributes.get("AS_SSA"));
			if (clientRegistrationResponse == null)
				logger.info("Passwurd. Unable to register client with AS");
			return false;

			configAttributes.put("AS_CLIENT_ID", clientRegistrationResponse.get("client_id"));
			configAttributes.put("AS_CLIENT_SECRET", clientRegistrationResponse.get("client_secret"));
			configAttributes.put("ORG_ID", clientRegistrationResponse.get("org_id"));
		}
                logger.info("Passwurd. Initialization. Completed");
	}

	public static boolean addUser(boolean userExists, String uid) {

		
		
		User resultUser = userService.getUserByAttribute("uid", uid);
		logger.info("userExists:" + resultUser);
		if (resultUser == null) {
			logger.info("Passwurd. Adding user: " + uid);
			User user = new User();
			user.setAttribute("uid", uid);
			user = userService.addUser(user, true);
			logger.info("User has been added - " + uid);
		} else
		{	return true; }

	}
	
	public static Map<String, String> registerScanClient(String asBaseUrl, String asRedirectUri, String asSSA) {
		logger.info("Passwurd. Attempting to register client");
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
			logger.info("Passwurd. Get client registration response status code: " + httpResponseStatusCode);

			if (httpService.isResponseStastusCodeOk(httpResponse) == false) {
				logger.info("Passwurd. Scan. Get invalid registration");
				httpService.consume(httpResponse);
				return null;
			}
			byte[] bytes = httpService.getResponseContent(httpResponse);

			response = httpService.convertEntityToString(bytes);
		} catch (Exception e) {
			logger.info("Passwurd. Failed to send client registration request: ");
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

			logger.info("Passwurd. Stored client credentials in script parameters");
		} catch (Exception e) {
			logger.error("Passwurd. Failed to store client credentials.", e);
			return null;
		}
		return result;

	}

	public static boolean userExists(String uid) {
		
		logger.info("Passwurd. userExists username: " + uid);
		if (uid == null || uid.isBlank()) {

			return false;
		} else {
			User resultUser = userService.getUserByAttribute("uid", uid);
			logger.info("userExists:" + resultUser);
			if (resultUser == null)
				return false;
			else
				return true;
		}
	}

	public static String getAccessTokenJansServer() {

		HttpClient httpClient = (HttpClient)httpService.getHttpsClient();
		logger.info("HttpClient : "+httpClient.getClass());
		String url = configAttributes.get("AS_ENDPOINT") + "/jans-auth/restv1/token";
		logger.info("configAttributes.get(AS_REDIRECT_URI): " + configAttributes.get("AS_REDIRECT_URI"));
		String data = "grant_type=client_credentials&scope=https://api.gluu.org/auth/scopes/scan.passwurd&redirect_uri=" + configAttributes.get("AS_REDIRECT_URI");
		Map<String, String> header = new HashMap<String, String>();
		header.put("Content-type", "application/x-www-form-urlencoded");
		header.put("Accept", "application/json");
		String encodedString = Base64.encodeBase64String((configAttributes.get("AS_CLIENT_ID") + ":" + configAttributes.get("AS_CLIENT_SECRET")).getBytes());
		

		HttpServiceResponse resultResponse = null;
		try {
			resultResponse = httpService.executePost(httpClient, url, encodedString, header, data);
			HttpResponse httpResponse = resultResponse.getHttpResponse();
			if (httpService.isResponseStastusCodeOk(httpResponse) == false) {
				logger.info("Passwurd. Jans-Auth getAccessToken. Get invalid response from server: ",
						(httpResponse.getStatusLine().getStatusCode()));
				httpService.consume(httpResponse);
				return null;
			} else {
				byte[] response_bytes = httpService.getResponseContent(httpResponse);
				String response_string = httpService.convertEntityToString(response_bytes);
				httpService.consume(httpResponse);

				if (response_string == null) {
					logger.info("Passwurd. getAccessToken. Got empty response from validation server");
					return null;
				}
				JSONObject response = new JSONObject(response_string);

				logger.info("Passwurd. response access token: " + response.get("access_token"));
				return String.valueOf(response.get("access_token"));
			}

		} catch (Exception e) {
			logger.error("Jans Auth Server - getAccessToken", e);
			return null;
		} finally {
			if (resultResponse != null) {
				resultResponse.closeConnection();
			}
		}

	}

	public static boolean validateOTP(HashMap<String, String> credentialMap) {
		String otp = credentialMap.get("first") + credentialMap.get("second") + credentialMap.get("third")
				+ credentialMap.get("fourth");
		logger.info("Passwurd. validateOTP: " + otp);
		if (otp.equals("1234"))

		{
			return true;
		} else
			return false;

	}
	public static String signUid(String uid) {

		String alias = (CdiUtil.bean(io.jans.as.model.configuration.AppConfiguration.class).getIssuer())
				.replace("https://", "");
		logger.info("alias : " + alias);

		// cryptoProvider = new
		// AuthCryptoProvider(configAttributes.get("PASSWURD_KEY_A_KEYSTORE"),
		// configAttributes.get("PASSWURD_KEY_A_PASSWORD"), null);
		logger.info("cryptoProvider : " + cryptoProvider);
		SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.fromString(SignatureAlgorithm.DEF_RS256);
		logger.info("signatureAlgorithm : " + signatureAlgorithm);
		String signedUID = cryptoProvider.sign(uid, alias, "changeit", signatureAlgorithm);
		logger.info("signedUID : " + signedUID);
		return signedUID;
	}

	public static int validateKeystrokes(String username, HashMap<String, String> credentialMap) {
		logger.info("Passwurd. Attempting to validate keystrokes" + credentialMap);
		credentialMap.forEach((key, value) -> logger.info(key + ":" + value));

		try {
			
			logger.info("Passwurd. validateKeystrokes username" + username);
			logger.info("Passwurd. validateKeystrokes k_username" + credentialMap.get("k_username"));
			String customer_sig = signUid(username);
			String access_token = getAccessTokenJansServer();
						
			StringBuffer data = new StringBuffer();
			data.append("{");
			data.append("\"k_username\" : " + credentialMap.get("k_username"));
			data.append(",");
			data.append("\"k_pwd\" : " + credentialMap.get("k_pwd"));
			data.append(",");
			data.append("\"customer_sig\" : \"" + customer_sig + "\"");
			data.append(",");
			data.append("\"org_id\" : \"" + configAttributes.get("ORG_ID") + "\"");
			data.append(",");
			data.append("\"uid\" : \"" + username + "\"}");

			Map<String, String> headers = new HashMap<String, String>();
			headers.put("Accept", "application/json");
			headers.put("Content-Type", "application/json");
			headers.put("Authorization", "Bearer " + access_token);
			String endpointUrl = configAttributes.get("PASSWURD_API_URL") + "/validate";

			HttpClient httpClient = httpService.getHttpsClient();
			logger.info("endpointUrl: "+endpointUrl);
			logger.info("headers: "+headers);
			logger.info("data: "+data.toString());
			
			HttpServiceResponse resultResponse = httpService.executePost(httpClient, endpointUrl, null,	headers, data.toString());
			HttpResponse httpResponse = resultResponse.getHttpResponse();
			String httpResponseStatusCode = httpResponse.getStatusLine().getStatusCode();
			logger.info("Passwurd. validate keystrokes response status code: " + httpResponseStatusCode);
			logger.info("Passwurd. validate keystrokes httpResponse: " + httpResponse);
			if (httpService.isResponseStastusCodeOk(httpResponse) == false) {
				logger.info("Passwurd. Validate response invalid ");
				httpService.consume(httpResponse);
				
			}
			byte[] bytes = httpService.getResponseContent(httpResponse);
			String response = httpService.convertEntityToString(bytes);
			logger.info("Response : "+response);
			JSONObject dataResponse = new JSONObject(response);
		
			if (StringHelper.equalsIgnoreCase(httpResponseStatusCode, "200")
					|| StringHelper.equalsIgnoreCase(httpResponseStatusCode, "202")) {

				if (StringHelper.equalsIgnoreCase(dataResponse.get("status"), "Enrollment")) {
					logger.info("Enrollment");
					return Integer.valueOf(dataResponse.get("track_id"));
				} else if (StringHelper.equalsIgnoreCase(dataResponse.get("status"), "Approved")) {
					logger.info("Approved");
					return 0;
				} else if (StringHelper.equalsIgnoreCase(dataResponse.get("status"), "Denied")) {
					logger.info("Denied" + dataResponse.get("track_id"));
					return Integer.valueOf(dataResponse.get("track_id"));

				} else {
					logger.info("Some error " + dataResponse.get("status"));
					return -4;
				}
				logger.info("Keystrokes validated successfully");
			} else if (StringHelper.equalsIgnoreCase(httpResponseStatusCode, "401")) {

				logger.info("Passwurd. Error 401");
				return -2;
			}  
			else if (StringHelper.equalsIgnoreCase(httpResponseStatusCode, "422")) {

				logger.info("Passwurd. Error 422");
				return -2;
			} else if (StringHelper.equalsIgnoreCase(httpResponseStatusCode, "400")) {
				logger.info(
						"Passwurd. in this case the password text mismatched, hence we do not offer the 2FA option");
				return -2;
			} else {
				logger.info("Failed to validate keystrokes, API returned error " + httpResponseStatusCode);
				return -4;
			}
		} catch (Exception e) {
			logger.info("Passwurd. Failed to execute /validate.", e);
			return -4;
		}
	}

	public static boolean notifyProfile(String uid, int trackId) {

		String access_token = getAccessTokenJansServer();
		
		try {

			JSONObject data = new JSONObject();
			data.put("uid", uid);
			data.put("track_id",trackId);

			Map<String, String> headers = new HashMap<String, String>();
			headers.put("Accept", "application/json");
			headers.put("Content-Type", "application/json");
			headers.put("Authorization", "Bearer " + access_token);

			String endpointUrl = configAttributes.get("PASSWURD_API_URL") + "/notify";

			HttpClient httpClient = httpService.getHttpsClient();
			logger.info("Passwurd. notifyProfile: " + data.toString());
			HttpServiceResponse resultResponse = httpService.executePost(httpClient, endpointUrl, null, headers, data.toString());
			HttpResponse httpResponse = resultResponse.getHttpResponse();
			String httpResponseStatusCode = httpResponse.getStatusLine().getStatusCode();
			logger.info("Passwurd. Notify response status code: " + httpResponseStatusCode);

			if (httpService.isResponseStastusCodeOk(httpResponse) == false) {
				logger.info("Passwurd. Notify response invalid ");
				httpService.consume(httpResponse);
				return null;
			}
			byte[] bytes = httpService.getResponseContent(httpResponse);

			String response = httpService.convertEntityToString(bytes);
			data = new JSONObject(response);
			logger.info(data.getString("status"));

		} catch (Exception e) {
			logger.info("Passwurd. Failed to execute /notify.", e);
			// return true irrespective of the result

		}
		return true;
	}
}