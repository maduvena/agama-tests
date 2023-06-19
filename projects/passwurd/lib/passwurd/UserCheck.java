
package passwurd;

import org.json.JSONObject;
import org.json.JSONArray;
import io.jans.as.common.model.User;
import io.jans.as.common.service.common.UserService;
import io.jans.service.custom.CustomScriptService;
import io.jans.model.custom.script.CustomScriptType;
import io.jans.model.custom.script.model.CustomScript;
import io.jans.service.cdi.util.CdiUtil;
import io.jans.as.server.service.net.HttpService2;
import io.jans.service.cdi.util.CdiUtil;
import java.util.Map;
import java.util.HashMap;
import org.apache.http.client.HttpClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import io.jans.as.server.model.net.HttpServiceResponse;
import org.apache.http.entity.ContentType;
import org.apache.http.HttpResponse;
import io.jans.util.StringHelper;
import io.jans.model.SimpleExtendedCustomProperty;

public class UserCheck {

	private static final Logger logger = LoggerFactory.getLogger(UserCheck.class);
	private static final UserService userService = CdiUtil.bean(UserService.class);

	private static Map<String, String> configAttributes;

	public static boolean initializeFlow(Map<String, String> config) {

		configAttributes = config;
		if (configAttributes.get("AS_ENDPOINT") == null) {
			logger.debug("Passwurd. Initialization. Property AS_ENDPOINT is mandatory");
			return false;
		}
		if (configAttributes.get("AS_REDIRECT_URI") == null) {
			logger.debug("Passwurd. Initialization. Property AS_REDIRECT_URI is mandatory");
			return false;
		}

		if (configAttributes.get("PORTAL_JWKS") == null) {
			logger.debug("Passwurd. Initialization. Property PORTAL_JWKS is mandatory");
			return false;
		}

		if (configAttributes.get("PASSWURD_KEY_A_KEYSTORE") == null) {
			logger.debug("Passwurd. Initialization. Property PASSWURD_KEY_A_KEYSTORE is mandatory");
			return false;
		}

		if (configAttributes.get("PASSWURD_KEY_A_PASSWORD") == null) {
			logger.debug("Passwurd. Initialization. Property PASSWURD_KEY_A_PASSWORD is mandatory");
			return false;
		}

		if (configAttributes.get("PASSWURD_API_URL") == null) {
			logger.debug("Passwurd. Initialization. Property PASSWURD_API_URL is mandatory");
			return false;
		}
		if (configAttributes.get("AS_SSA") == null) {
			logger.debug("Passwurd. Initialization. Property AS_SSA is mandatory");
			return false;
		}

		if (configAttributes.get("AS_CLIENT_ID") == null) {

			Map<String, String> clientRegistrationResponse = registerScanClient(configAttributes.get("AS_ENDPOINT"),
					configAttributes.get("AS_REDIRECT_URI"), configAttributes.get("AS_SSA"));
			if (clientRegistrationResponse == null)
				logger.debug("Passwurd. Unable to register client with AS");
			return false;

			configAttributes.put("AS_CLIENT_ID", clientRegistrationResponse.get("client_id"));
			configAttributes.put("AS_CLIENT_SECRET", clientRegistrationResponse.get("client_secret"));
		}

	}

	public static Map<String, String> registerScanClient(String asBaseUrl, String asRedirectUri,String asSSA){
        logger.debug( "Passwurd. Attempting to register client");
        JSONObject body = new JSONObject();
        JSONObject header = new JSONObject();
        JSONArray redirect = new JSONArray();
        redirect.put(asRedirectUri);
        body.put("redirect_uris", redirect);
        body.put("software_statement", asSSA);
        header.put("Accept" , "application/json");
        
        String endpointUrl = asBaseUrl + "/jans-auth/restv1/register";
         
        String response = null;

        try {
        	HttpService2 httpService = CdiUtil.bean(HttpService2);
        	HttpClient httpClient =  httpService.getHttpsClient();
        	HttpServiceResponse resultResponse = httpService.executePost(httpClient, endpointUrl, null, header.toString(), body.toString(), ContentType.APPLICATION_JSON);
        	HttpResponse httpResponse = resultResponse.getHttpResponse();
            String httpResponseStatusCode = httpResponse.getStatusLine().getStatusCode()
            logger.debug( "Passwurd. Get client registration response status code: " +httpResponseStatusCode);

            if(  httpService.isResponseStastusCodeOk(httpResponse)== false)
            {   logger.debug(  "Passwurd. Scan. Get invalid registration");
                httpService.consume(httpResponse);
                return null;
            }
            byte [] bytes = httpService.getResponseContent(httpResponse);

            response = httpService.convertEntityToString(bytes);
        }catch(Exception e)
        {
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
            for (List<SimpleExtendedCustomProperty> conf : customScript.getConfigurationProperties())
            {
                
                if (StringHelper.equalsIgnoreCase(conf.getValue1(), "AS_CLIENT_ID"))
                {   conf.setValue2(response_data.getString("client_id")); }
                else if (StringHelper.equalsIgnoreCase(conf.getValue1(), "AS_CLIENT_SECRET"))
                {   conf.setValue2(response_data.getString("client_secret")); }
            
            }
            custScriptService.update(customScript);    

            logger.debug( "Passwurd. Stored client credentials in script parameters");
        }catch(Exception e)
        {
        	logger.error( "Passwurd. Failed to store client credentials.", e);
            return null;
        }
        return result;

}
}