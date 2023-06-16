
package passwurd;

import io.jans.as.common.model.User;
import io.jans.as.common.service.common.UserService;
import io.jans.service.cdi.util.CdiUtil;

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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

		if (configAttributes.get("AS_SSA") == null) {
			logger.debug("Passwurd. Initialization. Property AS_SSA is mandatory");
			return false;
		}

		if (configAttributes.get("AS_CLIENT_ID") == null) {
			logger.debug("Passwurd. Initialization. Property AS_CLIENT_ID is mandatory");
			return false;
		}

		if (configAttributes.get("AS_CLIENT_SECRET") == null) {
			logger.debug("Passwurd. Initialization. Property AS_CLIENT_SECRET is mandatory");
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

	}

}