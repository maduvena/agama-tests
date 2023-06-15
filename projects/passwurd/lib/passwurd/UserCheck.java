package passwurd;

import io.jans.as.common.model.User;
import io.jans.as.common.service.common.UserService;
import io.jans.service.cdi.util.CdiUtil;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UserCheck{

private static final Logger logger = LoggerFactory.getLogger(UserCheck.class);
private static final UserService userService= CdiUtil.bean(UserService.class);



}