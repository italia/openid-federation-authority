package it.ipzs.fedauthority.oidclib.helper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OidHelper {

	private static final Logger logger = LoggerFactory.getLogger(OidHelper.class);

	private final JWTHelper jwtHelper;

	public OidHelper(JWTHelper jwtHelper) {
		this.jwtHelper = jwtHelper;
	}


}
