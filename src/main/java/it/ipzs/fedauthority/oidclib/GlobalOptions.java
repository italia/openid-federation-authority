package it.ipzs.fedauthority.oidclib;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import it.ipzs.fedauthority.oidclib.exception.ConfigException;
import it.ipzs.fedauthority.oidclib.exception.OIDCException;
import it.ipzs.fedauthority.oidclib.util.ArrayUtil;
import it.ipzs.fedauthority.oidclib.util.Validator;
import it.ipzs.fedauthority.util.StringUtil;
import lombok.extern.slf4j.Slf4j;


@Slf4j
public class GlobalOptions<T extends GlobalOptions<T>> {

	private Set<String> allowedSigningAlgs = new HashSet<>();

	public static int getDefaultExpiringMinutes() {
		String defaultExpiringMinutes = System.getenv("DEFAULT_EXPIRING_MINUTES");
		if(defaultExpiringMinutes!=null)
			return Integer.parseInt(defaultExpiringMinutes);
		else {
			log.error("cannot find DEFAULT_EXPIRING_MINUTES env variable");
			throw new RuntimeException("DEFAULT_EXPIRING_MINUTES env is not defined");
		}
	}

	public static String getDefaultJWSAlgorithm() {
		String defaultSigningAlg = System.getenv("DEFAULT_SIGNING_ALG");
		if(StringUtil.isBlank(defaultSigningAlg)){
			log.error("DEFAULT_SIGNING_ALG env is not defined");
			throw new RuntimeException("DEFAULT_SIGNING_ALG env is not defined");
		}
		return defaultSigningAlg;
	}

	public Set<String> getAllowedSigningAlgs() {
		return Collections.unmodifiableSet(allowedSigningAlgs);
	}

	@SuppressWarnings("unchecked")
	public T setAllowedSigningAlgs(String... values) {
		if (values.length > 0) {
			allowedSigningAlgs = ArrayUtil.asSet(values);
		}

		return (T)this;
	}

	protected void validate() throws OIDCException {

		if (!allowedSigningAlgs.contains(getDefaultJWSAlgorithm())) {
			log.error(
				"Not allowed jwsDefaultAlgorithm {}", getDefaultJWSAlgorithm());
		}

	}

}
