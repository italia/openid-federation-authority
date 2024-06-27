package it.ipzs.fedauthority.model;

import java.util.HashMap;
import java.util.Map;

public enum RoleEnum {

	RELYING_PARTY("openid_relying_party"), FEDERATION_ENTITY("federation_entity"), PROVIDER("openid_provider"),
	CREDENTIAL_ISSUER("openid_credential_issuer"), OAUTH_RESOURCES("oauth_resource"),
	WALLET_PROVIDER("wallet_provider"), WALLET_RELYING_PARTY("wallet_relying_party");

	private String description;

	private static final Map<String, RoleEnum> map = new HashMap<>(values().length);

	static {
		for (RoleEnum oe : values())
			map.put(oe.getDescription(), oe);
	}

	private RoleEnum(String descr) {
		this.description = descr;
	}

	public String getDescription() {
		return this.description;
	}

	public static RoleEnum of(String description) {
		RoleEnum res = map.get(description);
		if (res == null) {
			throw new IllegalArgumentException("Invalid value: " + description);
		}
		return res;
	}

}
