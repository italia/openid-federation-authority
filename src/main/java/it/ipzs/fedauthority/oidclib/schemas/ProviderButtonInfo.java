package it.ipzs.fedauthority.oidclib.schemas;

import it.ipzs.fedauthority.oidclib.util.Validator;

public class ProviderButtonInfo {

	private final String subject;
	private final String organizationName;
	private final String logoUrl;

	public ProviderButtonInfo(String subject, String organizationName, String logoUrl) {
		this.subject = subject;
		this.organizationName = organizationName;
		this.logoUrl = logoUrl;
	}

	public String getSubject() {
		return subject;
	}

	public String getOrganizationName() {
		return organizationName;
	}

	public String getLogoUrl() {
		return logoUrl;
	}

	public String getTitle() {
		if (Validator.isNullOrEmpty(organizationName)) {
			return subject;
		}

		return organizationName;
	}

}
