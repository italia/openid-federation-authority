package it.ipzs.fedauthority.oidclib;

import org.json.JSONObject;

public class FederationEntityOptions {

	private String organization_name;

	private String homepage_uri;

	private String policy_uri;

	private String tos_uri;

	private String logo_uri;

	private String federation_fetch_endpoint;

	private String federation_resolve_endpoint;

	private String federation_trust_mark_status_endpoint;

	private String federation_list_endpoint;

	private String federation_historical_jwks_endpoint;

	public String getOrganization_name() {
		return organization_name;
	}

	public void setOrganization_name(String organization_name) {
		this.organization_name = organization_name;
	}

	public String getHomepage_uri() {
		return homepage_uri;
	}

	public void setHomepage_uri(String homepage_uri) {
		this.homepage_uri = homepage_uri;
	}

	public String getPolicy_uri() {
		return policy_uri;
	}

	public void setPolicy_uri(String policy_uri) {
		this.policy_uri = policy_uri;
	}

	public String getTos_uri() {
		return tos_uri;
	}

	public void setTos_uri(String tos_uri) {
		this.tos_uri = tos_uri;
	}

	public String getLogo_uri() {
		return logo_uri;
	}

	public void setLogo_uri(String logo_uri) {
		this.logo_uri = logo_uri;
	}

	public JSONObject toJSON() {
		JSONObject json = new JSONObject();

		json.put("organization_name", organization_name);
		json.put("homepage_uri", homepage_uri);
		json.put("policy_uri", policy_uri);
		json.put("tos_uri", tos_uri);
		json.put("logo_uri", logo_uri);
		json.put("federation_list_endpoint", federation_list_endpoint);
		json.put("federation_fetch_endpoint", federation_fetch_endpoint);
		json.put("federation_trust_mark_status_endpoint", federation_trust_mark_status_endpoint);
		json.put("federation_resolve_endpoint", federation_resolve_endpoint);
		json.put("federation_historical_jwks_endpoint", federation_historical_jwks_endpoint);


		return json;
	}

	public String getFederation_fetch_endpoint() {
		return federation_fetch_endpoint;
	}

	public void setFederation_fetch_endpoint(String federation_fetch_endpoint) {
		this.federation_fetch_endpoint = federation_fetch_endpoint;
	}

	public String getFederation_resolve_endpoint() {
		return federation_resolve_endpoint;
	}

	public void setFederation_resolve_endpoint(String federation_resolve_endpoint) {
		this.federation_resolve_endpoint = federation_resolve_endpoint;
	}

	public String getFederation_trust_mark_status_endpoint() {
		return federation_trust_mark_status_endpoint;
	}

	public void setFederation_trust_mark_status_endpoint(String federation_trust_mark_status_endpoint) {
		this.federation_trust_mark_status_endpoint = federation_trust_mark_status_endpoint;
	}

	public String getFederation_list_endpoint() {
		return federation_list_endpoint;
	}

	public void setFederation_list_endpoint(String federation_list_endpoint) {
		this.federation_list_endpoint = federation_list_endpoint;
	}

	public String getFederation_historical_jwks_endpoint() {
		return federation_historical_jwks_endpoint;
	}

	public void setFederation_historical_jwks_endpoint(String federation_historical_jwks_endpoint) {
		this.federation_historical_jwks_endpoint = federation_historical_jwks_endpoint;
	}
}