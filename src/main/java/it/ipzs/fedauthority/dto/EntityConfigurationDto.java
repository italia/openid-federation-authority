package it.ipzs.fedauthority.dto;

import org.json.JSONObject;

import lombok.Data;

@Data
public class EntityConfigurationDto {

	private String iss;
	private String sub;
	private Long exp;
	private Long iat;
	private String sourceEndpoint;
	private JSONObject jwks;
	private JSONObject metadataPolicy;

}
