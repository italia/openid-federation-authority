package it.ipzs.fedauthority.service;

import java.util.Calendar;
import java.util.List;
import java.util.Optional;

import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import it.ipzs.fedauthority.dto.EntityConfigurationDto;
import it.ipzs.fedauthority.model.OidcRoleEnum;
import it.ipzs.fedauthority.model.OnboardEntity;
import it.ipzs.fedauthority.repository.OnboardEntityRepository;
import it.ipzs.fedauthority.util.JwtUtil;
import it.ipzs.fedauthority.util.StringUtil;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class OnboardEntityService {
	
	@Autowired OnboardEntityRepository onboardEntityRepository;

	@Autowired
	JwtUtil jwtUtil;

	@Value("${fed-config.hosts.trust-anchor}")
	private String sourceEndpointBasePath;

	public OnboardEntity save(OnboardEntity onboardEntity) {
		return onboardEntityRepository.save(onboardEntity);
	}

	public List<String> listSubordinates() {
		log.debug("listing subordinates where flag active true...");
		return onboardEntityRepository.findByActiveTrue().stream().map(OnboardEntity::getUrl).toList();

	}

	public String fetchByIssAndSub(String iss, String sub) {
		validateParams(iss);
		String result = null;
		String subUsed = sub;
		if (StringUtil.isBlank(subUsed)) {
			log.debug(
					"no sub, considered to be the same as the issuer and indicates a request for a self-signed Entity Configuration.");
			subUsed = iss;
		}

		Optional<OnboardEntity> optional = onboardEntityRepository.findByUrl(subUsed);
		if (optional.isPresent()) {
			OnboardEntity subEntity = optional.get();
			EntityConfigurationDto ec = new EntityConfigurationDto();
			Calendar instance = Calendar.getInstance();
			ec.setIss(iss);
			ec.setSub(subEntity.getUrl());
			ec.setIat(instance.getTimeInMillis() / 1000);
			instance.add(Calendar.YEAR, 1);
			ec.setExp(instance.getTimeInMillis() / 1000);
			ec.setSourceEndpoint(StringUtil.concat("http://", sourceEndpointBasePath, "/fetch"));
			String jwkString = new JSONObject(subEntity.getJwk()).toString();
			JSONObject jwks = new JSONObject(jwkString);
			ec.setJwks(jwks);
			JSONObject metadataPolicy = new JSONObject();
			JSONObject contacts = new JSONObject();
			JSONArray add = new JSONArray();
			add.put(subEntity.getEmail());
			contacts.put("add", add);
			switch(subEntity.getRole()) {
			case RELYING_PARTY: {
					if (subEntity.getEmail() != null) {
						JSONObject wrp = new JSONObject();
						wrp.put("contacts", contacts);
						metadataPolicy.put(OidcRoleEnum.RELYING_PARTY.getDescription(), wrp);
						ec.setMetadataPolicy(metadataPolicy);

					}
					break;
				}
				case CREDENTIAL_ISSUER: {
					if (subEntity.getEmail() != null) {
						JSONObject wrp = new JSONObject();
						wrp.put("contacts", contacts);
						metadataPolicy.put(OidcRoleEnum.CREDENTIAL_ISSUER.getDescription(), wrp);
						ec.setMetadataPolicy(metadataPolicy);

					}
					break;
				}
				case PROVIDER: {
					metadataPolicy.put(OidcRoleEnum.PROVIDER.getDescription(), "");
					break;
				}
				default: {
					log.info("");
					break;
	
				}
			}

			log.info("{}", ec);

			result = jwtUtil.generateECJwt(ec);

		} else {
			log.info("No entity found for url {}", sub);

		}

		return result;
	}

	private void validateParams(String iss) {
		if (StringUtil.isBlank(iss)) {
			log.error("iss param is empty");
			throw new RuntimeException("iss param is empty");
		}

	}

	public String resolveBySubTypeAndAnchor(String sub, String type, String anchor) {
		String result = null;
		Optional<OnboardEntity> optional = onboardEntityRepository.findByUrl(sub);
		if (optional.isPresent()) {
			OnboardEntity oe = optional.get();
			EntityConfigurationDto ec = new EntityConfigurationDto();
			Calendar instance = Calendar.getInstance();
			ec.setIss(StringUtil.concat("http://", sourceEndpointBasePath));
			ec.setSub(oe.getUrl());
			ec.setIat(instance.getTimeInMillis() / 1000);
			instance.add(Calendar.YEAR, 1);
			ec.setExp(instance.getTimeInMillis() / 1000);
			String jwkString = new JSONObject(oe.getJwk()).toString();
			JSONObject jwks = new JSONObject(jwkString);
			ec.setJwks(jwks);
			JSONObject metadataPolicy = null;
			
			switch(OidcRoleEnum.of(type)) {
				case CREDENTIAL_ISSUER: {
					metadataPolicy = resolveMetadataForCredentialIssuer(oe);
					break;
				}
				case PROVIDER: {
					metadataPolicy = resolveMetadataForOidcProvider(oe);
					break;
				}
				case RELYING_PARTY: {
					metadataPolicy = resolveMetadataForOidcRelyingParty(oe);
					break;
				}
				default: {
					metadataPolicy = resolveMetadata(oe);
					break;
				}
			}
			
			ec.setMetadataPolicy(metadataPolicy);

			log.info("{}", ec);

			result = jwtUtil.generateResolveECJwt(ec);

		}

		return result;
	}

	private JSONObject resolveMetadata(OnboardEntity oe) {
		// put all metadata for this entity
		// TODO stub for testing purpose, retrieve from EC
		JSONObject result = new JSONObject();
		String jwkString = new JSONObject(oe.getJwk()).toString();
		JSONObject jwks = new JSONObject(jwkString);
		result.put("jwks", jwks);
		return result;
	}

	private JSONObject resolveMetadataForOidcProvider(OnboardEntity oe) {
		// filter metadata only for OIDC Provider
		// TODO stub for testing purpose, retrieve from EC
		JSONObject result = new JSONObject();
		String jwkString = new JSONObject(oe.getJwk()).toString();
		JSONObject jwks = new JSONObject(jwkString);
		result.put("jwks", jwks);
		result.put("issuer", oe.getUrl());
		result.put("authorization_endpoint", StringUtil.concat("/authorize"));
		result.put("token_endpoint", StringUtil.concat("/token"));
		result.put("scopes_supported", List.of("openid"));
		result.put("response_types", List.of("code", "id_token", "token id_token"));
		result.put("grant_types", List.of("authorization_code", "implicit"));
		result.put("id_token_signed_response_alg", List.of("RS256"));

		return result;
	}

	private JSONObject resolveMetadataForOidcRelyingParty(OnboardEntity oe) {
		// filter metadata only for OIDC RP
		// TODO stub for testing purpose, retrieve from EC
		JSONObject result = new JSONObject();
		String jwkString = new JSONObject(oe.getJwk()).toString();
		JSONObject jwks = new JSONObject(jwkString);
		result.put("jwks", jwks);
		result.put("redirect_uris", List.of(StringUtil.concat(oe.getUrl(), "/callback")));
		result.put("response_types", List.of("code", "id_token", "token id_token"));
		result.put("application_type", "web");
		result.put("client_name", oe.getId());
		result.put("contacts", List.of(oe.getEmail()));
		result.put("id_token_signed_response_alg", "RS256");
		result.put("token_endpoint_auth_method", "client_secret_basic");
		result.put("grant_types", List.of("authorization_code", "implicit"));
		result.put("subject_types_supported", List.of("public", "pairwise"));
		return result;
	}

	private JSONObject resolveMetadataForCredentialIssuer(OnboardEntity oe) {
		// filter metadata only for OIDC Credential Issuer
		// TODO stub for testing purpose, retrieve from EC
		JSONObject result = new JSONObject();
		String jwkString = new JSONObject(oe.getJwk()).toString();
		JSONObject jwks = new JSONObject(jwkString);
		result.put("jwks", jwks);
		result.put("credential_issuer", oe.getUrl());
		result.put("pushed_authorization_request_endpoint", StringUtil.concat(oe.getUrl(), "/par"));
		result.put("authorization_endpoint", StringUtil.concat(oe.getUrl(), "/authorize"));
		result.put("token_endpoint", StringUtil.concat(oe.getUrl(), "/token"));
		result.put("credential_endpoint", StringUtil.concat(oe.getUrl(), "/credential"));
		result.put("contacts", List.of(oe.getEmail()));
		result.put("credentials_supported", List.of("vc+sd-jwt", "vc+mdoc-cbor"));
		result.put("dpop_signing_alg_values_supported", "RS256");
		result.put("grant_types", List.of("authorization_code", "implicit"));
		return result;
	}
	
}
