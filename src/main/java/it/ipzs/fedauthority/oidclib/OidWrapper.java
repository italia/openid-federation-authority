package it.ipzs.fedauthority.oidclib;

import java.io.File;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import com.nimbusds.jose.jwk.JWK;

import it.ipzs.fedauthority.oidclib.callback.RelyingPartyLogoutCallback;
import it.ipzs.fedauthority.oidclib.exception.OIDCException;
import it.ipzs.fedauthority.oidclib.handler.OidHandler;
import it.ipzs.fedauthority.oidclib.model.CredentialDefinition;
import it.ipzs.fedauthority.oidclib.model.CredentialEHICSubject;
import it.ipzs.fedauthority.oidclib.model.CredentialField;
import it.ipzs.fedauthority.oidclib.model.CredentialMDLSubject;
import it.ipzs.fedauthority.oidclib.model.CredentialSubject;
import it.ipzs.fedauthority.oidclib.model.CredentialType;
import it.ipzs.fedauthority.oidclib.model.DisplayConf;
import it.ipzs.fedauthority.oidclib.model.LogoConf;
import it.ipzs.fedauthority.oidclib.persistence.H2PersistenceImpl;
import it.ipzs.fedauthority.oidclib.schemas.OIDCProfile;
import it.ipzs.fedauthority.oidclib.schemas.ProviderButtonInfo;
import it.ipzs.fedauthority.oidclib.schemas.WellKnownData;
import it.ipzs.fedauthority.oidclib.util.Validator;
import jakarta.annotation.PostConstruct;

@Component
public class OidWrapper {

	private static Logger logger = LoggerFactory.getLogger(OidWrapper.class);

	@Autowired
	private FedConfig fedConfig;

	@Autowired
	private H2PersistenceImpl persistenceImpl;

	private OidHandler oidcHandler;

	public String getAuthorizeURL(
			String spidProvider, String trustAnchor, String redirectUri, String scope,
			String profile, String prompt)
			throws OIDCException {

		return oidcHandler.getAuthorizeURL(
				spidProvider, trustAnchor, redirectUri, scope, profile, prompt);
	}

	public List<ProviderButtonInfo> getProviderButtonInfos(OIDCProfile profile)
			throws OIDCException {

		return oidcHandler.getProviderButtonInfos(profile);
	}

	public JSONObject getUserInfo(String state, String code)
			throws OIDCException {

		return oidcHandler.getUserInfo(state, code);
	}

	public String getUserKey(JSONObject userInfo) {
		String userKey = userInfo.optString("https://attributes.spid.gov.it/email");

		if (Validator.isNullOrEmpty(userKey)) {
			userKey = userInfo.optString("email", "");
		}

		return userKey;
	}

	public WellKnownData getWellKnownData(String requestURL, boolean jsonMode)
			throws OIDCException {

		return oidcHandler.getWellKnownData(requestURL, jsonMode);
	}

	public WellKnownData getWellKnownData(boolean jsonMode) throws OIDCException {

		return oidcHandler.getWellKnownData(jsonMode);
	}

	public WellKnownData getFederationEntityData()
			throws OIDCException {

		return oidcHandler.getWellKnownData(true);
	}

	public String performLogout(String userKey, RelyingPartyLogoutCallback callback)
			throws OIDCException {

		return oidcHandler.performLogout(userKey, callback);
	}

	public void reloadHandler() throws OIDCException {
		logger.info("reload handler");

		postConstruct();
	}

	public JWK getJWK() throws ParseException {
		String jwk = oidcHandler.retrieveJWK();
		JWK parsedJWK = null;
		try {
			parsedJWK = JWK.parse(jwk);
		} catch (ParseException e) {
			logger.error("", e);
			throw e;
		}

		return parsedJWK;
	}

	public JWK getRelyingPartyJWK() throws ParseException {
		String jwk = oidcHandler.retrieveRelyingPartyJWK();
		JWK parsedJWK = null;
		try {
			parsedJWK = JWK.parse(jwk);
		} catch (ParseException e) {
			logger.error("", e);
			throw e;
		}

		return parsedJWK;
	}

	public JWK getCredentialIssuerJWK() throws ParseException {
		String credJwk = oidcHandler.getCredentialOptions().getJwk();
		JWK parsedJWK = null;
		try {
			parsedJWK = JWK.parse(credJwk);
		} catch (ParseException e) {
			logger.error("", e);
			throw e;
		}

		return parsedJWK;
	}

	public String getCredentialIssuerTrustMarks() {
		return oidcHandler.getCredentialOptions().getTrustMarks();
	}

	public List<String> getCredentialIssuerTrustChain() {
		return generateCredentialIssuerTrustChain();
	}

	private List<String> generateCredentialIssuerTrustChain() {
		RestTemplate restTemplate = new RestTemplate();

		try {
			ResponseEntity<String> entity = restTemplate.getForEntity(new URI(fedConfig.getFederationTrustChainUrl()),
					String.class);
			String fedTc = entity.getBody();

			WellKnownData wellKnown = getWellKnownData(false);

			return List.of(wellKnown.getValue(), fedTc);

		} catch (RestClientException | URISyntaxException | OIDCException e) {
			logger.error("Error in trust chain retrieval", e);

			throw new RuntimeException(e);
		}

	}

	public List<String> getRelyingPartyTrustChain() {
		return generateRelyingPartyTrustChain();
	}

	private List<String> generateRelyingPartyTrustChain() {
		logger.info("Trust chain retrieval");
		RestTemplate restTemplate = new RestTemplate();

		try {
			ResponseEntity<String> entity = restTemplate.getForEntity(new URI(
							fedConfig.getFederationTrustChainUrl()),
					String.class);
			String fedTc = entity.getBody();
			logger.info("> HTTP status code {}", entity.getStatusCode());

			WellKnownData wellKnown = getWellKnownData(false);

			return List.of(wellKnown.getValue(), fedTc);

		} catch (Exception e) {
			if (e instanceof HttpStatusCodeException rce) {
				logger.error("-> HTTP status code {}", rce.getStatusCode());
			} else {
				logger.error("", e);
			}

			throw new RuntimeException(e);
		}

	}

	@PostConstruct
	private void postConstruct() throws OIDCException {
		String jwk = readFile(fedConfig.getRelyingParty().getJwkFilePath());
		String trustMarks = readFile(
				fedConfig.getRelyingParty().getTrustMarksFilePath());

		logger.debug("final jwk: {}", jwk);
		logger.debug("final trust_marks: {}", trustMarks);

		RelyingPartyOptions options = new RelyingPartyOptions()
				.setDefaultTrustAnchor(fedConfig.getDefaultTrustAnchor())
				.setCIEProviders(fedConfig.getIdentityProviders(OIDCProfile.CIE))
				.setSPIDProviders(fedConfig.getIdentityProviders(OIDCProfile.SPID))
				.setTrustAnchors(fedConfig.getTrustAnchors())
				.setApplicationName(fedConfig.getRelyingParty().getApplicationName())
				.setClientId(fedConfig.getRelyingParty().getClientId())
				.setRedirectUris(fedConfig.getRelyingParty().getRedirectUris())
				.setRequestUris(fedConfig.getRelyingParty().getRequestUris())
				.setContacts(fedConfig.getRelyingParty().getContacts())
				.setJWK(jwk)
				.setTrustMarks(trustMarks);

		String credJwk = readFile(fedConfig.getOpenidCredentialIssuer().getJwkFilePath());

		OIDCCredentialIssuerOptions credentialOptions = OIDCCredentialIssuerOptions.builder()
				.pushedAuthorizationRequestEndpoint(
						fedConfig.getOpenidCredentialIssuer().getPushedAuthorizationRequestEndpoint())
				.credentialEndpoint(fedConfig.getOpenidCredentialIssuer().getCredentialEndpoint())
				.credentialIssueUrl(fedConfig.getOpenidCredentialIssuer().getCredentialIssuer())
				.tokenEndpoint(fedConfig.getOpenidCredentialIssuer().getTokenEndpoint())
				.authorizationEndpoint(fedConfig.getOpenidCredentialIssuer().getAuthorizationEndpoint())
				.credentialsSupported(generateCredentialSupportedList())
				.jwk(credJwk)
				.sub(fedConfig.getOpenidCredentialIssuer().getSub())
				.trustChain(fedConfig.getOpenidCredentialIssuer().getTrustChain())
				.build();

		FederationEntityOptions fedEntOptions = new FederationEntityOptions();
		fedEntOptions.setHomepage_uri(fedConfig.getFederationEntity().getHomepageUri());
		fedEntOptions.setTos_uri(fedConfig.getFederationEntity().getTosUri());
		fedEntOptions.setPolicy_uri(fedConfig.getFederationEntity().getPolicyUri());
		fedEntOptions.setLogo_uri(fedConfig.getFederationEntity().getLogoUri());
		fedEntOptions.setOrganization_name(fedConfig.getFederationEntity().getOrganizationName());
		fedEntOptions.setFederation_fetch_endpoint(fedConfig.getFederationEntity().getFederation_fetch_endpoint());
		fedEntOptions.setFederation_historical_jwks_endpoint(fedConfig.getFederationEntity().getFederation_historical_jwks_endpoint());
		fedEntOptions.setFederation_resolve_endpoint(fedConfig.getFederationEntity().getFederation_resolve_endpoint());
		fedEntOptions.setFederation_list_endpoint(fedConfig.getFederationEntity().getFederation_list_endpoint());
		fedEntOptions.setFederation_trust_mark_status_endpoint(fedConfig.getFederationEntity().getFederation_trust_mark_status_endpoint());

		oidcHandler = new OidHandler(options, persistenceImpl, credentialOptions, fedEntOptions);
//		try {
//			generateRelyingPartyTrustChain();
//		} catch (Exception e) {
//			logger.error("error in trust chain retrieval");
//		}
	}

	private List<CredentialType> generateCredentialSupportedList() {
		List<CredentialType> credentialSupported = new ArrayList<>();

		CredentialType cedSdJwt = generateSdJwtCEDCredType();
		credentialSupported.add(cedSdJwt);

		CredentialType ehicSdJwt = generateSdJwtEHICCredType();
		credentialSupported.add(ehicSdJwt);

		CredentialType mDLSdJwt = generateMDLCredType("vc+sd-jwt");
		credentialSupported.add(mDLSdJwt);

		CredentialType mDLCbor = generateMDLCredType("vc+mdoc-cbor");
		credentialSupported.add(mDLCbor);

		return credentialSupported;
	}

	private CredentialType generateSdJwtEHICCredType() {

		CredentialType cred = new CredentialType();

		cred.setId(it.ipzs.fedauthority.dto.CredentialType.EHIC.value().toLowerCase() + "."
				+ fedConfig.getOpenidCredentialIssuer().getId());

		cred.setFormat("vc+sd-jwt");
		DisplayConf d1 = DisplayConf.builder().name("QEAA Issuer").locale("it-IT").background_color("#12107c")
				.text_color("#FFFFFF")
				.logo(LogoConf.builder().url(
						"https://" + fedConfig.getOpenidCredentialIssuer().getCredentialIssuer() + "/public/logo.svg")
						.alt_text("logo").build())
				.build();

		DisplayConf d2 = DisplayConf.builder().name("QEAA Issuer").locale("en-US").background_color("#12107c")
				.text_color("#FFFFFF")
				.logo(LogoConf.builder().url(
						"https://" + fedConfig.getOpenidCredentialIssuer().getCredentialIssuer() + "/public/logo.svg")
						.alt_text("logo").build())
				.build();
		cred.setDisplay(List.of(d1, d2));

		CredentialDefinition credDef = new CredentialDefinition();
		credDef.getType().add(it.ipzs.fedauthority.dto.CredentialType.EHIC.value());
		CredentialEHICSubject credSubj = new CredentialEHICSubject();
		credSubj.setGiven_name(CredentialField.builder().mandatory(true)
				.display(List.of(DisplayConf.builder().name("Nome").locale("it-IT").build(),
						DisplayConf.builder().name("First Name").locale("en-US").build()))
				.build());

		credSubj.setFamily_name(CredentialField.builder().mandatory(true)
				.display(List.of(DisplayConf.builder().name("Cognome").locale("it-IT").build(),
						DisplayConf.builder().name("Family Name").locale("en-US").build()))
				.build());

		credSubj.setBirthdate(CredentialField.builder().mandatory(true)
				.display(List.of(DisplayConf.builder().name("Data di Nascita").locale("it-IT").build(),
						DisplayConf.builder().name("Date of Birth").locale("en-US").build()))
				.build());

		credSubj.setPlace_of_birth(CredentialField.builder().mandatory(true)
				.display(List.of(DisplayConf.builder().name("Luogo di Nascita").locale("it-IT").build(),
						DisplayConf.builder().name("Place of Birth").locale("en-US").build()))
				.build());

		credSubj.setFiscal_code(CredentialField.builder().mandatory(true)
				.display(List.of(DisplayConf.builder().name("Codice Fiscale").locale("it-IT").build(),
						DisplayConf.builder().name("Fiscal Code").locale("en-US").build()))
				.build());

		credSubj.setProvince(CredentialField.builder().mandatory(true)
				.display(List.of(DisplayConf.builder().name("Provincia").locale("it-IT").build(),
						DisplayConf.builder().name("Province").locale("en-US").build()))
				.build());

		credSubj.setSex(CredentialField.builder().mandatory(true)
				.display(List.of(DisplayConf.builder().name("Sesso").locale("it-IT").build(),
						DisplayConf.builder().name("Sex").locale("en-US").build()))
				.build());

		credSubj.setExpiry_date(CredentialField.builder().mandatory(true)
				.display(List.of(DisplayConf.builder().name("Data di Scadenza").locale("it-IT").build(),
						DisplayConf.builder().name("Expiry Date").locale("en-US").build()))
				.build());

		credSubj.setNation(CredentialField.builder().mandatory(true)
				.display(List.of(DisplayConf.builder().name("Nazione").locale("it-IT").build(),
						DisplayConf.builder().name("Nation").locale("en-US").build()))
				.build());

		credSubj.setDocument_number_team(
				CredentialField.builder().mandatory(true)
						.display(List.of(
								DisplayConf.builder().name("Numero identificativo della tessera (TEAM)").locale("it-IT")
										.build(),
								DisplayConf.builder().name("Document Number (TEAM)").locale("en-US").build()))
						.build());

		credSubj.setInstitution_number_team(CredentialField.builder().mandatory(true)
				.display(List.of(
						DisplayConf.builder().name("Numero identificativo dell'istituzione (TEAM)").locale("it-IT")
								.build(),
						DisplayConf.builder().name("Institution Number (TEAM)").locale("en-US").build()))
				.build());

		credDef.setCredentialSubject(credSubj);

		cred.setCredential_definition(credDef);
		return cred;

	}

	private CredentialType generateSdJwtCEDCredType() {
		CredentialType cred = new CredentialType();

		cred.setId(it.ipzs.fedauthority.dto.CredentialType.EDC.value().toLowerCase() + "."
				+ fedConfig.getOpenidCredentialIssuer().getId());

		cred.setFormat("vc+sd-jwt");
		DisplayConf d1 = DisplayConf.builder().name("QEAA Issuer").locale("it-IT").background_color("#12107c")
				.text_color("#FFFFFF")
				.logo(LogoConf.builder()
						.url("https://" + fedConfig.getOpenidCredentialIssuer().getCredentialIssuer()
								+ "/public/logo.svg")
						.alt_text("logo").build())
				.build();

		DisplayConf d2 = DisplayConf.builder().name("QEAA Issuer").locale("en-US").background_color("#12107c")
				.text_color("#FFFFFF")
				.logo(LogoConf.builder().url(
								"https://" + fedConfig.getOpenidCredentialIssuer().getCredentialIssuer() + "/public/logo.svg")
						.alt_text("logo").build())
				.build();
		cred.setDisplay(List.of(d1,d2));

		CredentialDefinition credDef = new CredentialDefinition();
		credDef.getType().add(it.ipzs.fedauthority.dto.CredentialType.EDC.value());
		CredentialSubject credSubj = new CredentialSubject();
		credSubj.setGiven_name(CredentialField.builder()
				.mandatory(true)
				.display(List.of(DisplayConf.builder().name("Nome").locale("it-IT").build(),
						DisplayConf.builder().name("First Name").locale("en-US").build()))
				.build());

		credSubj.setFamily_name(CredentialField.builder().mandatory(true)
				.display(List.of(DisplayConf.builder().name("Cognome").locale("it-IT").build(),
						DisplayConf.builder().name("Family Name").locale("en-US").build()))
				.build());

		credSubj.setBirthdate(CredentialField.builder().mandatory(true)
				.display(List.of(DisplayConf.builder().name("Data di Nascita").locale("it-IT").build(),
						DisplayConf.builder().name("Date of Birth").locale("en-US").build()))
				.build());

		credSubj.setFiscal_code(CredentialField.builder().mandatory(true)
				.display(List.of(DisplayConf.builder().name("Codice Fiscale").locale("it-IT").build(),
						DisplayConf.builder().name("Fiscal Code").locale("en-US").build()))
				.build());

		credSubj.setExpiration_date(CredentialField.builder().mandatory(true)
				.display(List.of(DisplayConf.builder().name("Data di Scadenza").locale("it-IT").build(),
						DisplayConf.builder().name("Expiration Date").locale("en-US").build()))
				.build());

		credSubj.setSerial_number(CredentialField.builder().mandatory(true)
				.display(List.of(DisplayConf.builder().name("Numero Seriale").locale("it-IT").build(),
						DisplayConf.builder().name("Serial Number").locale("en-US").build()))
				.build());

		credSubj.setAccompanying_person_right(CredentialField.builder().mandatory(true)
				.display(List.of(DisplayConf.builder().name("Diritto all'accompagnatore").locale("it-IT").build(),
						DisplayConf.builder().name("Accompanying Person Right").locale("en-US").build()))
				.build());

		credDef.setCredentialSubject(credSubj);

		cred.setCredential_definition(credDef);
		return cred;
	}

	private CredentialType generateMDLCredType(String format) {
		CredentialType cred = new CredentialType();

		cred.setId(it.ipzs.fedauthority.dto.CredentialType.MDL.value().toLowerCase() + "."
				+ fedConfig.getOpenidCredentialIssuer().getId());

		cred.setFormat(format);
		DisplayConf d1 = DisplayConf.builder().name("QEAA Issuer").locale("it-IT").background_color("#12107c")
				.text_color("#FFFFFF")
				.logo(LogoConf.builder().url(
						"https://" + fedConfig.getOpenidCredentialIssuer().getCredentialIssuer() + "/public/logo.svg")
						.alt_text("logo").build())
				.build();

		DisplayConf d2 = DisplayConf.builder().name("QEAA Issuer").locale("en-US").background_color("#12107c")
				.text_color("#FFFFFF")
				.logo(LogoConf.builder().url(
						"https://" + fedConfig.getOpenidCredentialIssuer().getCredentialIssuer() + "/public/logo.svg")
						.alt_text("logo").build())
				.build();
		cred.setDisplay(List.of(d1, d2));

		CredentialDefinition credDef = new CredentialDefinition();
		credDef.getType().add(it.ipzs.fedauthority.dto.CredentialType.MDL.value());
		CredentialMDLSubject credSubj = new CredentialMDLSubject();
		credSubj.setGiven_name(CredentialField.builder().mandatory(true)
				.display(List.of(DisplayConf.builder().name("Nome").locale("it-IT").build(),
						DisplayConf.builder().name("First Name").locale("en-US").build()))
				.build());

		credSubj.setFamily_name(CredentialField.builder().mandatory(true)
				.display(List.of(DisplayConf.builder().name("Cognome").locale("it-IT").build(),
						DisplayConf.builder().name("Family Name").locale("en-US").build()))
				.build());

		credSubj.setBirthdate(CredentialField.builder().mandatory(true)
				.display(List.of(DisplayConf.builder().name("Data di nascita").locale("it-IT").build(),
						DisplayConf.builder().name("Date of Birth").locale("en-US").build()))
				.build());

		credSubj.setIssuing_authority(CredentialField.builder().mandatory(true)
				.display(List.of(DisplayConf.builder().name("Autorità di rilascio").locale("it-IT").build(),
						DisplayConf.builder().name("Issuing Authority").locale("en-US").build()))
				.build());

		credSubj.setDriving_privileges(CredentialField.builder().mandatory(true)
				.display(List.of(DisplayConf.builder().name("Categorie di veicoli").locale("it-IT").build(),
						DisplayConf.builder().name("Driving Privileges").locale("en-US").build()))
				.build());

		credSubj.setIssuing_country(CredentialField.builder().mandatory(true)
				.display(List.of(DisplayConf.builder().name("Paese di rilascio").locale("it-IT").build(),
						DisplayConf.builder().name("Issuing Country").locale("en-US").build()))
				.build());

		credSubj.setIssue_date(CredentialField.builder().mandatory(true)
				.display(List.of(DisplayConf.builder().name("Data di rilascio").locale("it-IT").build(),
						DisplayConf.builder().name("Issue Date").locale("en-US").build()))
				.build());

		credSubj.setExpiry_date(CredentialField.builder().mandatory(true)
				.display(List.of(DisplayConf.builder().name("Data di scadenza").locale("it-IT").build(),
						DisplayConf.builder().name("Expiry Date").locale("en-US").build()))
				.build());

		credSubj.setUn_distinguishing_sign(CredentialField.builder().mandatory(true)
				.display(List.of(DisplayConf.builder().name("Segno distintivo UN").locale("it-IT").build(),
						DisplayConf.builder().name("UN Distinguishing Sign").locale("en-US").build()))
				.build());

		credSubj.setDocument_number(CredentialField.builder().mandatory(true)
				.display(List.of(DisplayConf.builder().name("Numero di documento").locale("it-IT").build(),
						DisplayConf.builder().name("Document Number").locale("en-US").build()))
				.build());

		credSubj.setPortrait(CredentialField.builder().mandatory(true)
				.display(List.of(DisplayConf.builder().name("Foto").locale("it-IT").build(),
						DisplayConf.builder().name("Portrait").locale("en-US").build()))
				.build());

		credDef.setCredentialSubject(credSubj);

		cred.setCredential_definition(credDef);
		return cred;
	}

	private String readFile(String filePath) {
		if (filePath != null) {
			try {
				File file = new File(filePath);

				if (file.isFile() && file.canRead()) {
					return Files.readString(file.toPath());
				}
			} catch (Exception e) {
				logger.error(e.getMessage(), e);
			}
		}

		return "";
	}

	public void reloadKeys() {
		String jwk = readFile(fedConfig.getRelyingParty().getJwkFilePath());
		String credJwk = readFile(fedConfig.getOpenidCredentialIssuer().getJwkFilePath());
		this.oidcHandler.getCredentialOptions().setJwk(credJwk);
		this.oidcHandler.getRelyingPartyOptions().setJWK(jwk);
		logger.debug("key reloaded!");
	}

}