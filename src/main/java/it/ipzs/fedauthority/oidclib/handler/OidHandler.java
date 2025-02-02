package it.ipzs.fedauthority.oidclib.handler;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

import it.ipzs.fedauthority.oidclib.FederationEntityOptions;
import it.ipzs.fedauthority.oidclib.GlobalOptions;
import it.ipzs.fedauthority.oidclib.OidConstants;
import it.ipzs.fedauthority.oidclib.OIDCCredentialIssuerOptions;
import it.ipzs.fedauthority.oidclib.RelyingPartyOptions;
import it.ipzs.fedauthority.oidclib.callback.RelyingPartyLogoutCallback;
import it.ipzs.fedauthority.oidclib.exception.OIDCException;
import it.ipzs.fedauthority.oidclib.exception.RelyingPartyException;
import it.ipzs.fedauthority.oidclib.exception.SchemaException;
import it.ipzs.fedauthority.oidclib.exception.TrustChainException;
import it.ipzs.fedauthority.oidclib.helper.EntityHelper;
import it.ipzs.fedauthority.oidclib.helper.JWTHelper;
import it.ipzs.fedauthority.oidclib.helper.OAuth2Helper;
import it.ipzs.fedauthority.oidclib.helper.OidHelper;
import it.ipzs.fedauthority.oidclib.helper.PKCEHelper;
import it.ipzs.fedauthority.oidclib.model.AuthnRequest;
import it.ipzs.fedauthority.oidclib.model.AuthnToken;
import it.ipzs.fedauthority.oidclib.model.CachedEntityInfo;
import it.ipzs.fedauthority.oidclib.model.EntityConfiguration;
import it.ipzs.fedauthority.oidclib.model.FederationEntity;
import it.ipzs.fedauthority.oidclib.model.TrustChain;
import it.ipzs.fedauthority.oidclib.model.TrustChainBuilder;
import it.ipzs.fedauthority.oidclib.persistence.PersistenceAdapter;
import it.ipzs.fedauthority.oidclib.schemas.CIEClaimItem;
import it.ipzs.fedauthority.oidclib.schemas.ClaimItem;
import it.ipzs.fedauthority.oidclib.schemas.OIDCProfile;
import it.ipzs.fedauthority.oidclib.schemas.ProviderButtonInfo;
import it.ipzs.fedauthority.oidclib.schemas.SPIDClaimItem;
import it.ipzs.fedauthority.oidclib.schemas.Scope;
import it.ipzs.fedauthority.oidclib.schemas.TokenResponse;
import it.ipzs.fedauthority.oidclib.schemas.WellKnownData;
import it.ipzs.fedauthority.oidclib.util.JSONUtil;
import it.ipzs.fedauthority.oidclib.util.ListUtil;
import it.ipzs.fedauthority.oidclib.util.Validator;


public class OidHandler {

	private static final Logger logger = LoggerFactory.getLogger(OidHandler.class);

	private final RelyingPartyOptions options;
	private final OIDCCredentialIssuerOptions credentialOptions;
	private final PersistenceAdapter persistence;
	private final JWTHelper jwtHelper;
	private final OAuth2Helper oauth2Helper;
	private final OidHelper oidHelper;
	private final FederationEntityOptions federationEntityOptions;

	public OidHandler(
			RelyingPartyOptions options, PersistenceAdapter persistence, OIDCCredentialIssuerOptions credentialOptions,
			FederationEntityOptions federationOptions)
			throws OIDCException {

		options.validate();

		if (persistence == null) {
			throw new OIDCException("persistence is mandatory");
		}

		this.options = options;
		this.credentialOptions = credentialOptions;
		this.persistence = persistence;
		this.jwtHelper = new JWTHelper(options);
		this.oauth2Helper = new OAuth2Helper(this.jwtHelper);
		this.oidHelper = new OidHelper(this.jwtHelper);
		this.federationEntityOptions = federationOptions;
	}

	/**
	 * Build the "authorize url": the URL a RelyingParty have to send to an OpenID Connect
	 * Provider to start a SPID/CIE authorization flow
	 *
	 * @param oidcProvider
	 * @param trustAnchor
	 * @param redirectUri
	 * @param scope
	 * @param profile {@code spid} or {@code cie}. If null or empty {@code spid} will be
	 * used
	 * @param prompt
	 * @return
	 * @throws OIDCException
	 */
	public String getAuthorizeURL(
			String oidcProvider, String trustAnchor, String redirectUri, String scope,
			String profile, String prompt)
			throws OIDCException {

		OIDCProfile oidcProfile = OIDCProfile.parse(profile);

		if (oidcProfile == null) {
			oidcProfile = OIDCProfile.SPID;
		}

		TrustChain tc = getOIDCProvider(oidcProvider, trustAnchor, oidcProfile);

		if (tc == null) {
			throw new OIDCException("TrustChain is unavailable");
		}

		JSONObject providerMetadata;

		try {
			providerMetadata = new JSONObject(tc.getMetadata());

			if (providerMetadata.isEmpty()) {
				throw new OIDCException("Provider metadata is empty");
			}
		}
		catch (Exception e) {
			throw e;
		}

		FederationEntity entityConf = getOrCreateFederationEntity(options.getClientId());

		if (entityConf == null || !entityConf.isActive()) {
			throw new OIDCException("Missing WellKnown configuration");
		}

		JSONObject entityMetadata;

		JWKSet entityJWKSet;

		try {
			entityMetadata = entityConf.getMetadataValue(
					OidConstants.OPENID_RELYING_PARTY);

			if (entityMetadata.isEmpty()) {
				throw new OIDCException("Entity metadata is empty");
			}

			entityJWKSet = JWTHelper.getJWKSetFromJSON(entityConf.getJwks());

			if (entityJWKSet.getKeys().isEmpty()) {
				throw new OIDCException("Entity with invalid or empty jwks");
			}
		}
		catch (OIDCException e) {
			throw e;
		}

		JWKSet providerJWKSet = JWTHelper.getMetadataJWKSet(providerMetadata);

		String authzEndpoint = providerMetadata.getString("authorization_endpoint");

		JSONArray entityRedirectUris = entityMetadata.getJSONArray("redirect_uris");

		if (entityRedirectUris.isEmpty()) {
			throw new OIDCException("Entity has no redirect_uris");
		}

		if (!Validator.isNullOrEmpty(redirectUri)) {
			if (!JSONUtil.contains(entityRedirectUris, redirectUri)) {
				logger.warn(
						"Requested for unknown redirect uri '{}'. Reverted to default '{}'",
						redirectUri, entityRedirectUris.getString(0));

				redirectUri = entityRedirectUris.getString(0);
			}
		}
		else {
			redirectUri = entityRedirectUris.getString(0);
		}

		if (Validator.isNullOrEmpty(scope)) {
			scope = Scope.OPEN_ID.value();
		}

		if (Validator.isNullOrEmpty(prompt)) {
			prompt = "consent login";
		}

		String responseType = entityMetadata.getJSONArray("response_types").getString(0);
		String nonce = UUID.randomUUID().toString();
		String state = UUID.randomUUID().toString();
		String clientId = entityMetadata.getString("client_id");
		long issuedAt = LocalDateTime.now().toEpochSecond(ZoneOffset.UTC);
		String[] aud = new String[] { tc.getSubject(), authzEndpoint };
		JSONObject claims = getRequestedClaims(oidcProfile);
		JSONObject pkce = PKCEHelper.getPKCE();

		String acr = options.getAcrValue(OIDCProfile.SPID);

		JSONObject authzData = new JSONObject()
				.put("scope", scope)
				.put("redirect_uri", redirectUri)
				.put("response_type", responseType)
				.put("nonce", nonce)
				.put("state", state)
				.put("client_id", clientId)
				.put("endpoint", authzEndpoint)
				.put("acr_values", acr)
				.put("iat", issuedAt)
				.put("aud", JSONUtil.asJSONArray(aud))
				.put("claims", claims)
				.put("prompt", prompt)
				.put("code_verifier", pkce.getString("code_verifier"))
				.put("code_challenge", pkce.getString("code_challenge"))
				.put("code_challenge_method", pkce.getString("code_challenge_method"));

		AuthnRequest authzEntry = new AuthnRequest()
				.setClientId(clientId)
				.setState(state)
				.setEndpoint(authzEndpoint)
				.setProvider(tc.getSubject())
				.setProviderId(tc.getSubject())
				.setData(authzData.toString())
				.setProviderJwks(providerJWKSet.toString())
				.setProviderConfiguration(providerMetadata.toString());

		authzEntry = persistence.storeOIDCAuthnRequest(authzEntry);

		authzData.remove("code_verifier");
		authzData.put("iss", entityMetadata.getString("client_id"));
		authzData.put("sub", entityMetadata.getString("client_id"));

		String requestObj = jwtHelper.createJWS(authzData, entityJWKSet);

		authzData.put("request", requestObj);

		String url = buildURL(authzEndpoint, authzData);

		logger.info("Starting Authn request to {}", url);

		return url;
	}

	/**
	 * Return the information needed to render the SignIn button with the OIDC Providers
	 * configured into {@link RelyingPartyOptions}.<br/>
	 * The list is randomized on every call.
	 *
	 * @param profile
	 * @return
	 * @throws OIDCException
	 */
	public List<ProviderButtonInfo> getProviderButtonInfos(OIDCProfile profile)
			throws OIDCException {

		List<ProviderButtonInfo> result = new ArrayList<>();

		Map<String, String> providers = options.getProviders(profile);

		for (Map.Entry<String, String> entry : providers.entrySet()) {
			try {
				TrustChain tc = getOIDCProvider(
						entry.getKey(), entry.getValue(), profile);

				JSONObject metadata = tc.getMetadataAsJSON();

				String logoUrl = metadata.optString("logo_uri", "");
				String organizationName = metadata.optString("organization_name", "");

				result.add(
						new ProviderButtonInfo(tc.getSubject(), organizationName, logoUrl));
			}
			catch (Exception e) {
				logger.warn(
						"Failed trust chain for {} to {}: {}", entry.getKey(),
						entry.getValue(), e.getMessage());
			}
		}

		Collections.shuffle(result);

		return Collections.unmodifiableList(result);
	}

	public JSONObject getUserInfo(String state, String code)
			throws OIDCException {

		try {
			return doGetUserInfo(state, code);
		}
		catch (OIDCException e) {
			throw e;
		}
		catch (Exception e) {
			throw new RelyingPartyException.Generic(e);
		}
	}

	/**
	 * Return the "Well Known" information of the current Relying Party. The completeness
	 * of these informations depends of the federation on-boarding status of the entity.
	 * <br/>
	 * Use this method only for the OnBoarding phase. For other scenarious use
	 * {@link #getWellKnownData(String, boolean)}
	 *
	 * @param jsonMode
	 * @return
	 * @throws OIDCException
	 */
	public WellKnownData getWellKnownData(boolean jsonMode) throws OIDCException {
		String sub = options.getClientId();

		FederationEntity conf = persistence.fetchFederationEntity(sub, true);

		if (conf == null) {
			return prepareOnboardingData(sub, jsonMode);
		}
		else {
			return getWellKnownData(conf, jsonMode);
		}
	}

	/**
	 * Return the "Well Known" information of the current Relying Party. The completeness
	 * of these informations depends of the federation on-boarding status of the entity.
	 *
	 * @param requestURL the requested url with the ".well-known" suffix
	 * @param jsonMode
	 * @return
	 * @throws OIDCException
	 */
	public WellKnownData getWellKnownData(String requestURL, boolean jsonMode)
			throws OIDCException {

		String sub = getSubjectFromWellKnownURL(requestURL);

		if (!checkSubAndClientIdMatch(sub, options.getClientId())) {
			throw new OIDCException(
					String.format(
							"Sub doesn't match %s : %s", sub, options.getClientId()));
		}

		FederationEntity conf = persistence.fetchFederationEntity(sub, true);

		if (conf == null) {
			return prepareOnboardingData(sub, jsonMode);
		}
		else {
			return getWellKnownData(conf, jsonMode);
		}
	}

	private boolean checkSubAndClientIdMatch(String sub, String clientId) {
		String subNoHttp = sub.substring(sub.indexOf(":"));
		String clientIdNoHttp = clientId.substring(clientId.indexOf(":"));
		return Objects.equals(clientIdNoHttp, subNoHttp);
	}

	// TODO: userKey is not enough. We need a more unique element
	public String performLogout(String userKey, RelyingPartyLogoutCallback callback)
			throws OIDCException {

		try {
			return doPerformLogout(userKey, callback);
		}
		catch (OIDCException e) {
			throw e;
		}
		catch (Exception e) {
			throw new OIDCException(e);
		}
	}

	public String retrieveJWK() {
		return options.getJwk();
	}

	public String retrieveRelyingPartyJWK() {
		return options.getJwk();
	}

	public OIDCCredentialIssuerOptions getCredentialOptions() {
		return credentialOptions;
	}

	public RelyingPartyOptions getRelyingPartyOptions() {
		return options;
	}

	protected JSONObject doGetUserInfo(String state, String code)
			throws OIDCException {

		if (Validator.isNullOrEmpty(code) || Validator.isNullOrEmpty(state)) {
			throw new SchemaException.Validation(
					"Authn response object validation failed");
		}

		List<AuthnRequest> authnRequests = persistence.findAuthnRequests(state);

		if (authnRequests.isEmpty()) {
			throw new RelyingPartyException.Generic("No AuthnRequest");
		}

		AuthnRequest authnRequest = ListUtil.getLast(authnRequests);

		AuthnToken authnToken = new AuthnToken()
				.setAuthnRequestId(authnRequest.getStorageId())
				.setCode(code);

		authnToken = persistence.storeOIDCAuthnToken(authnToken);

		// Get clientId configuration. In this situation "clientId" refers this
		// RelyingParty

		FederationEntity entityConf = persistence.fetchFederationEntity(
				authnRequest.getClientId(), true);

		if (entityConf == null) {
			throw new RelyingPartyException.Generic(
					"RelyingParty %s not found", authnRequest.getClientId());
		}
		else if (!Objects.equals(options.getClientId(), authnRequest.getClientId())) {
			throw new RelyingPartyException.Generic(
					"Invalid RelyingParty %s", authnRequest.getClientId());
		}

		JSONObject authnData = new JSONObject(authnRequest.getData());

		JSONObject providerConfiguration = new JSONObject(
				authnRequest.getProviderConfiguration());

		JSONObject jsonTokenResponse = oauth2Helper.performAccessTokenRequest(
				authnData.optString("redirect_uri"), state, code,
				authnRequest.getProviderId(), entityConf,
				providerConfiguration.optString("token_endpoint"),
				authnData.optString("code_verifier"));

		TokenResponse tokenResponse = TokenResponse.of(jsonTokenResponse);

		if (logger.isDebugEnabled()) {
			logger.debug("TokenResponse={}", tokenResponse);
		}

		JWKSet providerJwks = JWTHelper.getJWKSetFromJSON(
				providerConfiguration.optJSONObject("jwks"));

		try {
			jwtHelper.verifyJWS(tokenResponse.getAccessToken(), providerJwks);
		}
		catch (Exception e) {
			throw new RelyingPartyException.Authentication(
					"Authentication token validation error.");
		}

		try {
			jwtHelper.verifyJWS(tokenResponse.getIdToken(), providerJwks);
		}
		catch (Exception e) {
			throw new RelyingPartyException.Authentication("ID token validation error.");
		}

		// Update AuthenticationToken

		authnToken.setAccessToken(tokenResponse.getAccessToken());
		authnToken.setIdToken(tokenResponse.getIdToken());
		authnToken.setTokenType(tokenResponse.getTokenType());
		authnToken.setScope(jsonTokenResponse.optString("scope"));
		authnToken.setExpiresIn(tokenResponse.getExpiresIn());

		authnToken = persistence.storeOIDCAuthnToken(authnToken);

		JWKSet entityJwks = JWTHelper.getJWKSetFromJSON(entityConf.getJwks());

		JSONObject userInfo = null;
//		//oidcHelper.getUserInfo(
//				state, tokenResponse.getAccessToken(), providerConfiguration, true,
//				entityJwks);

		authnToken.setUserKey(getUserKeyFromUserInfo(userInfo));

		authnToken = persistence.storeOIDCAuthnToken(authnToken);

		//userInfo.put("access_token", tokenResponse.getAccessToken());
		return userInfo;
	}

	protected String doPerformLogout(
			String userKey, RelyingPartyLogoutCallback callback)
			throws Exception {

		if (Validator.isNullOrEmpty(userKey)) {
			throw new RelyingPartyException.Generic("UserKey null or empty");
		}

		List<AuthnToken> authnTokens = persistence.findAuthnTokens(userKey);

		if (authnTokens.isEmpty()) {
			return options.getLogoutRedirectURL();
		}

		AuthnToken authnToken = ListUtil.getLast(authnTokens);

		AuthnRequest authnRequest = persistence.fetchAuthnRequest(
				authnToken.getAuthnRequestId());

		if (authnRequest == null) {
			throw new RelyingPartyException.Generic(
					"No AuthnRequest with id " + authnToken.getAuthnRequestId());
		}

		JSONObject providerConfiguration = new JSONObject(
				authnRequest.getProviderConfiguration());

		String revocationUrl = providerConfiguration.optString("revocation_endpoint");

		// Do local logout

		if (callback != null) {
			callback.logout(userKey, authnRequest, authnToken);
		}

		if (Validator.isNullOrEmpty(revocationUrl)) {
			logger.warn(
					"{} doesn't expose the token revocation endpoint.",
					authnRequest.getProviderId());

			return options.getLogoutRedirectURL();
		}

		FederationEntity entityConf = persistence.fetchFederationEntity(
				authnRequest.getClientId(), true);

		JWTHelper.getJWKSetFromJSON(entityConf.getJwks());

		authnToken.setRevoked(LocalDateTime.now());

		authnToken = persistence.storeOIDCAuthnToken(authnToken);

		try {
			oauth2Helper.sendRevocationRequest(
					authnToken.getAccessToken(), authnRequest.getClientId(), revocationUrl,
					entityConf);
		}
		catch (Exception e) {
			logger.error("Token revocation failed: {}", e.getMessage());
		}

		// Revoke older user's authnToken. Evaluate better

		authnTokens = persistence.findAuthnTokens(userKey);

		for (AuthnToken oldToken : authnTokens) {
			oldToken.setRevoked(authnToken.getRevoked());

			persistence.storeOIDCAuthnToken(oldToken);
		}

		return options.getLogoutRedirectURL();
	}

	protected TrustChain getOrCreateTrustChain(
			String subject, String trustAnchor, String metadataType, boolean force)
			throws OIDCException {

		CachedEntityInfo trustAnchorEntity = persistence.fetchEntityInfo(
				trustAnchor, trustAnchor);

		EntityConfiguration taConf;

		if (trustAnchorEntity == null || trustAnchorEntity.isExpired() || force) {
			String jwt = EntityHelper.getEntityConfiguration(trustAnchor);

			taConf = new EntityConfiguration(jwt, jwtHelper);

			if (trustAnchorEntity == null) {
				trustAnchorEntity = CachedEntityInfo.of(
						trustAnchor, trustAnchor, taConf.getExpiresOn(), taConf.getIssuedAt(),
						taConf.getPayload(), taConf.getJwt());

				trustAnchorEntity = persistence.storeEntityInfo(trustAnchorEntity);
			}
			else {
				trustAnchorEntity.setModifiedDate(LocalDateTime.now());
				trustAnchorEntity.setExpiresOn(taConf.getExpiresOn());
				trustAnchorEntity.setIssuedAt(taConf.getIssuedAt());
				trustAnchorEntity.setStatement(taConf.getPayload());
				trustAnchorEntity.setJwt(taConf.getJwt());

				trustAnchorEntity = persistence.storeEntityInfo(trustAnchorEntity);
			}
		}
		else {
			taConf = EntityConfiguration.of(trustAnchorEntity, jwtHelper);
		}

		TrustChain trustChain = persistence.fetchTrustChain(subject, trustAnchor);

		if (trustChain != null && !trustChain.isActive()) {
			return null;
		}
		else {
			TrustChainBuilder tcb =
					new TrustChainBuilder(subject, metadataType, jwtHelper)
							.setTrustAnchor(taConf)
							.start();

			if (!tcb.isValid()) {
				String msg = String.format(
						"Trust Chain for subject %s or trust_anchor %s is not valid",
						subject, trustAnchor);

				throw new TrustChainException.InvalidTrustChain(msg);
			}
			else if (Validator.isNullOrEmpty(tcb.getFinalMetadata())) {
				String msg = String.format(
						"Trust chain for subject %s and trust_anchor %s doesn't have any " +
								"metadata of type '%s'", subject, trustAnchor, metadataType);

				throw new TrustChainException.MissingMetadata(msg);
			}
			else {
				logger.info("KK TCB is valid");
			}

			trustChain = persistence.fetchTrustChain(subject, trustAnchor, metadataType);

			if (trustChain == null) {
				trustChain = new TrustChain()
						.setSubject(subject)
						.setType(metadataType)
						.setExpiresOn(tcb.getExpiresOn())
						.setChain(tcb.getChainAsString())
						.setPartiesInvolved(tcb.getPartiesInvolvedAsString())
						.setProcessingStart(LocalDateTime.now())
						.setActive(true)
						.setMetadata(tcb.getFinalMetadata())
						.setTrustAnchor(trustAnchor)
						.setTrustMarks(tcb.getVerifiedTrustMarksAsString())
						.setStatus("valid");
			}
			else {
				trustChain = trustChain
						.setExpiresOn(tcb.getExpiresOn())
						.setChain(tcb.getChainAsString())
						.setPartiesInvolved(tcb.getPartiesInvolvedAsString())
						.setProcessingStart(LocalDateTime.now())
						.setActive(true)
						.setMetadata(tcb.getFinalMetadata())
						.setTrustAnchor(trustAnchor)
						.setTrustMarks(tcb.getVerifiedTrustMarksAsString())
						.setStatus("valid");
			}

			trustChain = persistence.storeTrustChain(trustChain);
		}

		return trustChain;
	}

	protected TrustChain getOIDCProvider(
			String oidcProvider, String trustAnchor, OIDCProfile profile)
			throws OIDCException {

		if (Validator.isNullOrEmpty(oidcProvider)) {
			if (logger.isWarnEnabled()) {
				logger.warn(TrustChainException.MissingProvider.DEFAULT_MESSAGE);
			}

			throw new TrustChainException.MissingProvider();
		}

		if (Validator.isNullOrEmpty(trustAnchor)) {
			trustAnchor = options.getProviders(profile).get(oidcProvider);

			if (Validator.isNullOrEmpty(trustAnchor)) {
				trustAnchor = options.getDefaultTrustAnchor();
			}
		}

		if (!options.getTrustAnchors().contains(trustAnchor)) {
			logger.warn(TrustChainException.InvalidTrustAnchor.DEFAULT_MESSAGE);

			throw new TrustChainException.InvalidTrustAnchor();
		}

		TrustChain trustChain = persistence.fetchTrustChain(oidcProvider, trustAnchor);

		boolean discover = false;

		if (trustChain == null) {
			logger.info("TrustChain not found for {}", oidcProvider);

			discover = true;
		}
		else if (!trustChain.isActive()) {
			String msg = TrustChainException.TrustChainDisabled.getDefaultMessage(
					trustChain.getModifiedDate());

			if (logger.isWarnEnabled()) {
				logger.warn(msg);
			}

			throw new TrustChainException.TrustChainDisabled(msg);
		}
		else if (trustChain.isExpired()) {
			logger.warn(
					String.format(
							"TrustChain found but EXPIRED at %s.",
							trustChain.getExpiresOn().toString()));
			logger.warn("Try to renew the trust chain");

			discover = true;
		}

		if (discover) {
			trustChain = getOrCreateTrustChain(
					oidcProvider, trustAnchor, OidConstants.OPENID_PROVIDER, true);
		}

		return trustChain;
	}

	// TODO: move to an helper?
	private String buildURL(String endpoint, JSONObject params) {
		StringBuilder sb = new StringBuilder();

		sb.append(endpoint);

		if (!params.isEmpty()) {
			boolean first = true;

			for (String key : params.keySet()) {
				if (first) {
					sb.append("?");
					first = false;
				}
				else {
					sb.append("&");
				}

				sb.append(key);
				sb.append("=");

				String value = params.get(key).toString();

				sb.append(URLEncoder.encode(value, StandardCharsets.UTF_8));
			}
		}

		return sb.toString();
	}

	private FederationEntity getOrCreateFederationEntity(String subject)
			throws OIDCException {

		FederationEntity entityConf = persistence.fetchFederationEntity(
				subject, OidConstants.OPENID_RELYING_PARTY, true);

		if (entityConf != null) {
			return entityConf;
		}

		WellKnownData wellKnown = prepareOnboardingData(options.getClientId(), true);

		if (!wellKnown.isComplete()) {
			return null;
		}

		return persistence.fetchFederationEntity(
				subject, OidConstants.OPENID_RELYING_PARTY, true);
	}

	private JSONObject getRequestedClaims(OIDCProfile profile) {
		return options.getRequestedClaimsAsJSON(profile);
	}

	private String getSubjectFromWellKnownURL(String url) {
		int x = url.indexOf(OidConstants.OIDC_FEDERATION_WELLKNOWN_URL);

		if (x > 1) {
			return url.substring(0, x - 1);
		}

		return "";
	}

	private String getUserKeyFromUserInfo(JSONObject userInfo) {
		String userKey = userInfo.optString(options.getUserKeyClaim(), null);

		if (userKey != null) {
			return userKey;
		}

		ClaimItem spidClaim = SPIDClaimItem.get(options.getUserKeyClaim());

		if (spidClaim != null) {
			userKey = userInfo.optString(spidClaim.getAlias(), null);

			if (userKey != null) {
				return userKey;
			}
		}
		else {
			spidClaim = SPIDClaimItem.getByAlias(options.getUserKeyClaim());

			if (spidClaim != null) {
				userKey = userInfo.optString(spidClaim.getName(), null);

				if (userKey != null) {
					return userKey;
				}
			}
		}

		ClaimItem cieClaim = CIEClaimItem.get(options.getUserKeyClaim());

		if (cieClaim != null) {
			userKey = userInfo.optString(cieClaim.getAlias(), null);

			if (userKey != null) {
				return userKey;
			}
		}
		else {
			cieClaim = CIEClaimItem.getByAlias(options.getUserKeyClaim());

			if (cieClaim != null) {
				userKey = userInfo.optString(cieClaim.getName());

				if (userKey != null) {
					return userKey;
				}
			}
		}

		return null;
	}

	private WellKnownData getWellKnownData(FederationEntity entity, boolean jsonMode)
			throws OIDCException {

		JWKSet jwkSet = JWTHelper.getJWKSetFromJSON(entity.getJwks());

		JSONObject metadataJson = new JSONObject(entity.getMetadata());

		long iat = LocalDateTime.now().toEpochSecond(ZoneOffset.UTC);

		JSONObject json = new JSONObject();

		json.put("exp", iat + (entity.getDefaultExpireMinutes() * 60));
		json.put("iat", iat);
		json.put("iss", entity.getSubject());
		json.put("sub", entity.getSubject());
		json.put("jwks", JWTHelper.getJWKSetAsJSONObject(jwkSet, true));
		json.put("metadata", metadataJson);
		json.put("authority_hints", new JSONArray(entity.getAuthorityHints()));
		json.put("trust_marks", new JSONArray(entity.getTrustMarks()));

		if (jsonMode) {
			return WellKnownData.of(WellKnownData.STEP_COMPLETE, json.toString());
		}

		String jws = jwtHelper.createJWS(json, jwkSet);

		return WellKnownData.of(WellKnownData.STEP_COMPLETE, jws);
	}

	private WellKnownData prepareOnboardingData(String sub, boolean jsonMode)
			throws OIDCException {

		// TODO: JWSAlgorithm via default?

		String confJwk = options.getJwk();

		String generalJwk = credentialOptions.getJwk();

		if (Validator.isNullOrEmpty(confJwk)) {

			RSAKey jwk = JWTHelper.createRSAKey(JWSAlgorithm.RS256, KeyUse.SIGNATURE);

			JSONObject json = new JSONObject(jwk.toString());

			return WellKnownData.of(WellKnownData.STEP_ONLY_JWKS, json.toString(2));
		}

		RSAKey jwk = JWTHelper.parseRSAKey(confJwk);
		RSAKey genKey = JWTHelper.parseRSAKey(generalJwk);


		logger.debug("Configured jwk\n {}", jwk);

		JSONArray jsonPublicJwk = new JSONArray()
				.put(new JSONObject(jwk.toPublicJWK().toJSONObject()));

		logger.debug("Configured public jwk\n {}", jsonPublicJwk.toString(2));

		JWKSet jwkSet = new JWKSet(List.of(jwk));

		JSONObject metadataJson = new JSONObject();

		metadataJson.put("federation_entity", federationEntityOptions.toJSON());

		long iat = LocalDateTime.now().toEpochSecond(ZoneOffset.UTC);

		JWKSet genJwkSet = new JWKSet(List.of(genKey));
		JSONObject json = new JSONObject();

		json.put("exp", iat + (GlobalOptions.getDefaultExpiringMinutes() * 3600 * 365));
		json.put("iat", iat);
		json.put("iss", options.getClientId());
		json.put("sub", options.getClientId());
		json.put("jwks", JWTHelper.getJWKSetAsJSONObject(genJwkSet, true));
		json.put("metadata", metadataJson);
		json.put(
				"authority_hints", JSONUtil.asJSONArray(options.getDefaultTrustAnchor()));

		int step = WellKnownData.STEP_INTERMEDIATE;

		if (!Validator.isNullOrEmpty(options.getTrustMarks())) {
			JSONArray tm = new JSONArray(options.getTrustMarks());

			json.put("trust_marks", tm);

			step = WellKnownData.STEP_COMPLETE;

			FederationEntity entity = new FederationEntity();

			entity.setSubject(json.getString("sub"));
			entity.setDefaultExpireMinutes(options.getDefaultExpiringMinutes());
			entity.setDefaultSignatureAlg(JWSAlgorithm.RS256.toString());
			entity.setAuthorityHints(json.getJSONArray("authority_hints").toString());
			entity.setJwks(
					JWTHelper.getJWKSetAsJSONArray(jwkSet, true, false).toString());
			entity.setTrustMarks(json.getJSONArray("trust_marks").toString());
			entity.setTrustMarksIssuers("{}");
			entity.setMetadata(json.getJSONObject("metadata").toString());
			entity.setActive(true);
			entity.setConstraints("{}");
			entity.setEntityType(OidConstants.OPENID_RELYING_PARTY);

			persistence.storeFederationEntity(entity);
		}

		if (jsonMode) {
			return WellKnownData.of(step, json.toString(), jsonPublicJwk.toString(2));
		}

		Map<String, Object> customHeader = new HashMap<>();
		customHeader.put("typ", "entity-statement+jwt");
		String jws = jwtHelper.createJWS(json, jwkSet, customHeader);

		return WellKnownData.of(step, jws, jsonPublicJwk.toString(2));
	}

	public FederationEntityOptions getFederationEntityOptions() {
		return federationEntityOptions;
	}

}