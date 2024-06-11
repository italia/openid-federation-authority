package it.ipzs.fedauthority.util;

import java.text.ParseException;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;

import org.json.JSONArray;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import it.ipzs.fedauthority.config.KeyStoreConfig;
import it.ipzs.fedauthority.dto.EntityConfigurationDto;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class JwtUtil {

	@Autowired
	private KeyStoreConfig keyConfig;

	@Value("${fed-config.hosts.federation-entity}")
	private String basePath;

	
	
	public JWTClaimsSet parse(String jwtString) throws ParseException, JOSEException {
		SignedJWT jwt = SignedJWT.parse(jwtString);

//		JWSHeader jwsHeader = jwt.getHeader();
//		JWK jwk = jwsHeader.getJWK();
		
//		JWSVerifier verifier;
//		 if (jwk instanceof ECKey) {
//				ECKey ecKey = (ECKey) jwk;
//	            verifier = new ECDSAVerifier(ecKey);
//			} else if (jwk instanceof RSAKey) {
//				RSAKey rsaKey = (RSAKey) jwk;
//	            verifier = new RSASSAVerifier(rsaKey.toRSAPublicKey());
//			} else {
//				throw new IllegalArgumentException("JWK key type not matched: " + jwk.getKeyType().getValue());
//	        }
		
//		jwt.verify(verifier);
		ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode = objectMapper.valueToTree(jwt.getJWTClaimsSet().getJSONObjectClaim("jwks").get("keys"));
		JWK jwk = JWK.parse(jsonNode.get(0).toPrettyString());
		log.info("parse {}", jwk);
		JWSVerifier verifier;
		if (jwk instanceof ECKey) {
			ECKey ecKey = (ECKey) jwk;
			verifier = new ECDSAVerifier(ecKey);
		} else if (jwk instanceof RSAKey) {
			RSAKey rsaKey = (RSAKey) jwk;
			verifier = new RSASSAVerifier(rsaKey.toRSAPublicKey());
		} else {
			throw new IllegalArgumentException("JWK key type not matched: " + jwk.getKeyType().getValue());
		}
		
		jwt.verify(verifier);
        return jwt.getJWTClaimsSet();

	}

	public String generateECJwt(EntityConfigurationDto ec) {
		String result = null;
		Map<String, Object> claimsMap = new HashMap<>();
		claimsMap.put("iss", ec.getIss());
		claimsMap.put("sub", ec.getSub());
		claimsMap.put("iat", ec.getIat());
		claimsMap.put("exp", ec.getExp());
		claimsMap.put("jwks", ec.getJwks().toMap());
		claimsMap.put("metadata", ec.getMetadataPolicy().toMap());
		JWSHeader header = null;
		JWSSigner signer = null;

		try {
			JWTClaimsSet claimsSet = JWTClaimsSet.parse(claimsMap);
			JWK jwk = extractKey();
			if (jwk != null && jwk instanceof ECKey ecKey) {
				header = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(jwk.getKeyID())
						.type(new JOSEObjectType("entity-statement+jwt")).build();
				signer = new ECDSASigner(jwk.toECKey());
			} else if (jwk != null && jwk instanceof ECKey RSAKey) {
				header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(jwk.getKeyID())
						.type(new JOSEObjectType("entity-statement+jwt")).build();
				signer = new RSASSASigner(jwk.toRSAKey());
			} else {
				header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(jwk.getKeyID())
						.type(new JOSEObjectType("entity-statement+jwt")).build();
				signer = new RSASSASigner(jwk.toRSAKey());
			}

			SignedJWT jwt = new SignedJWT(header, claimsSet);
			jwt.sign(signer);

			result = jwt.serialize();

		} catch (ParseException | JOSEException e) {
			log.error("", e);
		}

		return result;
	}

	private JWK extractKey() {
		return keyConfig.loadKey();

	}

	public String generateHistoricalJwksJwt(JSONArray keysArray) {

		String result = null;
		Map<String, Object> claimsMap = new HashMap<>();
		Calendar cal = Calendar.getInstance();
		claimsMap.put("iat", cal.getTimeInMillis() / 1000);
		claimsMap.put("keys", keysArray.toList());
		claimsMap.put("iss", StringUtil.concat("http://", basePath));
		JWSHeader header = null;
		JWSSigner signer = null;
		try {
			JWTClaimsSet claimsSet = JWTClaimsSet.parse(claimsMap);
			JWK jwk = extractKey();
			if (jwk != null && jwk instanceof ECKey ecKey) {
				header = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(jwk.getKeyID())
						.type(new JOSEObjectType("jwk-set+jwt")).build();
				signer = new ECDSASigner(jwk.toECKey());
			} else if (jwk != null && jwk instanceof ECKey RSAKey) {
				header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(jwk.getKeyID())
						.type(new JOSEObjectType("jwk-set+jwt")).build();
				signer = new RSASSASigner(jwk.toRSAKey());
			} else {
				header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(jwk.getKeyID())
						.type(new JOSEObjectType("jwk-set+jwt")).build();
				signer = new RSASSASigner(jwk.toRSAKey());
			}

			SignedJWT jwt = new SignedJWT(header, claimsSet);
			jwt.sign(signer);

			result = jwt.serialize();

		} catch (ParseException | JOSEException e) {
			log.error("", e);
		}

		return result;
	}

	public String generateResolveECJwt(EntityConfigurationDto ec) {

		String result = null;
		Map<String, Object> claimsMap = new HashMap<>();
		claimsMap.put("iss", ec.getIss());
		claimsMap.put("sub", ec.getSub());
		claimsMap.put("iat", ec.getIat());
		claimsMap.put("exp", ec.getExp());
		claimsMap.put("jwks", ec.getJwks().toMap());
		claimsMap.put("metadata", ec.getMetadataPolicy().toMap());
		JWSHeader header = null;
		JWSSigner signer = null;

		try {
			JWTClaimsSet claimsSet = JWTClaimsSet.parse(claimsMap);
			JWK jwk = extractKey();
			if (jwk != null && jwk instanceof ECKey ecKey) {
				header = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(jwk.getKeyID())
						.type(new JOSEObjectType("resolve-response+jwt")).build();
				signer = new ECDSASigner(jwk.toECKey());
			} else if (jwk != null && jwk instanceof ECKey RSAKey) {
				header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(jwk.getKeyID())
						.type(new JOSEObjectType("resolve-response+jwt")).build();
				signer = new RSASSASigner(jwk.toRSAKey());
			} else {
				header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(jwk.getKeyID())
						.type(new JOSEObjectType("resolve-response+jwt")).build();
				signer = new RSASSASigner(jwk.toRSAKey());
			}

			SignedJWT jwt = new SignedJWT(header, claimsSet);
			jwt.sign(signer);

			result = jwt.serialize();

		} catch (ParseException | JOSEException e) {
			log.error("", e);
		}

		return result;
	
	}

	public String generateTrustMarkResponse(EntityConfigurationDto ec) {
		String result = null;
		Map<String, Object> claimsMap = new HashMap<>();
		claimsMap.put("iss", StringUtil.concat("https://", basePath));
		claimsMap.put("sub", ec.getSub());
		claimsMap.put("iat", ec.getIat());
		claimsMap.put("exp", ec.getExp());
		claimsMap.put("id", StringUtil.concat(ec.getSub(), ec.getIss()));
		JWSHeader header = null;
		JWSSigner signer = null;

		try {
			JWTClaimsSet claimsSet = JWTClaimsSet.parse(claimsMap);
			JWK jwk = extractKey();
			if (jwk != null && jwk instanceof ECKey ecKey) {
				header = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(jwk.getKeyID()).build();
				signer = new ECDSASigner(jwk.toECKey());
			} else if (jwk != null && jwk instanceof ECKey RSAKey) {
				header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(jwk.getKeyID()).build();
				signer = new RSASSASigner(jwk.toRSAKey());
			} else {
				header = new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(jwk.getKeyID()).build();
				signer = new RSASSASigner(jwk.toRSAKey());
			}

			SignedJWT jwt = new SignedJWT(header, claimsSet);
			jwt.sign(signer);

			result = jwt.serialize();

		} catch (ParseException | JOSEException e) {
			log.error("", e);
		}

		return result;
	}
}
