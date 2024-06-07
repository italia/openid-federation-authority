package it.ipzs.fedauthority.service;

import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.stereotype.Service;

import com.nimbusds.jose.jwk.JWK;

import it.ipzs.fedauthority.config.KeyStoreConfig;
import it.ipzs.fedauthority.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class HistoricalJwksService {

	private final KeyStoreConfig keyConfig;

	private final JwtUtil jwtUtil;

	public String generateHistoricalJwksResponse() {
		log.debug("generate historical jwks response");
		JWK actualSignKey = keyConfig.loadKey();
		List<JWK> revokedKeys = keyConfig.loadRevokedKeys();
		JSONObject actualJwk = new JSONObject(actualSignKey.toPublicJWK().toJSONObject());
		JSONArray keysArray = new JSONArray();
		keysArray.put(actualJwk);
		// TODO revoked info for testing purpose
		for (JWK revKey : revokedKeys) {
			Map<String, Object> revokedMap = new HashMap<>();
			revokedMap.put("revoked_at", Calendar.getInstance().getTimeInMillis() / 1000);
			revokedMap.put("reason", "unspecified");
			JSONObject tmpKey = new JSONObject(revKey.toPublicJWK().toJSONObject());
			tmpKey.put("revoked", revokedMap);
			keysArray.put(tmpKey);
		}

		return jwtUtil.generateHistoricalJwksJwt(keysArray);
	}

}
