package it.ipzs.fedauthority.config;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

import it.ipzs.fedauthority.oidclib.OidcWrapper;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class KeyStoreConfig implements CommandLineRunner {

	@Value("${keys.directory-path}")
	private String keyDirectoryPath;

	@Value("${keys.path}")
	private String keyFilePath;

	@Value("${keys.public-jwk-set-path}")
	private String publicKeyFilePath;

	@Value("${keys.revoked-jwk-set-path}")
	private String revokedKeysFilePath;

	@Autowired
	private OidcWrapper oidcWrapper;

	@Override
	public void run(String... args) throws Exception {
		log.debug("Running KeyStore...");
		boolean reload = false;
		Path keyPath = Paths.get(keyDirectoryPath);
		if (!Files.exists(keyPath)) {
			Files.createDirectory(keyPath);
			reload = true;
		} else {
			log.debug("{} path exists", keyDirectoryPath);
		}

		if (!new File(keyFilePath).exists()) {
			KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
			gen.initialize(2048);
			KeyPair keyPair = gen.generateKeyPair();

			Calendar cal = Calendar.getInstance();
			cal.add(Calendar.YEAR, 1);
			Date validityEndDate = cal.getTime();

			JWK jwk = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
					.privateKey((RSAPrivateKey) keyPair.getPrivate()).keyUse(KeyUse.SIGNATURE)
					.keyID(UUID.randomUUID().toString()).issueTime(new Date()).expirationTime(validityEndDate)
					.keyIDFromThumbprint().build();

			try (FileWriter fw = new FileWriter(keyFilePath)) {

				fw.write(jwk.toJSONString());
			} catch (Exception e) {
				log.error("", e);
			}


			JSONArray jsonPublicJwk = new JSONArray().put(new JSONObject(jwk.toPublicJWK().toJSONObject()));

			JSONObject pubKeysJsonObj = new JSONObject().put("keys", jsonPublicJwk);


			try (FileWriter fw = new FileWriter(publicKeyFilePath)) {

				fw.write(pubKeysJsonObj.toString());
			} catch (Exception e) {
				log.error("", e);
			}
			reload = true;
		} else {
			log.debug("{} path exists", keyFilePath);
		}

		if (reload) {
			oidcWrapper.reloadKeys();
		}

	}

	public JWK loadKey() {

		if (new File(keyFilePath).exists()) {
			Path path = Paths.get(keyFilePath);

			try {
				String read = Files.readAllLines(path).get(0);
				return JWK.parse(read);
			} catch (IOException | ParseException e) {
				log.error("", e);
			}
		}

		throw new RuntimeException("cannot load key from file");

	}

	public JWKSet loadJWKS() {
		if (new File(publicKeyFilePath).exists()) {
			Path path = Paths.get(publicKeyFilePath);

			try {
				String read = Files.readAllLines(path).get(0);
				return JWKSet.parse(read);
			} catch (IOException | ParseException e) {
				log.error("", e);
			}
		}

		throw new RuntimeException("cannot load key from file");
	}

	public JWKSet loadRevokedJWKS() {
		if (new File(revokedKeysFilePath).exists()) {
			Path path = Paths.get(revokedKeysFilePath);

			try {
				String read = Files.readAllLines(path).get(0);
				return JWKSet.parse(read);
			} catch (IOException | ParseException e) {
				log.error("", e);
			}
		}

		throw new RuntimeException("cannot load key from file");
	}

	public List<JWK> loadRevokedKeys() {
		JWKSet tmp = loadRevokedJWKS();

		return tmp.getKeys();
	}

}
