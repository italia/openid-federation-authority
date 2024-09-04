package it.ipzs.fedauthority.config;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.*;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import it.ipzs.fedauthority.oidclib.OidWrapper;
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

	@Value("${keys.config.type")
	private String keyTypeConfig;

	@Value("${keys.config.rsa.keySize:2048}")
	private Integer rsaKeySize;

	@Value("${keys.config.ec.curveType:P-256}")
	private String ecCurveType;

	@Autowired
	private OidWrapper oidcWrapper;

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
			JWK jwk = null;

			if("RSA".equals(keyTypeConfig)){
				jwk = generateRsaSigningKey();
			} else if("EC".equals(keyTypeConfig)) {
				jwk = generateEcSigningKey();
			} else {
				log.error("Algorithm not supported {}", keyTypeConfig);
				throw new NoSuchAlgorithmException("Algorithm not supported " + keyTypeConfig);
			}

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

	private JWK generateEcSigningKey() {
		KeyPairGenerator gen = null;
		try {
			gen = KeyPairGenerator.getInstance("EC");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
		Curve curve = null;
		try {
			curve = Curve.parse(ecCurveType);
		} catch (Exception e) {
			log.error("cannot parse EC curve type " + ecCurveType, e);
			throw new RuntimeException("Cannot parse EC curve type");
		}
        try {
            gen.initialize(curve.toECParameterSpec());
        } catch (InvalidAlgorithmParameterException e) {
            throw new RuntimeException(e);
        }
        KeyPair keyPair = gen.generateKeyPair();

		Calendar cal = Calendar.getInstance();
		cal.add(Calendar.YEAR, 1);
		Date validityEndDate = cal.getTime();

		try {
			JWK jwk = new ECKey.Builder(curve, (ECPublicKey) keyPair.getPublic())
					.privateKey((RSAPrivateKey) keyPair.getPrivate()).keyUse(KeyUse.SIGNATURE)
					.keyID(UUID.randomUUID().toString()).issueTime(new Date()).expirationTime(validityEndDate)
					.keyIDFromThumbprint().build();
			log.debug("key EC generated - {}", jwk.getKeyID());
			return jwk;
		} catch (JOSEException e) {
			throw new RuntimeException(e);
		}
	}

	private JWK generateRsaSigningKey() {
        KeyPairGenerator gen = null;
        try {
            gen = KeyPairGenerator.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        gen.initialize(rsaKeySize);
		KeyPair keyPair = gen.generateKeyPair();

		Calendar cal = Calendar.getInstance();
		cal.add(Calendar.YEAR, 1);
		Date validityEndDate = cal.getTime();

        try {
            JWK jwk = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                    .privateKey((RSAPrivateKey) keyPair.getPrivate()).keyUse(KeyUse.SIGNATURE)
                    .keyID(UUID.randomUUID().toString()).issueTime(new Date()).expirationTime(validityEndDate)
                    .keyIDFromThumbprint().build();
			log.debug("key RSA generated - {}", jwk.getKeyID());
			return jwk;
        } catch (JOSEException e) {
            throw new RuntimeException(e);
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
