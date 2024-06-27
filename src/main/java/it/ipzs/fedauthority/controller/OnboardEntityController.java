package it.ipzs.fedauthority.controller;

import java.text.ParseException;

import it.ipzs.fedauthority.util.StringUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;

import it.ipzs.fedauthority.model.OnboardEntity;
import it.ipzs.fedauthority.oidclib.OidConstants;
import it.ipzs.fedauthority.service.OnboardEntityService;
import it.ipzs.fedauthority.util.JwtUtil;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/onboard")
@Slf4j
public class OnboardEntityController {

	@Autowired
	OnboardEntityService onboardEntityService;
	
	@Autowired
	JwtUtil jwtUtil;
	
	@Autowired
	private WebClient webclient;


	@PostMapping()
	public ResponseEntity<OnboardEntity> save(@RequestBody OnboardEntity onboardEntity) throws ParseException, JOSEException {
		if(StringUtil.isBlank(onboardEntity.getUrl())){
			log.error("missing url param in onboard request: {}", onboardEntity);
			return ResponseEntity.badRequest().build();
		}
		String wellknownURL = null;
		if(onboardEntity.getUrl().endsWith("/"))
			wellknownURL = onboardEntity.getUrl() + OidConstants.OIDC_FEDERATION_WELLKNOWN_URL;
		else {
			wellknownURL = onboardEntity.getUrl()+ "/" + OidConstants.OIDC_FEDERATION_WELLKNOWN_URL;
		}
		String wellknown = webclient.get()
	            .uri(wellknownURL)
	            .retrieve().bodyToMono(String.class).block();
		JWTClaimsSet parse = jwtUtil.parse(wellknown);
		log.info("claims {}", parse);
		return ResponseEntity.ok(onboardEntityService.save(onboardEntity));

	}

}
