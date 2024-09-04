package it.ipzs.fedauthority.controller;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.google.gson.Gson;

import it.ipzs.fedauthority.service.HistoricalJwksService;
import it.ipzs.fedauthority.service.OnboardEntityService;
import it.ipzs.fedauthority.service.TrustMarkService;
import it.ipzs.fedauthority.util.StringUtil;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * cfr. https://openid.net/specs/openid-federation-1_0.html
 */

@RestController
@Slf4j
@RequiredArgsConstructor
public class FederationController {

	private final OnboardEntityService onboardService;

	private final HistoricalJwksService hjService;

	private final TrustMarkService tmService;

	private Gson gson = new Gson();

	@GetMapping(value = "/list", produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<List<String>> listSubordinates() {
		log.debug("requested list subordinates");
		List<String> subordinates = onboardService.listSubordinates();
		log.debug("result list subordinates: {}", subordinates);
		return ResponseEntity.ok(subordinates);
	}

	@GetMapping(value = "/fetch")
	public void fetch(@RequestParam(required = true) String iss, @RequestParam(required = false) String sub,
			HttpServletResponse response) {
		log.debug("requested fetch - iss {} - sub {}", iss, sub);
		try {
			String entityStatement = onboardService.fetchByIssAndSub(iss, sub);
			if (entityStatement != null) {
				PrintWriter writer = response.getWriter();
				writer.print(entityStatement);
				writer.flush();

				response.setContentType("application/entity-statement+jwt");
				response.setStatus(HttpServletResponse.SC_OK);
			} else {
				response.setContentType(MediaType.APPLICATION_JSON_VALUE);
				Map<String, String> responseBody = new HashMap<>();
				responseBody.put("error", "not_found");
				String bodyString = this.gson.toJson(responseBody);

				PrintWriter writer = response.getWriter();
				writer.print(bodyString);
				writer.flush();

				response.setStatus(HttpServletResponse.SC_NOT_FOUND);
			}
		} catch (RuntimeException e) {
			response.setContentType(MediaType.APPLICATION_JSON_VALUE);
			Map<String, String> responseBody = new HashMap<>();
			responseBody.put("error", "invalid_issuer");
			String bodyString = this.gson.toJson(responseBody);
			PrintWriter writer;
			try {
				writer = response.getWriter();
				writer.print(bodyString);
				writer.flush();
			} catch (IOException e1) {
				log.error("", e);
			}

			response.setStatus(HttpServletResponse.SC_NOT_FOUND);
		} catch (IOException e) {
			log.error("", e);
		}
	}

	@GetMapping("/historical-jwks")
	public void historicaJwks(HttpServletResponse response) {
		log.debug("requested historical jwks");
		String result = hjService.generateHistoricalJwksResponse();

		PrintWriter writer;
		try {
			writer = response.getWriter();

			writer.print(result);
			writer.flush();

		} catch (IOException e) {
			log.error("", e);
		}
		response.setContentType("application/jwk-set+jwt");
		response.setStatus(HttpServletResponse.SC_OK);
	}

	@PostMapping("/resolve")
	public void resolve(@RequestParam String sub, @RequestParam String type, @RequestParam String anchor,
			HttpServletResponse response) {
		String result = onboardService.resolveBySubTypeAndAnchor(sub, type, anchor);
		if (!StringUtil.isBlank(result)) {
			PrintWriter writer;
			try {
				writer = response.getWriter();
				writer.print(result);
				writer.flush();
			} catch (IOException e) {
				log.error("", e);
			}

			response.setContentType("application/resolve-response+jwt");
			response.setStatus(HttpServletResponse.SC_OK);
		} else {
			response.setContentType(MediaType.APPLICATION_JSON_VALUE);
			Map<String, String> responseBody = new HashMap<>();
			responseBody.put("error", "not_found");
			String bodyString = this.gson.toJson(responseBody);

			PrintWriter writer;
			try {
				writer = response.getWriter();
				writer.print(bodyString);
				writer.flush();

			} catch (IOException e) {
				log.error("", e);
			}

			response.setStatus(HttpServletResponse.SC_NOT_FOUND);
		}
	}

	@GetMapping(value = "/trust_mark")
	public void trustMark(@RequestParam String sub, @RequestParam("trust_mark_id") String trustMarkId,
			HttpServletResponse response) {

		String jwt = tmService.retrieveTrustMarkJwt(sub, trustMarkId);
		if (StringUtil.isBlank(jwt)) {
			response.setContentType("application/trust-mark+jwt");
			response.setStatus(HttpServletResponse.SC_NOT_FOUND);
		} else {
			PrintWriter writer;
			try {
				writer = response.getWriter();
				writer.print(jwt);
				writer.flush();

			} catch (IOException e) {
				log.error("", e);
			}
			response.setContentType("application/trust-mark+jwt");
			response.setStatus(HttpServletResponse.SC_OK);
		}

	}

	@PostMapping(value = "/status", produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<?> trustMarkStatus(@RequestParam String sub,
			@RequestParam("trust_mark_id") String trustMarkId) {
		Map<String, Boolean> response = new HashMap<>(1);
		response.put("active", tmService.checkStatus(sub, trustMarkId));

		return ResponseEntity.ok(response);
	}
}
