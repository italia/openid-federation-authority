package it.ipzs.fedauthority.service;

import java.util.Calendar;
import java.util.Optional;

import org.springframework.stereotype.Service;

import it.ipzs.fedauthority.dto.EntityConfigurationDto;
import it.ipzs.fedauthority.model.OnboardEntity;
import it.ipzs.fedauthority.repository.OnboardEntityRepository;
import it.ipzs.fedauthority.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class TrustMarkService {

	private final OnboardEntityRepository oeRepo;

	private final JwtUtil jwtUtil;

	public String retrieveTrustMarkJwt(String sub, String trustMarkId) {
		Optional<OnboardEntity> optional = oeRepo.findByUrl(sub);
		if (optional.isPresent()) {
			OnboardEntity oe = optional.get();
			EntityConfigurationDto ec = new EntityConfigurationDto();
			Calendar instance = Calendar.getInstance();
			ec.setIat(instance.getTimeInMillis() / 1000);
			instance.add(Calendar.MONTH, 1);
			ec.setExp(instance.getTimeInMillis() / 1000);
			ec.setSub(oe.getUrl());
			ec.setIss(oe.getId());
			String result = jwtUtil.generateTrustMarkResponse(ec);

			log.debug("trustMark result {}", result);

			return result;

		} else

			return null;
	}

	public Boolean checkStatus(String sub, String trustMarkId) {
		// TODO stub for testing purpose
		Optional<OnboardEntity> optional = oeRepo.findByUrl(sub);
		return optional.isPresent();
	}

}
