package it.ipzs.fedauthority.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.mongodb.repository.MongoRepository;

import it.ipzs.fedauthority.model.OnboardEntity;

public interface OnboardEntityRepository extends MongoRepository<OnboardEntity, String> {

	public List<OnboardEntity> findByActiveTrue();

	public Optional<OnboardEntity> findByUrl(String sub);


}