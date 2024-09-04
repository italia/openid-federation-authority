package it.ipzs.fedauthority.model;

import java.util.Map;

import org.springframework.data.annotation.Id;

import com.fasterxml.jackson.annotation.JsonIgnore;

import lombok.Data;


@Data
public class OnboardEntity {

  @Id
  public String id;

  private String organizationName;
  private String url;
  private String urlCIEButton;
  private String email;
  private RoleEnum role;
  private Map<String, Object> jwk;
  private String trustMark;
  @JsonIgnore
  private Boolean active = Boolean.FALSE;
  

}