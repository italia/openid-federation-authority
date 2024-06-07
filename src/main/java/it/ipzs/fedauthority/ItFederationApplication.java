package it.ipzs.fedauthority;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.ApplicationPidFileWriter;

@SpringBootApplication
public class ItFederationApplication {

	public static void main(String[] args) {
		SpringApplication springApplication = new SpringApplication(ItFederationApplication.class);
        springApplication.addListeners(new ApplicationPidFileWriter());
        springApplication.run(args);
	}

}
