package it.ipzs.fedauthority.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

import io.netty.handler.ssl.SslContext;

@Configuration
public class WebclientConfig {

   @Autowired(required = false)
   SslContext sslContext;

   @Bean
//   @Profile("!ssl")
   WebClient createWebClient() {
      return WebClient.builder().build();
   }

//   @Bean
////   @Profile("ssl")
//   WebClient createSslWebClient() {
//      final HttpClient httpClient = HttpClient.create().secure(t -> t.sslContext(sslContext));
//      return WebClient.builder().clientConnector(new ReactorClientHttpConnector(httpClient)).build();
//   }
}
