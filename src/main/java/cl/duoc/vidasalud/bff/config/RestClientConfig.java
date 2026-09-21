package cl.duoc.vidasalud.bff.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestClient;

@Configuration
public class RestClientConfig {

    @Bean("appointmentsClient")
    RestClient appointmentsClient(@Value("${services.appointments.url}") String baseUrl) {
        return RestClient.builder().baseUrl(baseUrl).build();
    }

    @Bean("catalogClient")
    RestClient catalogClient(@Value("${services.catalog.url}") String baseUrl) {
        return RestClient.builder().baseUrl(baseUrl).build();
    }
}