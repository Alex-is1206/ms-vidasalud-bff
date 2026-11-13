package cl.duoc.vidasalud.bff;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * Seguridad de las rutas de analitica: solo Admin y Auditor, con el scope Appointments.Read.
 * analytics apunta a un puerto cerrado: si la seguridad deja pasar, la respuesta es 503.
 */
@SpringBootTest(properties = {
        "services.appointments.url=http://localhost:1",
        "services.catalog.url=http://localhost:1",
        "services.analytics.url=http://localhost:1"
})
class AnaliticaBffTests {

    private static final String ISSUER =
            "https://login.microsoftonline.com/596d0d2f-cf4a-4fd1-8c07-98226aeaeaa5/v2.0";

    @Autowired
    private WebApplicationContext context;

    @MockitoBean
    private JwtDecoder jwtDecoder;

    private MockMvc mvc;

    @BeforeEach
    void configurar() {
        mvc = MockMvcBuilders.webAppContextSetup(context)
                .apply(springSecurity())
                .build();
    }

    private RequestPostProcessor token(List<String> roles, String... scopes) {
        List<GrantedAuthority> authorities = new ArrayList<>();
        roles.forEach(r -> authorities.add(new SimpleGrantedAuthority("ROLE_" + r)));
        for (String s : scopes) {
            authorities.add(new SimpleGrantedAuthority("SCOPE_" + s));
        }
        return jwt()
                .jwt(j -> j
                        .subject("usuario-de-prueba")
                        .issuer(ISSUER)
                        .audience(List.of("2b3609f5-dacf-4b1b-b9ec-fa0dfd1be88d"))
                        .expiresAt(Instant.now().plusSeconds(3600))
                        .claim("preferred_username", "prueba@vidasalud.cl")
                        .claim("roles", roles)
                        .claim("scp", String.join(" ", scopes)))
                .authorities(authorities);
    }

    @Test
    @DisplayName("Sin token: 401")
    void sinToken() throws Exception {
        mvc.perform(get("/api/analitica/resumen"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("Paciente no ve la analitica: 403 por rol")
    void pacienteNoPuede() throws Exception {
        mvc.perform(get("/api/analitica/resumen").with(token(List.of("Paciente"), "Appointments.Read")))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Recepcionista no ve la analitica: 403 por rol")
    void recepcionistaNoPuede() throws Exception {
        mvc.perform(get("/api/analitica/resumen").with(token(List.of("Recepcionista"), "Appointments.Read")))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Admin sin el scope Appointments.Read: 403 por scope")
    void adminSinScope() throws Exception {
        mvc.perform(get("/api/analitica/resumen").with(token(List.of("Admin"), "Catalog.Read")))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Auditor autorizado con analytics caido: 503 (la seguridad lo dejo pasar)")
    void auditorAutorizado() throws Exception {
        mvc.perform(get("/api/analitica/atenciones/41/historial").with(token(List.of("Auditor"), "Appointments.Read")))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.error").value("service_unavailable"));
    }

    @Test
    @DisplayName("Admin autorizado con analytics caido: 503 en resumen y boxes")
    void adminAutorizado() throws Exception {
        mvc.perform(get("/api/analitica/resumen").with(token(List.of("Admin"), "Appointments.Read")))
                .andExpect(status().isServiceUnavailable());
        mvc.perform(get("/api/analitica/boxes").with(token(List.of("Admin"), "Appointments.Read")))
                .andExpect(status().isServiceUnavailable());
    }
}
