package cl.duoc.vidasalud.bff;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * Pruebas de la seguridad del BFF.
 *
 * Los tokens se simulan con jwt() de spring-security-test, así que no
 * se necesita internet ni Entra ID. Los microservicios apuntan a un
 * puerto cerrado para comprobar también el 503.
 */
@SpringBootTest(properties = {
        "services.appointments.url=http://localhost:1",
        "services.catalog.url=http://localhost:1"
})
class SeguridadBffTests {

    private static final String ISSUER =
            "https://login.microsoftonline.com/596d0d2f-cf4a-4fd1-8c07-98226aeaeaa5/v2.0";

    @Autowired
    private WebApplicationContext context;

    /** Reemplaza al decodificador real: evita descargar llaves desde Entra ID. */
    @MockitoBean
    private JwtDecoder jwtDecoder;

    private MockMvc mvc;

    @BeforeEach
    void configurar() {
        mvc = MockMvcBuilders.webAppContextSetup(context)
                .apply(springSecurity())
                .build();
    }

    /** Token simulado con los roles y scopes indicados. */
    private RequestPostProcessor token(List<String> roles, String... scopes) {
        List<GrantedAuthority> authorities = new java.util.ArrayList<>();
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
                        .claim("name", "Usuario de Prueba")
                        .claim("preferred_username", "prueba@vidasalud.cl")
                        .claim("roles", roles)
                        .claim("scp", String.join(" ", scopes)))
                .authorities(authorities);
    }

    @Test
    @DisplayName("Sin token: 401 con JSON del BFF")
    void sinTokenResponde401() throws Exception {
        mvc.perform(get("/api/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("unauthorized"))
                .andExpect(jsonPath("$.status").value(401));
    }

    @Test
    @DisplayName("Token válido: /api/me devuelve los roles del token")
    void conTokenValidoResponde200() throws Exception {
        mvc.perform(get("/api/me").with(token(List.of("Admin"), "Appointments.Read")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("prueba@vidasalud.cl"))
                .andExpect(jsonPath("$.roles[0]").value("Admin"));
    }

    @Test
    @DisplayName("Paciente con todos los scopes no puede crear prestaciones: 403 por rol")
    void pacienteNoPuedeCrearPrestaciones() throws Exception {
        mvc.perform(post("/api/catalog/services")
                        .with(token(List.of("Paciente"), "Catalog.Read", "Catalog.Write"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"nombre\":\"X\",\"precio\":1,\"duracionMinutos\":10}"))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Admin sin el scope Catalog.Write no puede crear prestaciones: 403 por scope")
    void adminSinScopeNoPuedeCrearPrestaciones() throws Exception {
        mvc.perform(post("/api/catalog/services")
                        .with(token(List.of("Admin"), "Catalog.Read"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"nombre\":\"X\",\"precio\":1,\"duracionMinutos\":10}"))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Paciente no puede ver boxes: 403")
    void pacienteNoPuedeVerBoxes() throws Exception {
        mvc.perform(get("/api/catalog/boxes").with(token(List.of("Paciente"), "Catalog.Read")))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Paciente no puede cambiar el estado de una atención: 403")
    void pacienteNoPuedeCambiarEstado() throws Exception {
        mvc.perform(put("/api/appointments/1/status")
                        .with(token(List.of("Paciente"), "Appointments.Write"))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"status\":\"CONFIRMADA\"}"))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Usuario sin rol no puede listar atenciones: 403")
    void sinRolNoPuedeListarAtenciones() throws Exception {
        mvc.perform(get("/api/appointments").with(token(List.of(), "Appointments.Read")))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("Autorizado pero con el microservicio caído: 503")
    void microservicioCaidoResponde503() throws Exception {
        mvc.perform(get("/api/catalog/services").with(token(List.of("Admin"), "Catalog.Read")))
                .andExpect(status().isServiceUnavailable())
                .andExpect(jsonPath("$.error").value("service_unavailable"));
    }
}
