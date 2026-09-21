package cl.duoc.vidasalud.bff.controller;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

import cl.duoc.vidasalud.bff.security.TokenClaims;

/**
 * Atenciones. Cada endpoint exige un scope (qué puede hacer la aplicación)
 * y un rol (quién es el usuario), como pide el caso.
 */
@RestController
@RequestMapping("/api/appointments")
public class AppointmentsController {

    private static final String BASE = "/api/appointments";
    private static final ParameterizedTypeReference<Map<String, Object>> MAPA =
            new ParameterizedTypeReference<>() {
            };

    private final RestClient client;

    public AppointmentsController(@Qualifier("appointmentsClient") RestClient client) {
        this.client = client;
    }

    /** Admin, Recepcionista y Auditor ven todas. El Paciente solo las suyas. */
    @GetMapping
    @PreAuthorize("hasAuthority('SCOPE_Appointments.Read') "
            + "and hasAnyRole('Admin', 'Recepcionista', 'Auditor', 'Paciente')")
    public ResponseEntity<Object> listar(@AuthenticationPrincipal Jwt jwt,
                                         @RequestParam(required = false) String status,
                                         @RequestParam(required = false) String from,
                                         @RequestParam(required = false) String to) {
        String pacienteEmail = TokenClaims.esSoloPaciente(jwt) ? TokenClaims.email(jwt) : null;

        ResponseEntity<Object> respuesta = client.get()
                .uri(builder -> builder.path(BASE)
                        .queryParamIfPresent("status", Optional.ofNullable(status))
                        .queryParamIfPresent("from", Optional.ofNullable(from))
                        .queryParamIfPresent("to", Optional.ofNullable(to))
                        .queryParamIfPresent("pacienteEmail", Optional.ofNullable(pacienteEmail))
                        .build())
                .retrieve()
                .toEntity(Object.class);

        return reenviar(respuesta);
    }

    /** Un Paciente solo puede consultar una atención que sea suya. */
    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('SCOPE_Appointments.Read') "
            + "and hasAnyRole('Admin', 'Recepcionista', 'Auditor', 'Paciente')")
    public ResponseEntity<Object> buscarPorId(@AuthenticationPrincipal Jwt jwt,
                                              @PathVariable Long id) {
        ResponseEntity<Map<String, Object>> respuesta = client.get()
                .uri(BASE + "/{id}", id)
                .retrieve()
                .toEntity(MAPA);

        Map<String, Object> atencion = respuesta.getBody();

        if (TokenClaims.esSoloPaciente(jwt) && atencion != null) {
            String duenio = String.valueOf(atencion.get("pacienteEmail"));
            if (!duenio.equalsIgnoreCase(TokenClaims.email(jwt))) {
                throw new AccessDeniedException("La atención pertenece a otro paciente");
            }
        }

        return ResponseEntity.status(respuesta.getStatusCode()).body(atencion);
    }

    /**
     * El Paciente agenda para sí mismo: su email sale del token, no del body,
     * así nadie puede agendar a nombre de otro. El personal del centro
     * agenda para un paciente indicando su email en el body.
     */
    @PostMapping
    @PreAuthorize("hasAuthority('SCOPE_Appointments.Write') "
            + "and hasAnyRole('Admin', 'Recepcionista', 'Paciente')")
    public ResponseEntity<Object> crear(@AuthenticationPrincipal Jwt jwt,
                                        @RequestBody Map<String, Object> body) {
        Map<String, Object> atencion = new HashMap<>(body);

        if (TokenClaims.esSoloPaciente(jwt)) {
            atencion.put("pacienteEmail", TokenClaims.email(jwt));
        }

        ResponseEntity<Object> respuesta = client.post()
                .uri(BASE)
                .contentType(MediaType.APPLICATION_JSON)
                .body(atencion)
                .retrieve()
                .toEntity(Object.class);

        return reenviar(respuesta);
    }

    /** Solo el personal del centro mueve una atención por sus estados. */
    @PutMapping("/{id}/status")
    @PreAuthorize("hasAuthority('SCOPE_Appointments.Write') "
            + "and hasAnyRole('Admin', 'Recepcionista')")
    public ResponseEntity<Object> cambiarEstado(@PathVariable Long id,
                                                @RequestBody Map<String, Object> body) {
        ResponseEntity<Object> respuesta = client.put()
                .uri(BASE + "/{id}/status", id)
                .contentType(MediaType.APPLICATION_JSON)
                .body(body)
                .retrieve()
                .toEntity(Object.class);

        return reenviar(respuesta);
    }

    /**
     * Devuelve el código y el cuerpo del microservicio, sin copiar sus
     * cabeceras (Content-Length y similares no aplican a la nueva respuesta).
     */
    private ResponseEntity<Object> reenviar(ResponseEntity<Object> respuesta) {
        return ResponseEntity.status(respuesta.getStatusCode()).body(respuesta.getBody());
    }
}
