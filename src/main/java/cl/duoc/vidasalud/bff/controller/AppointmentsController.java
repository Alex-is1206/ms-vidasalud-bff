package cl.duoc.vidasalud.bff.controller;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/appointments")
public class AppointmentsController {

    private final RestClient client;

    public AppointmentsController(@Qualifier("appointmentsClient") RestClient client) {
        this.client = client;
    }

    /** Admin, Recepcionista y Auditor ven todo. El Paciente solo lo suyo. */
    @GetMapping
    @PreAuthorize("hasAuthority('SCOPE_Appointments.Read')")
    public List<Map<String, Object>> listar(@AuthenticationPrincipal Jwt jwt) {
        List<String> roles = jwt.getClaimAsStringList("roles");

        boolean soloPaciente = roles != null
                && roles.contains("Paciente")
                && !roles.contains("Admin")
                && !roles.contains("Recepcionista")
                && !roles.contains("Auditor");

        String uri = soloPaciente
                ? "/atenciones?paciente=" + jwt.getClaimAsString("preferred_username")
                : "/atenciones";

        return client.get().uri(uri).retrieve().body(List.class);
    }

    @PostMapping
    @PreAuthorize("hasAnyRole('Paciente', 'Recepcionista', 'Admin')")
    public Map<String, Object> crear(@AuthenticationPrincipal Jwt jwt,
                                     @RequestBody Map<String, Object> atencion) {
        // El email sale del token, no del body: nadie agenda a nombre de otro
        atencion.put("pacienteEmail", jwt.getClaimAsString("preferred_username"));

        return client.post()
                .uri("/atenciones")
                .body(atencion)
                .retrieve()
                .body(Map.class);
    }

    @PatchMapping("/{id}/estado")
    @PreAuthorize("hasAnyRole('Recepcionista', 'Admin')")
    public Map<String, Object> cambiarEstado(@PathVariable Long id,
                                             @RequestBody Map<String, String> body) {
        return client.patch()
                .uri("/atenciones/{id}/estado", id)
                .body(body)
                .retrieve()
                .body(Map.class);
    }
}