package cl.duoc.vidasalud.bff.controller;

import java.util.Map;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

/**
 * Boxes clínicos. Es información operativa: la consulta el personal
 * del centro, no los pacientes. Solo el Admin los administra.
 */
@RestController
@RequestMapping("/api/catalog/boxes")
public class BoxesController {

    private static final String BASE = "/api/catalog/boxes";

    private final RestClient client;

    public BoxesController(@Qualifier("catalogClient") RestClient client) {
        this.client = client;
    }

    @GetMapping
    @PreAuthorize("hasAuthority('SCOPE_Catalog.Read') "
            + "and hasAnyRole('Admin', 'Recepcionista', 'Auditor')")
    public ResponseEntity<Object> listar() {
        ResponseEntity<Object> respuesta = client.get()
                .uri(BASE)
                .retrieve()
                .toEntity(Object.class);

        return ResponseEntity.status(respuesta.getStatusCode()).body(respuesta.getBody());
    }

    @PostMapping
    @PreAuthorize("hasAuthority('SCOPE_Catalog.Write') and hasRole('Admin')")
    public ResponseEntity<Object> crear(@RequestBody Map<String, Object> body) {
        ResponseEntity<Object> respuesta = client.post()
                .uri(BASE)
                .contentType(MediaType.APPLICATION_JSON)
                .body(body)
                .retrieve()
                .toEntity(Object.class);

        return ResponseEntity.status(respuesta.getStatusCode()).body(respuesta.getBody());
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasAuthority('SCOPE_Catalog.Write') and hasRole('Admin')")
    public ResponseEntity<Object> actualizar(@PathVariable Long id,
                                             @RequestBody Map<String, Object> body) {
        ResponseEntity<Object> respuesta = client.put()
                .uri(BASE + "/{id}", id)
                .contentType(MediaType.APPLICATION_JSON)
                .body(body)
                .retrieve()
                .toEntity(Object.class);

        return ResponseEntity.status(respuesta.getStatusCode()).body(respuesta.getBody());
    }
}
