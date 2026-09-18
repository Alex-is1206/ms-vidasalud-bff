package cl.duoc.vidasalud.bff.controller;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestClient;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/catalog")
public class CatalogController {

    private final RestClient client;

    public CatalogController(@Qualifier("catalogClient") RestClient client) {
        this.client = client;
    }

    @GetMapping("/prestaciones")
    @PreAuthorize("hasAuthority('SCOPE_Catalog.Read')")
    public List<Map<String, Object>> listar() {
        return client.get()
                .uri("/prestaciones")
                .retrieve()
                .body(List.class);
    }

    /** Exige rol Y scope: defensa en profundidad. */
    @PostMapping("/prestaciones")
    @PreAuthorize("hasRole('Admin') and hasAuthority('SCOPE_Catalog.Write')")
    public Map<String, Object> crear(@RequestBody Map<String, Object> prestacion) {
        return client.post()
                .uri("/prestaciones")
                .body(prestacion)
                .retrieve()
                .body(Map.class);
    }
}