package cl.duoc.vidasalud.bff.controller;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

/**
 * Analitica en tiempo real (ms-vidasalud-analytics, alimentado por Kafka).
 *
 * Son indicadores de gestion del centro: los ven el Admin y el Auditor, no el
 * personal de atencion ni los pacientes. Se usa el scope de lectura existente
 * Appointments.Read (los datos salen de las atenciones), asi no hubo que tocar
 * Entra ID. Solo lectura: los datos entran por Kafka, no por HTTP.
 */
@RestController
@RequestMapping("/api/analitica")
@PreAuthorize("hasAuthority('SCOPE_Appointments.Read') and hasAnyRole('Admin', 'Auditor')")
public class AnaliticaController {

    private static final String BASE = "/api/analitica";

    private final RestClient client;

    public AnaliticaController(@Qualifier("analyticsClient") RestClient client) {
        this.client = client;
    }

    /** Metricas en vivo: atenciones por estado, confirmaciones por minuto y hora, boxes activos. */
    @GetMapping("/resumen")
    public ResponseEntity<Object> resumen() {
        return reenviar(client.get().uri(BASE + "/resumen").retrieve().toEntity(Object.class));
    }

    /** Estado actual de cada box, reconstruido desde el topico compactado. */
    @GetMapping("/boxes")
    public ResponseEntity<Object> boxes() {
        return reenviar(client.get().uri(BASE + "/boxes").retrieve().toEntity(Object.class));
    }

    /** Linea de tiempo de una atencion (historial guardado en Oracle). */
    @GetMapping("/atenciones/{id}/historial")
    public ResponseEntity<Object> historial(@PathVariable Long id) {
        return reenviar(client.get()
                .uri(BASE + "/atenciones/{id}/historial", id)
                .retrieve()
                .toEntity(Object.class));
    }

    /** Devuelve el codigo y el cuerpo del microservicio, sin copiar sus cabeceras. */
    private ResponseEntity<Object> reenviar(ResponseEntity<Object> respuesta) {
        return ResponseEntity.status(respuesta.getStatusCode()).body(respuesta.getBody());
    }
}
