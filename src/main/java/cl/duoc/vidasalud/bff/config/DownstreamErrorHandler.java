package cl.duoc.vidasalud.bff.config;

import java.time.Instant;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClientResponseException;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Traduce los errores de los microservicios en respuestas del BFF.
 *
 * Sin esto, un 404 o un 409 del microservicio llegaría al frontend
 * como un 500 genérico, y se perdería el motivo real del error.
 */
@RestControllerAdvice
public class DownstreamErrorHandler {

    /** El microservicio respondió con error: se reenvía el mismo código y cuerpo. */
    @ExceptionHandler(RestClientResponseException.class)
    public ResponseEntity<Object> reenviarError(RestClientResponseException ex,
                                                HttpServletRequest request) {
        String cuerpo = ex.getResponseBodyAsString();

        if (cuerpo == null || cuerpo.isBlank()) {
            return ResponseEntity.status(ex.getStatusCode()).body(Map.of(
                    "timestamp", Instant.now().toString(),
                    "status", ex.getStatusCode().value(),
                    "error", "downstream_error",
                    "message", "El microservicio respondió con un error",
                    "path", request.getRequestURI()));
        }

        return ResponseEntity.status(ex.getStatusCode())
                .contentType(MediaType.APPLICATION_JSON)
                .body(cuerpo);
    }

    /** El microservicio no respondió (caído o inalcanzable). */
    @ExceptionHandler(ResourceAccessException.class)
    public ResponseEntity<Map<String, Object>> servicioNoDisponible(HttpServletRequest request) {
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(Map.of(
                "timestamp", Instant.now().toString(),
                "status", HttpStatus.SERVICE_UNAVAILABLE.value(),
                "error", "service_unavailable",
                "message", "El microservicio no está disponible",
                "path", request.getRequestURI()));
    }
}
