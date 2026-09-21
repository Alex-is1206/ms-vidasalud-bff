package cl.duoc.vidasalud.bff.config;

import java.io.IOException;
import java.time.Instant;

import org.springframework.http.MediaType;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletResponse;

/**
 * Respuestas JSON para los rechazos de Spring Security.
 *
 * Estas respuestas se escriben en la cadena de filtros, antes de que
 * exista un controlador, por eso el JSON se arma directamente.
 */
@Component
public class SecurityErrorHandlers {

    /** 401: no hay token, está expirado, la firma no valida,
     *  el issuer no corresponde o la audiencia no es esta API. */
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return (request, response, authException) ->
                write(response, HttpServletResponse.SC_UNAUTHORIZED,
                      "unauthorized",
                      "Token ausente, expirado o no valido",
                      request.getRequestURI());
    }

    /** 403: el token es válido, pero el usuario no tiene
     *  el rol o el scope necesario para este endpoint. */
    public AccessDeniedHandler accessDeniedHandler() {
        return (request, response, accessDeniedException) ->
                write(response, HttpServletResponse.SC_FORBIDDEN,
                      "forbidden",
                      "No tiene permisos para acceder a este recurso",
                      request.getRequestURI());
    }

    private void write(HttpServletResponse response, int status,
                       String error, String message, String path) throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");

        String json = "{"
                + "\"timestamp\":\"" + Instant.now() + "\","
                + "\"status\":" + status + ","
                + "\"error\":\"" + escape(error) + "\","
                + "\"message\":\"" + escape(message) + "\","
                + "\"path\":\"" + escape(path) + "\""
                + "}";

        response.getWriter().write(json);
    }

    /** Escapa los caracteres que romperían un string JSON. */
    private static String escape(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder(value.length());
        for (char c : value.toCharArray()) {
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }
}
