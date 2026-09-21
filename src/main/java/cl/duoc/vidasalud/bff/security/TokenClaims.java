package cl.duoc.vidasalud.bff.security;

import java.util.List;

import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Lectura de los claims de identidad que el BFF usa para autorizar.
 * Todo sale del token ya validado, nunca de lo que envía el cliente.
 */
public final class TokenClaims {

    private TokenClaims() {
    }

    public static List<String> roles(Jwt jwt) {
        List<String> roles = jwt.getClaimAsStringList("roles");
        return roles != null ? roles : List.of();
    }

    /** Paciente que no tiene además un rol de personal del centro. */
    public static boolean esSoloPaciente(Jwt jwt) {
        List<String> roles = roles(jwt);
        return roles.contains("Paciente")
                && !roles.contains("Admin")
                && !roles.contains("Recepcionista")
                && !roles.contains("Auditor");
    }

    /** Email del usuario autenticado, tal como lo emite Entra ID. */
    public static String email(Jwt jwt) {
        String username = jwt.getClaimAsString("preferred_username");
        return username != null ? username : jwt.getClaimAsString("email");
    }
}
