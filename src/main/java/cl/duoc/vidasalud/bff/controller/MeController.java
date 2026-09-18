package cl.duoc.vidasalud.bff.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class MeController {

    /** Devuelve la identidad y los permisos que el BFF leyo del token. */
    @GetMapping("/me")
    public Map<String, Object> me(@AuthenticationPrincipal Jwt jwt) {
        List<String> roles = jwt.getClaimAsStringList("roles");
        String scp = jwt.getClaimAsString("scp");

        return Map.of(
                "name", jwt.getClaimAsString("name"),
                "username", jwt.getClaimAsString("preferred_username"),
                "subject", jwt.getSubject(),
                "issuer", jwt.getIssuer().toString(),
                "audience", jwt.getAudience(),
                "roles", roles != null ? roles : List.of(),
                "scopes", scp != null ? List.of(scp.split(" ")) : List.of(),
                "expiresAt", jwt.getExpiresAt().toString());
    }
}