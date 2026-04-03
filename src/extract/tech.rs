/// Lightweight technology detection from server header, content-type, and body patterns.
/// No wappalyzer database bloat — just fast pattern matching on common signatures.
pub fn detect_technologies(server: &str, content_type: &str, body: &str) -> Vec<String> {
    let mut techs = Vec::new();
    let server_lower = server.to_lowercase();
    let body_lower_prefix: String = body.chars().take(50_000).collect::<String>().to_lowercase();

    // Server header fingerprinting
    if server_lower.contains("nginx") {
        techs.push("nginx".into());
    }
    if server_lower.contains("apache") {
        techs.push("Apache".into());
    }
    if server_lower.contains("cloudflare") {
        techs.push("Cloudflare".into());
    }
    if server_lower.contains("iis") || server_lower.contains("microsoft") {
        techs.push("IIS".into());
    }
    if server_lower.contains("litespeed") {
        techs.push("LiteSpeed".into());
    }
    if server_lower.contains("caddy") {
        techs.push("Caddy".into());
    }
    if server_lower.contains("envoy") {
        techs.push("Envoy".into());
    }
    if server_lower.contains("openresty") {
        techs.push("OpenResty".into());
    }
    if server_lower.contains("gunicorn") {
        techs.push("Gunicorn".into());
    }
    if server_lower.contains("uvicorn") {
        techs.push("Uvicorn".into());
    }
    if server_lower.contains("express") {
        techs.push("Express".into());
    }

    // Body pattern fingerprinting
    if body_lower_prefix.contains("wp-content") || body_lower_prefix.contains("wordpress") {
        techs.push("WordPress".into());
    }
    if body_lower_prefix.contains("drupal") {
        techs.push("Drupal".into());
    }
    if body_lower_prefix.contains("joomla") {
        techs.push("Joomla".into());
    }
    if body_lower_prefix.contains("shopify") {
        techs.push("Shopify".into());
    }
    if body_lower_prefix.contains("next.js") || body_lower_prefix.contains("/_next/") {
        techs.push("Next.js".into());
    }
    if body_lower_prefix.contains("react") && body_lower_prefix.contains("__next") {
        techs.push("React".into());
    }
    if body_lower_prefix.contains("vue") && body_lower_prefix.contains("__vue") {
        techs.push("Vue.js".into());
    }
    if body_lower_prefix.contains("angular") {
        techs.push("Angular".into());
    }
    if body_lower_prefix.contains("laravel") {
        techs.push("Laravel".into());
    }
    if body_lower_prefix.contains("django") || body_lower_prefix.contains("csrfmiddlewaretoken") {
        techs.push("Django".into());
    }
    if body_lower_prefix.contains("rails") || body_lower_prefix.contains("csrf-token") {
        techs.push("Ruby on Rails".into());
    }
    if body_lower_prefix.contains("phpmyadmin") {
        techs.push("phpMyAdmin".into());
    }
    if body_lower_prefix.contains("grafana") {
        techs.push("Grafana".into());
    }
    if body_lower_prefix.contains("jenkins") {
        techs.push("Jenkins".into());
    }
    if body_lower_prefix.contains("gitlab") {
        techs.push("GitLab".into());
    }
    if body_lower_prefix.contains("confluence") {
        techs.push("Confluence".into());
    }
    if body_lower_prefix.contains("jira") {
        techs.push("Jira".into());
    }

    // Content-type hints
    if content_type.contains("application/json") {
        techs.push("JSON API".into());
    }
    if content_type.contains("application/xml") || content_type.contains("text/xml") {
        techs.push("XML API".into());
    }
    if content_type.contains("application/grpc") {
        techs.push("gRPC".into());
    }

    techs
}
