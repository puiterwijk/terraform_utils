variable "domain" {
    type = string
}

resource "cloudflare_zone" "zone" {
    zone = var.domain
}

output "zone_id" {
    value = cloudflare_zone.zone.id
}

resource "cloudflare_zone_settings_override" "zone_settings" {
    zone_id = cloudflare_zone.zone.id
    settings {
        always_online            = var.always_online
        always_use_https         = var.always_use_https
        automatic_https_rewrites = var.automatic_https_rewrites
        brotli                   = "on"
        browser_check            = "on"
        development_mode         = "off"
        email_obfuscation        = "on"
        hotlink_protection       = "off"
        ip_geolocation           = "on"
        ipv6                     = "on"
        opportunistic_encryption = "on"
        opportunistic_onion      = "on"
        privacy_pass             = "on"
        rocket_loader            = "off"
        server_side_exclude      = "on"
        tls_client_auth          = var.tls_client_auth
        websockets               = var.websockets

        cache_level              = "aggressive"
        min_tls_version          = var.min_tls_version
        pseudo_ipv4              = "off"
        security_level           = var.security_level
        ssl                      = var.ssl_type
        tls_1_3                  = var.tls_1_3

        browser_cache_ttl = 14400
        challenge_ttl     = 1800
        edge_cache_ttl    = 7200
        max_upload        = 100

        minify {
            css  = "off"
            js   = "off"
            html = "off"
        }

        security_header {
            enabled            = true
            preload            = true
            max_age            = 15552000
            include_subdomains = true
            nosniff            = true
        }
    }
}
