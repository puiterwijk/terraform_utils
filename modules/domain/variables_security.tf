variable "min_tls_version" {
    type = string
    default = "1.0"
}

variable "security_level" {
    type = string
    default = "medium"
}

variable "ssl_type" {
    type = string
    default = "flexible"
}

variable "tls_1_3" {
    type = string
    default = "on"
}

variable "tls_client_auth" {
    type = string
    default = "off"
}

variable "always_online" {
    type = string
    default = "on"
}

variable "always_use_https" {
    type = string
    default = "on"
}

variable "automatic_https_rewrites" {
    type = string
    default = "on"
}

variable "websockets" {
    type = string
    default = "on"
}
