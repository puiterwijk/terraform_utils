#!/bin/python3
import requests
import os
import subprocess
import sys

email = None
token = None


zone_template = """# Domain: %(name)s
resource "cloudflare_zone" "%(name_safe)s" {
    zone = "%(name)s"
}
"""


zone_settings_template = """
resource "cloudflare_zone_settings_override" "%(name_safe)s" {
    name = "${cloudflare_zone.%(name_safe)s.zone}"
    settings {
        always_online            = "%(always_online)s"
        always_use_https         = "%(always_use_https)s"
        automatic_https_rewrites = "%(automatic_https_rewrites)s"
        brotli                   = "%(brotli)s"
        browser_check            = "%(browser_check)s"
        development_mode         = "%(development_mode)s"
        email_obfuscation        = "%(email_obfuscation)s"
        hotlink_protection       = "%(hotlink_protection)s"
        ip_geolocation           = "%(ip_geolocation)s"
        ipv6                     = "%(ipv6)s"
        opportunistic_encryption = "%(opportunistic_encryption)s"
        opportunistic_onion      = "%(opportunistic_onion)s"
        privacy_pass             = "%(privacy_pass)s"
        rocket_loader            = "%(rocket_loader)s"
        server_side_exclude      = "%(server_side_exclude)s"
        tls_1_2_only             = "%(tls_1_2_only)s"
        tls_client_auth          = "%(tls_client_auth)s"
        websockets               = "%(websockets)s"

        cache_level              = "%(cache_level)s"
        min_tls_version          = "%(min_tls_version)s"
        pseudo_ipv4              = "%(pseudo_ipv4)s"
        security_level           = "%(security_level)s"
        ssl                      = "%(ssl)s"
        tls_1_3                  = "%(tls_1_3)s"

        browser_cache_ttl = %(browser_cache_ttl)i
        challenge_ttl     = %(challenge_ttl)i
        edge_cache_ttl    = %(edge_cache_ttl)i
        max_upload        = %(max_upload)i

        minify {
            css  = "%(minify__css)s"
            js   = "%(minify__js)s"
            html = "%(minify__html)s"
        }

        mobile_redirect {
            mobile_subdomain = "%(mobile_redirect__mobile_subdomain)s"
            status           = "%(mobile_redirect__status)s"
            strip_uri        = %(mobile_redirect__strip_uri)s
        }

        security_header {
            enabled            = %(security_header__strict_transport_security__enabled)s
            preload            = %(security_header__strict_transport_security__preload)s
            max_age            = %(security_header__strict_transport_security__max_age)i
            include_subdomains = %(security_header__strict_transport_security__include_subdomains)s
            nosniff            = %(security_header__strict_transport_security__nosniff)s
        }
    }
}
"""

record_template_generic = """
resource "cloudflare_record" "%(record_name)s" {
    domain  = "${cloudflare_zone.%(zone_name_safe)s.zone}"
    name    = "%(name)s"
    type    = "%(type)s"
    ttl     = %(ttl)i
    value   = "%(content)s"
    proxied = %(proxied)s
}
"""

record_template_srv = """
resource "cloudflare_record" "%(record_name)s" {
    domain  = "${cloudflare_zone.%(zone_name_safe)s.zone}"
    name    = "%(name)s"
    type    = "%(type)s"
    ttl     = %(ttl)i
    data    = {
        service  = "%(data__service)s"
        proto    = "%(data__proto)s"
        name     = "%(data__name)s"
        weight   = %(data__weight)i
        port     = %(data__port)i
        target   = "%(data__target)s"
        priority = %(data__priority)i
    }
    proxied = %(proxied)s
}
"""

record_template_mx = """
resource "cloudflare_record" "%(record_name)s" {
    domain   = "${cloudflare_zone.%(zone_name_safe)s.zone}"
    name     = "%(name)s"
    type     = "%(type)s"
    ttl      = %(ttl)i
    value    = "%(content)s"
    priority = %(priority)i
}
"""

record_templates = {
    'SRV': record_template_srv,
    'MX': record_template_mx,
}


def perform_request(relative):
    resp = requests.get(
        "https://api.cloudflare.com/client/v4" + relative + "?per_page=500",
        headers={
            "Content-type": "application/json",
            "X-Auth-Email": email,
            "X-Auth-Key": token})
    resp.raise_for_status()
    resp = resp.json()
    if len(resp['errors']) != 0:
        raise Exception("Request to %s ended in errors: %s" % (relative, resp['errors']))
    if len(resp['messages']) != 0:
        print("Request to %s got messages: %s" % (relative, resp['message']))
    return resp['result']


def norm_val(val):
    if isinstance(val, bool):
        return str(val).lower()
    if val is None:
        return ""
    return val


def flatten_dict(val):
    res = {}
    for key in val:
        res[key] = norm_val(val[key])
        if isinstance(val[key], dict):
            # Flatten one level
            for l1_key in val[key]:
                res[key + "__" + l1_key] = norm_val(val[key][l1_key])
                if isinstance(val[key][l1_key], dict):
                    # Flatten one more level
                    for l2_key in val[key][l1_key]:
                        res[key + "__" + l1_key + "__" + l2_key] = norm_val(val[key][l1_key][l2_key])
    return res


def settings_to_dict(lst):
    res = {}
    for setting in lst:
        if not setting['editable']:
            continue
        res[setting['id']] = setting['value']
    res = flatten_dict(res)
    return res


def process_zone(outfile, to_import, zone):
    print("Processing zone %s" % zone['name'])
    zone['name_safe'] = zone['name'].replace('.', '_')
    to_import["zones"][zone['name_safe']] = zone['id']

    settings = perform_request("/zones/%s/settings" % zone['id'])
    settings = settings_to_dict(settings)
    settings['name'] = zone['name']
    settings['name_safe'] = zone['name_safe']

    records = perform_request("/zones/%s/dns_records" % zone['id'])

    zonefile = "%s.tf" % zone['name_safe']

    if os.path.exists(zonefile):
        raise Exception("File for zone %s already exists" % zone['name'])

    outfile.write(zone_template % zone)
    outfile.write(zone_settings_template % settings)

    ctrs = {}
    for record in records:
        record = flatten_dict(record)
        ctr_idx = record['name'] + '_TYPE_' + record['type']
        if ctr_idx not in ctrs:
            ctrs[ctr_idx] = 0

        for key in record:
            record[key] = norm_val(record[key])

        record['zone_name_safe'] = zone['name_safe']
        record['name_safe'] = record['name'].replace('.', '_')[:-(len(zone['name'])+1)]
        record['ctr'] = ctrs[ctr_idx]
        record['record_name'] = '%s_%s_%s_%i' % (
            record['zone_name_safe'],
            record['name_safe'],
            record['type'],
            record['ctr'])

        to_import['records'][record['record_name']] = '%s/%s' % (zone['name'], record['id'])

        ctrs[ctr_idx] += 1
        template = record_templates.get(record['type'])
        if template is None:
            template = record_template_generic
        outfile.write(template % record)


def run_import(args):
    subprocess.run(["terraform", "import"] + args, check=True)


def main():
    global email, token
    if len(sys.argv) != 3:
        raise SystemExit("Please call as <script> $cloudflare_email $api_token")
    _, email, token = sys.argv

    if os.path.exists("domains.tf"):
        raise SystemExit("domains.tf existed")

    to_import = {"zones": {}, "records": {}}

    zones = perform_request("/zones")

    with open("domains.tf", "w") as outfile:
        for zone in zones:
            process_zone(outfile, to_import, zone)

    print("Importing zones...")
    for zone in to_import["zones"]:
        zone_id = to_import["zones"][zone]
        print("Importing zone %s (%s)" % (zone, zone_id))
        run_import(["cloudflare_zone.%s" % zone, zone_id])

    print("Importing records...")
    for record in to_import["records"]:
        record_id = to_import["records"][record]
        print("Importing record %s (%s)" % (record, record_id))
        run_import(["cloudflare_record.%s" % record, record_id])


if __name__ == '__main__':
    main()
