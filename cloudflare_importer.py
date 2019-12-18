#!/bin/python3
import requests
import os
import subprocess
import sys

email = None
token = None


zone_template = """# Domain: %(name)s
module "domain_%(name_safe)s" {
    source = "github.com/puiterwijk/terraform_utils//modules/domain"

    domain = "%(name)s"

    # Security settings"""


settings_template = '''
    %(setting)s = "%(value)s"'''

record_template_generic = """
resource "cloudflare_record" "%(record_name)s" {
    zone_id = module.domain_%(zone_name_safe)s.zone_id
    name    = "%(name)s"
    type    = "%(type)s"
    ttl     = %(ttl)i
    value   = "%(content)s"
    proxied = %(proxied)s
}
"""

record_template_srv = """
resource "cloudflare_record" "%(record_name)s" {
    zone_id = module.domain_%(zone_name_safe)s.zone_id
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
    zone_id = module.domain_%(zone_name_safe)s.zone_id
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

default_settings = {
    "min_tls_version": "1.0",
    "security_level": "medium",
    "ssl": "flexible",
    "tls_1_3": "on",
    "tls_client_auth": "off",
    "always_online": "on",
    "websockets": "on",
}

def process_zone(outfile, to_import, zone):
    print("Processing zone %s" % zone['name'])
    zone['name_safe'] = zone['name'].replace('.', '_')
    to_import["zones"][zone['name_safe']] = zone['id']

    settings = perform_request("/zones/%s/settings" % zone['id'])
    settings = settings_to_dict(settings)
    settings['name'] = zone['name']
    settings['name_safe'] = zone['name_safe']

    records = perform_request("/zones/%s/dns_records" % zone['id'])

    to_set = []
    for setting in default_settings:
        if settings[setting] != default_settings[setting]:
            #to_set[setting] = settings[setting]
            val = settings[setting]
            if setting == 'ssl':
                setting = 'ssl_type'
            to_set.append(settings_template % {"setting": setting, "value": val})
    to_set = ''.join(to_set)

    outfile.write((zone_template % zone) + to_set + """
}
""")

    ctrs = {}
    for record in records:
        record = flatten_dict(record)
        ctr_idx = record['name'] + '_TYPE_' + record['type']
        if ctr_idx not in ctrs:
            ctrs[ctr_idx] = 0

        for key in record:
            record[key] = norm_val(record[key])

        record['zone_name_safe'] = zone['name_safe']
        record['name_safe'] = record['name'].replace('.', '_').replace('*', 'WLD')[:-(len(zone['name'])+1)]
        record['ctr'] = ctrs[ctr_idx]
        record['record_name'] = '%s_%s_%s_%i' % (
            record['zone_name_safe'],
            record['name_safe'],
            record['type'],
            record['ctr'])

        to_import['records'][record['record_name']] = '%s/%s' % (zone['id'], record['id'])

        ctrs[ctr_idx] += 1
        template = record_templates.get(record['type'])
        if template is None:
            template = record_template_generic
        record['name'] = record['name'].replace('.' + zone['name'], '')
        outfile.write(template % record)


def run_import(args):
    subprocess.run(["/Users/patrickuiterwijk/Downloads/terraform", "import"] + args, check=True)


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
        run_import(
            ["module.domain_%s.cloudflare_zone.zone" % zone, zone_id])

    print("Importing records...")
    for record in to_import["records"]:
        record_id = to_import["records"][record]
        print("Importing record %s (%s)" % (record, record_id))
        run_import(["cloudflare_record.%s" % record, record_id])


if __name__ == '__main__':
    main()
