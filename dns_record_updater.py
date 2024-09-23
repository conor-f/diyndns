import configparser
import logging
import os
import requests
import shelve
import sys

import cloudflare


config = configparser.ConfigParser()
config.read(os.environ.get("CONFIG_FILEPATH", "config.ini"))
config = config["DEFAULT"]

cloudflare_api_email = config.get("CLOUDFLARE_API_EMAIL", None)
cloudflare_api_key = config.get("CLOUDFLARE_API_KEY", None)
domain_names = config.get("DOMAIN_NAMES", None).split(",")
log_filename = config.get("LOG_FILENAME", "/var/log/dns_record_updater.log")

logfile_handler = logging.FileHandler(filename=log_filename)
stdout_handler = logging.StreamHandler(stream=sys.stdout)
handlers = [logfile_handler, stdout_handler]

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] {%(filename)s:%(lineno)d} %(levelname)s - %(message)s",
    handlers=handlers,
)

logger = logging.getLogger()


shelf_name = "public_ip_shelf"


def get_public_ip_address():
    return str(requests.get("https://ipinfo.io/json").json()["ip"])


def read_stored_ip_address():
    with shelve.open(shelf_name) as shelf:
        return shelf.get("public_ip", None)


def write_new_ip_address(ip):
    with shelve.open(shelf_name) as shelf:
        shelf["public_ip"] = ip


def is_new_ip(ip):
    """
    Given an IP address, check if it's different from the one we have stored.
    Return True if they differ, False otherwise.
    """
    return ip != read_stored_ip_address()


def should_update_records(ip):
    """
    Return True if we should try update DNS records to this IP address, False
    otherwise.
    """
    return read_stored_ip_address() == None or is_new_ip(ip)


def update_records(ip):
    """
    Given a new IP address, update the basic DNS A records for that IP on
    Cloudflare. Raise on any issue.
    """
    cf = cloudflare.Cloudflare(
        api_email=cloudflare_api_email,
        api_key=cloudflare_api_key,
    )
    zone_ids = [zone.id for zone in cf.zones.list() if zone.name in domain_names]

    for zone_id in zone_ids:
        records = cf.dns.records.list(zone_id=zone_id)

        for domain_name in domain_names:
            records_to_update = [
                r
                for r in records
                if (r.name == f"*.{domain_name}" or r.name == domain_name)
                and r.type == "A"
            ]

            for r in records_to_update:
                cf.dns.records.edit(
                    zone_id=zone_id,
                    type="A",
                    dns_record_id=r.id,
                    name=r.name,
                    content=ip,
                )

    write_new_ip_address(ip)


def main():
    logger.info("Running dns_record_updater...")

    current_ip = get_public_ip_address()

    if should_update_records(current_ip):
        logger.info(
            f"Trying to update from {read_stored_ip_address()} to {current_ip}..."
        )
        try:
            update_records(current_ip)
            logger.info("Update Successful.")
        except Exception as e:
            logger.error("Updating Failed.")
            logger.exception(e)
    else:
        logger.info("No updates needed.")


if __name__ == "__main__":
    main()
