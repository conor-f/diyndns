import configparser
import logging
import os
from typing import List
import requests
import shelve
import sys

import cloudflare

SHELF_NAME = "public_ip_shelf"


class Provider:
    def update_records(self, ip: str) -> None:
        raise NotImplementedError


class CloudflareProvider(Provider):
    def __init__(self, email_address, api_key, domains):
        self.email_address = email_address
        self.api_key = api_key
        self.domains = domains

    def __str__(self):
        return f"CloudflareProvider<{self.email_address}>"

    def update_records(self, ip: str):
        """
        Given a new IP address, update the basic DNS A records for that IP on
        Cloudflare. Raise on any issue.
        """
        cf = cloudflare.Cloudflare(
            api_email=self.email_address,
            api_key=self.api_key,
        )
        zone_ids = [zone.id for zone in cf.zones.list() if zone.name in self.domains]

        for zone_id in zone_ids:
            records = cf.dns.records.list(zone_id=zone_id)

            for domain_name in self.domains:
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


class PorkbunProvider(Provider):
    def __init__(self, api_key, secret_key, domains):
        self.api_key = api_key
        self.secret_key = secret_key
        self.domains = domains
        self.base_url = "https://api.porkbun.com/api/json/v3/dns"
        self.payload = {"apikey": self.api_key, "secretapikey": self.secret_key}
        self.headers = {"Content-Type": "application/json"}

    def __str__(self):
        return f"PorkbunProvider<{self.api_key}>"

    def _create_new_record(self, domain_name: str, name: str, ip: str):
        create_url = f"{self.base_url}/create/{domain_name}"

        # Create root domain record
        root_payload = {
            **self.payload,
            "name": name,
            "type": "A",
            "content": ip,
            "ttl": "600",
        }

        root_response = requests.post(
            create_url, json=root_payload, headers=self.headers
        )

        if root_response.json()["status"] != "SUCCESS":
            raise Exception(f"Failed to create record for '{domain_name}'")

    def _create_new_records(self, domain_name: str, ip: str):
        """
        Create new records for the given domain and IP.
        """
        # Root record is an empty string.
        self._create_new_record(domain_name, "", ip)
        self._create_new_record(domain_name, "*", ip)

    def update_records(self, ip: str):
        for domain_name in self.domains:
            # Retrieve current DNS records
            retrieve_url = f"{self.base_url}/retrieve/{domain_name}"
            response = requests.post(
                retrieve_url, json=self.payload, headers=self.headers
            )
            response_data = response.json()

            if response_data["status"] != "SUCCESS":
                raise Exception(f"Failed to retrieve records for {domain_name}")

            # Filter for A records
            a_records = [r for r in response_data["records"] if r["type"] == "A"]

            if a_records:
                # Delete existing records, then create them afresh, as Porkbun
                # doesn't co-operate well with editing a root record through
                # the API -_-
                for record in a_records:
                    delete_url = f"{self.base_url}/delete/{domain_name}/{record['id']}"
                    delete_response = requests.post(
                        delete_url, json=self.payload, headers=self.headers
                    )
                    delete_response_data = delete_response.json()

                    if delete_response_data["status"] != "SUCCESS":
                        raise Exception(
                            f"Failed to delete record {record['id']} for {domain_name}"
                        )

            self._create_new_records(domain_name, ip)


def get_providers_from_config(config: configparser.ConfigParser) -> List[Provider]:
    providers = []

    for key in config:
        if key == "DEFAULT":
            continue
        if key == "CLOUDFLARE":
            cloudflare_config = config["CLOUDFLARE"]

            email_address = cloudflare_config.get("API_EMAIL", None)
            api_key = cloudflare_config.get("API_KEY", None)
            domains = cloudflare_config.get("DOMAINS", "").split(",")

            providers.append(CloudflareProvider(email_address, api_key, domains))
        elif key == "PORKBUN":
            porkbun_config = config["PORKBUN"]

            api_key = porkbun_config.get("API_KEY", None)
            secret_key = porkbun_config.get("SECRET_KEY", None)
            domains = porkbun_config.get("DOMAINS", "").split(",")

            providers.append(PorkbunProvider(api_key, secret_key, domains))
        else:
            print(f"Unknown provider: {key}")

    return providers


def init_logger(config: configparser.ConfigParser) -> logging.Logger:
    log_filename = config["DEFAULT"].get(
        "LOG_FILENAME", "/var/log/dns_record_updater.log"
    )

    logfile_handler = logging.FileHandler(filename=log_filename)
    stdout_handler = logging.StreamHandler(stream=sys.stdout)
    handlers = [logfile_handler, stdout_handler]

    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] {%(filename)s:%(lineno)d} %(levelname)s - %(message)s",
        handlers=handlers,
    )

    return logging.getLogger()


def get_public_ip_address():
    return str(requests.get("https://ipinfo.io/json").json()["ip"])


def read_stored_ip_address():
    with shelve.open(SHELF_NAME) as shelf:
        return shelf.get("public_ip", None)


def write_new_ip_address(ip):
    with shelve.open(SHELF_NAME) as shelf:
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


def main():
    config = configparser.ConfigParser()
    config.read(os.environ.get("CONFIG_FILEPATH", "config.ini"))

    providers = get_providers_from_config(config)
    logger = init_logger(config)

    logger.info("Running dns_record_updater...")

    current_ip = get_public_ip_address()

    if should_update_records(current_ip):
        logger.info(
            f"Trying to update from {read_stored_ip_address()} to {current_ip}..."
        )

        for provider in providers:
            try:
                provider.update_records(current_ip)
                logger.info(f"Update Successful for {provider}.")
            except Exception as e:
                logger.error(f"Updating Failed for {provider}.")
                logger.exception(e)

        write_new_ip_address(current_ip)
    else:
        logger.info("No updates needed.")


if __name__ == "__main__":
    main()
