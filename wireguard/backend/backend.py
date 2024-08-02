import os
import re
import sys
import json
import subprocess

CONFIG_FILE = "config.json"


def is_root():
    if os.geteuid() != 0:
        raise RuntimeError("You need to run this script as root")


def get_home_dir(client_name):
    home_dir = f"/home/{client_name}"
    if os.path.exists(home_dir):
        return home_dir

    sudo_user = os.getenv("SUDO_USER", None)
    if sudo_user is not None:
        if sudo_user == "root":
            return "/root"
        return f"/home/{sudo_user}"

    return "/root"


def create_config():
    print("Welcome to the WireGuard installer!")
    print("I need to ask you a few questions before starting the setup.")
    print("You can keep the default options and just press enter if you are ok with them.")
    print()

    server_pub_ip = subprocess.check_output(["ip", "-4", "addr"]).decode().strip()
    server_pub_ip = re.search(r"inet (\S+)/\d+ scope global", server_pub_ip)
    if server_pub_ip:
        server_pub_ip = server_pub_ip.group(1)
    else:
        server_pub_ip = subprocess.check_output(["ip", "-6", "addr"]).decode().strip()
        server_pub_ip = re.search(r"inet6 (\S+)/", server_pub_ip).group(1)

    server_pub_ip = input(f"IPv4 or IPv6 public address: [{server_pub_ip}] ") or server_pub_ip

    server_pub_nic = subprocess.check_output(["ip", "-4", "route", "ls"]).decode().strip()
    server_pub_nic = re.search(r"dev (\S+)", server_pub_nic).group(1)
    server_pub_nic = input(f"Public interface: [{server_pub_nic}] ") or server_pub_nic

    server_wg_nic = input("WireGuard interface name: [wg0] ") or "wg0"

    server_wg_ipv4 = input("Server WireGuard IPv4: [10.66.66.1] ") or "10.66.66.1"
    server_wg_ipv6 = input("Server WireGuard IPv6: [fd42:42:42::1] ") or "fd42:42:42::1"

    random_port = str(subprocess.check_output(["shuf", "-i49152-65535", "-n1"]).decode().strip())
    server_port = input(f"Server WireGuard port [1-65535]: [{random_port}] ") or random_port

    client_dns_1 = input("First DNS resolver to use for the clients: [1.1.1.1] ") or "1.1.1.1"
    client_dns_2 = input("Second DNS resolver to use for the clients (optional): [1.0.0.1] ") or "1.0.0.1"

    allowed_ips = (
        input("Allowed IPs list for generated clients (leave default to route everything): [0.0.0.0/0,::/0] ")
        or "0.0.0.0/0,::/0"
    )

    config = {
        "server_pub_ip": server_pub_ip,
        "server_pub_nic": server_pub_nic,
        "server_wg_nic": server_wg_nic,
        "server_wg_ipv4": server_wg_ipv4,
        "server_wg_ipv6": server_wg_ipv6,
        "server_port": server_port,
        "client_dns_1": client_dns_1,
        "client_dns_2": client_dns_2,
        "allowed_ips": allowed_ips,
    }

    with open(CONFIG_FILE, "w") as f:
        f.write(json.dumps(config))


def read_config():
    with open(CONFIG_FILE, "r") as f:
        return json.loads(f.read())


def generate_keys():
    private_key = subprocess.check_output(["wg", "genkey"]).strip().decode("utf-8")
    public_key = subprocess.check_output(["wg", "pubkey"], input=private_key.encode()).strip().decode("utf-8")
    return private_key, public_key


def get_client_name(server_wg_nic):
    while True:
        client_name = input("Client name: ")
        if re.match(r"^[a-zA-Z0-9_-]+$", client_name) and len(client_name) < 16:
            result = subprocess.run(
                ["grep", "-c", f"^### Client {client_name}$", f"/etc/wireguard/{server_wg_nic}.conf"],
                capture_output=True,
                text=True,
            )
            if result.stdout.strip() == "0":
                return client_name
            print("A client with the specified name was already created, please choose another name.")
        else:
            print(
                "The client name must consist of alphanumeric characters, "
                "underscores, or dashes and can't exceed 15 chars."
            )


def find_available_ip(base_ip, conf_file):
    for dot_ip in range(2, 255):
        result = subprocess.run(["grep", "-c", f"{base_ip[:-1]}{dot_ip}", conf_file], capture_output=True, text=True)
        if result.stdout.strip() == "0":
            return dot_ip
    raise RuntimeError("The subnet configured supports only 253 clients.")


def generate_preshared_key():
    preshared_key = subprocess.check_output(["wg", "genpsk"]).strip().decode("utf-8")
    return preshared_key


def new_client():
    is_root()

    if not os.path.exists(CONFIG_FILE):
        create_config()

    config = read_config()

    server_pub_ip = config["server_pub_ip"]
    server_port = config["server_port"]
    server_wg_nic = config["server_wg_nic"]
    server_wg_ipv4 = config["server_wg_ipv4"]
    server_wg_ipv6 = config["server_wg_ipv6"]
    client_dns_1 = config["client_dns_1"]
    client_dns_2 = config["client_dns_2"]
    private_key, public_key = generate_keys()
    server_pub_key = public_key
    allowed_ips = config["allowed_ips"]

    if ":" in server_pub_ip and not (server_pub_ip.startswith("[") and server_pub_ip.endswith("]")):
        server_pub_ip = f"[{server_pub_ip}]"

    endpoint = f"{server_pub_ip}:{server_port}"

    client_name = get_client_name(server_wg_nic)

    dot_ip = find_available_ip(server_wg_ipv4, f"/etc/wireguard/{server_wg_nic}.conf")
    client_wg_ipv4 = f"{server_wg_ipv4.rsplit('.', 1)[0]}.{dot_ip}"

    dot_ip = find_available_ip(server_wg_ipv6, f"/etc/wireguard/{server_wg_nic}.conf")
    client_wg_ipv6 = f"{server_wg_ipv6.split('::')[0]}::{dot_ip}"

    client_priv_key = private_key
    client_pub_key = public_key
    client_pre_shared_key = generate_preshared_key()

    home_dir = get_home_dir(client_name)

    client_conf = f"""
[Interface]
PrivateKey = {client_priv_key}
Address = {client_wg_ipv4}/32,{client_wg_ipv6}/128
DNS = {client_dns_1},{client_dns_2}

[Peer]
PublicKey = {server_pub_key}
PresharedKey = {client_pre_shared_key}
Endpoint = {endpoint}
AllowedIPs = {allowed_ips}
"""
    client_dir = os.path.join(home_dir, f"{client_name}.conf")

    with open(client_dir, "w") as f:
        f.write(client_conf)

    server_conf = f"""
### Client {client_name}
[Peer]
PublicKey = {client_pub_key}
PresharedKey = {client_pre_shared_key}
AllowedIPs = {client_wg_ipv4}/32,{client_wg_ipv6}/128
"""
    with open(f"/etc/wireguard/{server_wg_nic}.conf", "a") as f:
        f.write(server_conf)

    subprocess.run(["wg", "syncconf", server_wg_nic, f"<(wg-quick strip {server_wg_nic})"], shell=True)

    qr_file = f"{client_dir}.png"
    subprocess.run(["qrencode", "-o", qr_file, "-t", "png", server_conf], check=True)
    print(f"QR code saved to {qr_file}")

    print(f"Your client config file is in {client_dir}.conf")


def list_clients():
    is_root()

    wg_dir = "/etc/wireguard"

    if not os.path.exists(wg_dir):
        print("WireGuard directory does not exist.")
        return

    if not os.path.exists(CONFIG_FILE):
        raise RuntimeError("The wireguard configuration file does not exist.")

    config = read_config()

    server_wg_nic = config["server_wg_nic"]
    config_file = f"{wg_dir}/{server_wg_nic}.conf"

    try:
        with open(config_file, "r") as file:
            lines = file.readlines()
    except FileNotFoundError:
        print(f"Configuration file {config_file} not found.")
        sys.exit(1)

    clients = [line.split(" ")[2].strip() for line in lines if line.startswith("### Client")]

    if len(clients) == 0:
        print("\nYou have no existing clients!")
        sys.exit(1)

    for idx, client in enumerate(clients, start=1):
        print(f"{idx}) {client}")
