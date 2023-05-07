import os
import json
import socket
import ssl
from OpenSSL.SSL import Connection, Context, SSLv23_METHOD, TLSv1_2_METHOD
from datetime import datetime
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning, SubjectAltNameWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
requests.packages.urllib3.disable_warnings(SubjectAltNameWarning)


def get_certificate_info(connect_ip, connect_port):
    """ Get details from the host. """

    try:
        try:
            ssl_connection_setting = Context(SSLv23_METHOD)
        except ValueError:
            ssl_connection_setting = Context(TLSv1_2_METHOD)

        ssl_connection_setting.set_timeout(5)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((connect_ip, connect_port))
            c = Connection(ssl_connection_setting, s)
            c.set_tlsext_host_name(str.encode(connect_ip))
            c.set_connect_state()
            c.do_handshake()

            cert = c.get_peer_certificate()
            is_expired = cert.has_expired()
            issuer = cert.get_issuer()

            subject_list = cert.get_subject().get_components()
            cert_byte_arr_decoded = {}
            for item in subject_list:
                cert_byte_arr_decoded.update({item[0].decode('utf-8'): item[1].decode('utf-8')})

            subject = None
            if len(cert_byte_arr_decoded) > 0:
                subject = cert_byte_arr_decoded
            common_name = None
            if cert_byte_arr_decoded["CN"]:
                common_name = cert_byte_arr_decoded["CN"]

            end_date = datetime.strptime(str(cert.get_notAfter().decode('utf-8')), "%Y%m%d%H%M%SZ")
            expire_date = str(end_date)
            c.shutdown()
            s.close()
            info = {
                "common_name": common_name,
                "issuer": issuer,
                "subject": subject,
                "expire_date": expire_date,
                "is_expired": is_expired
            }
            return info
    except Exception as error:
        info = {
            "connect_ip": connect_ip,
            "error": error
        }
        return info


def get_certificate(hostname, port):
    security_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    security_context.verify_mode = ssl.CERT_REQUIRED
    security_context.check_hostname = True
    security_context.load_default_certs()

    # Create a streaming socket
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Create a secure socket
    secure_connection = security_context.wrap_socket(connection, server_hostname=hostname)
    # Connect to host
    secure_connection.connect((hostname, port))
    # Get the certificate from the host
    cert = secure_connection.getpeercert(binary_form=True)
    # Convert to PEM format
    cert_pem = ssl.DER_cert_to_PEM_cert(cert)
    return cert_pem


def configure_pem(local_host, local_port, local_path):

    pem_file_path = os.path.join(local_path, local_host + ".pem")
    local_pem = get_certificate(local_host, local_port)
    if len(local_pem) >= 10 and "BEGIN CERTIFICATE" in local_pem and "END CERTIFICATE" in local_pem:
        if not os.path.exists(pem_file_path):
            with open(pem_file_path, mode="w", encoding="utf-8") as out_pem:
                out_pem.write(local_pem)
                out_pem.write("\n")
        return pem_file_path
    else:
        print("ERROR:".ljust(30), local_pem)
        return False


def get_cluster_data(local_host, local_port, local_cert):

    api_username = "ontapadmin"
    api_password = "fakepassword1"

    base_url = "https://" + local_host + ":" + str(local_port)
    url_filter = "/api/cluster?return_timeout=120&return_records=true"
    url = base_url + url_filter

    data = requests.get(url, auth=(api_username, api_password), verify=local_cert)
    api_code = data.status_code
    api_json = json.dumps(data.json(), indent=4, sort_keys=False)
    print(api_code)
    print(api_json)


def main():
    out_folder = "certs_data"
    os.makedirs(out_folder, exist_ok=True)

    device_address = "192.168.1.160"
    device_port = 443

    cert_info = get_certificate_info(device_address, device_port)
    common_name = cert_info["common_name"]

    dns_hostname = socket.gethostbyaddr(device_address)[0]
    if dns_hostname == common_name:
        cert_file = configure_pem(dns_hostname, device_port, out_folder)
        if cert_file:
            get_cluster_data(dns_hostname, device_port, cert_file)


if __name__ == "__main__":
    main()

