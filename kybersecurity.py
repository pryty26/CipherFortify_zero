"""
Short version (suitable for README header):

⚠️ This project is for legal and authorized security testing only.
Unauthorized scanning may be illegal.
The authors take no responsibility for user actions.

But u can scan 127.0.0.1
its your own ip!
"""


import socket
from urllib.parse import urlparse
import logging


def get_host_ip(full_domain:str) -> dict:
    if not full_domain:
        return {'success':'False','message':'illegal domain name, please check again'}
    parsed_domain = urlparse(full_domain)
    hostname = parsed_domain.hostname

    try:
        ip = socket.gethostbyname(hostname)
        return {'success':True, 'message':f'the host = {hostname},ip = {ip}'}
    except socket.gaierror as e:
        return {'success':'error','message':'illegal domain name, please check again'}
    except Exception as e:
        return {'success':'error','message':f'error{e}'}



def 666(target_ip)
    try:
        if not target_ip:
            return render_template('ipportscan.html',result="You need to write the ip")

        input_target_port = request.form.get('target_ports')
        if not input_target_port:
            target_ports = [80, 443, 22, 21, 53]#default port
        else:
            if ',' in input_target_port:
                target_ports= [int(port.strip())for port in input_target_port.split(',')]
            else:
                target_ports = [int(input_target_port)]
        for port in target_ports:
            if port<1 or port>65535:
                return render_template('ipportscan.html',result="The port can't be bigger then 65535 or smaller then 1(port should be 1-65535)")

        if len(target_ports) > 50:
            return render_template('ipportscan.html',result="You cannot scan too many ports at once (maximum 50)")

        scan_result = []
        for port in target_ports:
            src_port = random.randint(50000, 65535)
            ip_layer = IP(dst=target_ip)#where do u send IP层
            tcp_layer = TCP(sport=src_port,dport=port,flags="S")#how which port and flag=syn 更低




            response = sr1(ip_layer / tcp_layer, timeout=1, verbose=0)

            if response:
                if response.haslayer(TCP):
                    tcp_layer = response.getlayer(TCP)
                    if tcp_layer.flags == 0x12:  # SYN-ACK syn=0x2 ack=0x10
                        scan_result.append(f"Port {port}: Open")
                    elif tcp_layer.flags == 0x14:  # RST-ACK rst=0x4 ack=0x10
                        scan_result.append(f"Port {port}: closed")
            else:
                 scan_result.append(f"Port {port}: Filtered/No response")
        scan_result_text = '<br>'.join(scan_result)





print(result)
def socket_scanner(ip):
    sock = socket.socket(socket.inet)