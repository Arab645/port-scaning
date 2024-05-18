import nmap
from hosts import wks
values_list = wks.col_values(1)
print(values_list)

def cheking_ports(values_list):
    for item in values_list:
        nm = nmap.PortScanner()
        print(f"[*] Сканирование...{item}")
        nm.scan(item)
        scan_stats = nm.scanstats()
        print(f"[{scan_stats['timestr']}] Прошло времени: {scan_stats['elapsed']} с " \
              f"Активные хосты: {scan_stats['uphosts']} Неактивные хосты: {scan_stats['downhosts']} " \
              f"Всего хостов: {scan_stats['totalhosts']} ")
        hosts = nm.all_hosts()
        for host in hosts:
            hostname = nm[host].hostname()
            addresses = nm[host].get("addresses")
            ipv4 = addresses.get("ipv4")
            mac_address = addresses.get("mac")
            vendor = nm[host].get("vendor")
            open_tcp_ports = nm[host].all_tcp()
            open_udp_ports = nm[host].all_udp()
            print("=" * 30, host, "=" * 30)
            print(f"Имя хоста: {hostname} IPv4: {ipv4} MAC: {mac_address}")
            print(f"Вендор: {vendor}")
            if open_tcp_ports or open_udp_ports:
                print("-" * 30, "Открытые порты", "-" * 30)
                for tcp_port in open_tcp_ports:
                    port_details = nm[host].tcp(tcp_port)
                    port_state = port_details.get("state")
                    port_up_reason = port_details.get("reason")
                    port_service_name = port_details.get("name")
                    port_product_name = port_details.get("product")
                    port_product_version = port_details.get("version")
                    port_extrainfo = port_details.get("extrainfo")
                    port_cpe = port_details.get("cpe")
                    print(f"TCP-порт: {tcp_port} Состояние: {port_state} Причина: {port_up_reason}")
                    print(f"Служба: {port_service_name} Продукт: {port_product_name} Версия: {port_product_version}")
                    print(f"Дополнительная информация: {port_extrainfo} CPE: {port_cpe}")
                    print("-" * 50)
            if open_udp_ports:
                print(open_udp_ports)
print(cheking_ports(values_list))