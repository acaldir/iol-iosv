import os
import re

EKIPMAN_CONFIGS = {
    "SW": {
        "kind":    "cisco_iol",
        "image":   "cisco_iol:L2-17.12.01",
        "type":    "L2",
        "mgmt_ip": "iol_switch_mgmt_ip",
    },
    "R": {
        "kind":    "cisco_iol",
        "image":   "cisco_iol:17.12.01",
        "type":    None,
        "mgmt_ip": "iol_router_mgmt_ip",
    },
    "vR": {
        "kind":    "cisco_vios",
        "image":   "cisco_vios:15.9.3M6",
        "type":    "router",
        "mgmt_ip": "vios_router_mgmt_ip",
    },
    "vSW": {
        "kind":    "cisco_viosl2",
        "image":   "cisco_viosl2:15.2.2020",
        "type":    "switch",
        "mgmt_ip": "viosl2_switch_mgmt_ip",
    }, 
}    

mgmt_ip_artirimi = {
    "iol_router_mgmt_ip": 11,
    "iol_switch_mgmt_ip": 51,
    "vios_router_mgmt_ip": 71,
    "viosl2_switch_mgmt_ip": 91,
}

# ── Yardımcı Fonksiyonlar ──────────────────────────────────────────────

def get_id(name):
    return int(re.search(r'\d+', name).group())


def get_cihaz_prefix(cihaz):
    cihaz_isimleri = re.match(r'[A-Za-z]+', cihaz).group()

    if cihaz_isimleri in EKIPMAN_CONFIGS:
        return cihaz_isimleri

    if cihaz_isimleri.upper() in EKIPMAN_CONFIGS:
        return cihaz_isimleri.upper()

    for buyuk_kucuk_harf in EKIPMAN_CONFIGS.keys():
        if cihaz_isimleri.upper() == buyuk_kucuk_harf.upper():
            return buyuk_kucuk_harf

    raise ValueError(
        f"Tanimsiz cihaz tipi: '{cihaz}' - EKIPMAN_CONFIGS içine tanim ekleyebilirsiniz!"
    )

def normal_cihaz_adi(cihaz):
    input_harf_kismi = get_cihaz_prefix(cihaz)
    input_sayi_kismi   = get_id(cihaz)
    return f"{input_harf_kismi}{input_sayi_kismi}"

def is_vios_router(cihaz):
    return get_cihaz_prefix(cihaz) == "vR"

def is_viosl2_switch(cihaz):
    return get_cihaz_prefix(cihaz) == "vSW"


def format_iol_port(port: str, node_ismi: str, satir_numarasi: int) -> str:

    if re.match(r'(?i)^(gigabit|gi|g)', port):
        raise ValueError(
            f"\n!!! PORT HATASI !!! Satır {satir_numarasi}: "
            f"{node_ismi} '{port}' geçersiz. IOL'de sadece Ethernet portları kullanılabilir. Dogru yazim = e0/1 gibi"
        )

    ethernet_port_degisimi = re.sub(r'(?i)^(ethernet|e)', '', port)

    if ethernet_port_degisimi.isdigit():
        port_index = int(ethernet_port_degisimi)
        slot, port_numarasi = divmod(port_index, 4)
        return f"Ethernet{slot}/{port_numarasi}"

    if '/' in ethernet_port_degisimi:
        slot, interface = map(int, ethernet_port_degisimi.split('/'))

        if interface > 3:
            raise ValueError(
                f"\n!!! PORT HATASI !!! Satır {satir_numarasi}: "
                f"{node_ismi} '{port}' geçersiz. IOL'de eX/4 olamaz."
            )

        return f"ethernet{slot}/{interface}"

    return f"ethernet{ethernet_port_degisimi}"


def format_vios_port(port: str, node_ismi: str, satir_numarasi: int) -> str:

    if re.match(r'(?i)^(ethernet|e)', port):
        raise ValueError(
            f"\n!!! PORT HATASI !!! Satır {satir_numarasi}: "
            f"{node_ismi} '{port}' geçersiz. vIOS'da sadece GigabitEthernet portları kullanılabilir. Dogru yazim = g0/1 gibi"
        )
    
    gigabit_port_degisimi = port.lower().replace('Gi', '').replace('g', '')

    if '/' in gigabit_port_degisimi:
        parts = gigabit_port_degisimi.split('/')
        slot, interfaces = int(parts[0]), int(parts[1])
        return f"Gi{slot}/{interfaces}"

    if gigabit_port_degisimi.isdigit():
        return f"Gi/{gigabit_port_degisimi}"

    raise ValueError(
        f"\n!!! PORT HATASI !!! Satır {satir_numarasi}: "
        f" {node_ismi} '{port}' geçersiz. vIOS'da GiX/Y formatında olmalıdır."
    )

def format_iosvl2_port(port: str, node_ismi: str, satir_numarasi: int) -> str:
    if re.match(r'(?i)^(ethernet|e)', port):
        raise ValueError(
            f"\n!!! PORT HATASI !!! Satır {satir_numarasi}: "
            f"{node_ismi} '{port}' geçersiz. vIOSL2'de sadece GigabitEthernet portları kullanılabilir. Dogru yazim = g0/1 gibi"
        )

    gigabit_port_degisimi = port.lower().replace('Gi', '').replace('g', '')

    if '/' in gigabit_port_degisimi:
        parts = gigabit_port_degisimi.split('/')
        slot, interfaces = int(parts[0]), int(parts[1])
        return f"Gi{slot}/{interfaces}"
    
    if gigabit_port_degisimi.isdigit():
        return f"Gi/{gigabit_port_degisimi}"

    raise ValueError(
        f"\n!!! PORT HATASI !!! Satır {satir_numarasi}: "
        f" {node_ismi} '{port}' geçersiz. vIOSL2'de GiX/Y formatında olmalıdır."
    )

def format_port(port: str, node_ismi: str, satir_numarasi: int) -> str:
    if is_vios_router(node_ismi):
        return format_vios_port(port, node_ismi, satir_numarasi)
    elif is_viosl2_switch(node_ismi):
        return format_iosvl2_port(port, node_ismi, satir_numarasi)
    else:
        return format_iol_port(port, node_ismi, satir_numarasi)

def port_display(port: str, cihaz: str) -> str:
    if is_vios_router(cihaz) or is_viosl2_switch(cihaz):
        return port
    else:
        return port.replace('ethernet', 'Ethernet', 1)


# ── Dosya Okuma & Satır İşleme ─────────────────────────────────────────

def mgmt_port_map(cihaz):
    if is_vios_router(cihaz) or is_viosl2_switch(cihaz):
        return "GigabitEthernet0/0"
    else:
        return "Ethernet0/0"

def dosyayi_isle(input_path):
    cihaz_bilgisi      = {}
    links_lines        = []
    topology_name      = "default_topology"
    kullanilan_portlar = {}
    ansible_data       = {}

    with open(input_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    for satir_numarasi, satir in enumerate(lines, 1):
        satir = satir.strip()

        if not satir or satir.startswith("#"):
            continue

        if satir.startswith("name:"):
            topology_name = satir.split(":")[1].strip()
            continue

        clean_line = satir.replace('\xa0', ' ').replace('\t', ' ')
        parts      = [p.strip() for p in clean_line.split() if p.strip()]

        if len(parts) != 4:
            continue

        cihaz1_adi, port1, cihaz2_adi, port2 = parts

        cihaz1_adi = normal_cihaz_adi(cihaz1_adi)
        cihaz2_adi = normal_cihaz_adi(cihaz2_adi)

        cihaz1_portu = format_port(port1, cihaz1_adi, satir_numarasi)
        cihaz2_portu = format_port(port2, cihaz2_adi, satir_numarasi)

        for cihaz, port in [(cihaz1_adi, cihaz1_portu), (cihaz2_adi, cihaz2_portu)]:
            beklenen_mgmt_port = mgmt_port_map(cihaz)
            if port == beklenen_mgmt_port:
                raise ValueError(
                    f"\n!!!!! HATA !!!! Satır {satir_numarasi}: {cihaz} üzerinde "
                    f"{port_display(beklenen_mgmt_port, cihaz)} (Mgmt portu) kullanılamaz."
                )

            if cihaz not in kullanilan_portlar:
                kullanilan_portlar[cihaz] = set()
            if port in kullanilan_portlar[cihaz]:
                raise ValueError(
                    f"\n!!!!! ÇAKIŞMA !!!! Satır {satir_numarasi}: "
                    f"{cihaz}-{port_display(port, cihaz)} portu zaten kullanılmış!"
                )

            kullanilan_portlar[cihaz].add(port)

            if cihaz not in cihaz_bilgisi:
                bas_harf  = get_cihaz_prefix(cihaz)
                ekipman   = EKIPMAN_CONFIGS[bas_harf]
                ip_key    = ekipman["mgmt_ip"]
                mgmt_ipv4 = f"172.20.20.{mgmt_ip_artirimi[ip_key]}"
                mgmt_ip_artirimi[ip_key] += 1

                cihaz_bilgisi[cihaz] = {
                    "kind":      ekipman["kind"],
                    "image":     ekipman["image"],
                    "type":      ekipman["type"],
                    "mgmt_ipv4": mgmt_ipv4,
                    "id":        get_id(cihaz),
                }

        cihaz1_ip, cihaz2_ip, mask = ip_hesapla(cihaz1_adi, cihaz2_adi)

        for cihaz, port, ip, hedef in [
            (cihaz1_adi, cihaz1_portu, cihaz1_ip, cihaz2_adi),
            (cihaz2_adi, cihaz2_portu, cihaz2_ip, cihaz1_adi),
        ]:
            if get_cihaz_prefix(cihaz) in ["R", "vR"]:
                if cihaz not in ansible_data:
                    ansible_data[cihaz] = []

                ansible_data[cihaz].append({
                    "name": port.replace('ethernet', 'Ethernet').replace('Gi', 'GigabitEthernet'),
                    "ip":   ip,
                    "mask": mask,
                    "desc": f"TO_{hedef}",
                })

        link_end_point1 = f"{cihaz1_adi}:{port_display(cihaz1_portu, cihaz1_adi)}"
        link_end_point2 = f"{cihaz2_adi}:{port_display(cihaz2_portu, cihaz2_adi)}"
        links_lines.append(f'    - endpoints: ["{link_end_point1 }", "{link_end_point2}"]')

    return topology_name, cihaz_bilgisi, links_lines, ansible_data


def ip_hesapla(cihaz1_adi, cihaz2_adi):
    cihaz1_ip = ""
    cihaz2_ip = ""
    mask      = "255.255.255.0"

    input_prefix1 = get_cihaz_prefix(cihaz1_adi)
    input_prefix2 = get_cihaz_prefix(cihaz2_adi)

    is_router1 = input_prefix1 == "R" or input_prefix1 == "vR"
    is_router2 = input_prefix2 == "R" or input_prefix2 == "vR"
    is_switch1 = input_prefix1 == "SW"
    is_switch2 = input_prefix2 == "SW"

    if is_router1 and is_router2:
        id1 = get_id(cihaz1_adi)
        id2 = get_id(cihaz2_adi)

        x = min(id1, id2)
        y = max(id1, id2)

        cihaz1_ip = f"10.{x}.{y}.1"
        cihaz2_ip = f"10.{x}.{y}.2"

    elif (is_switch1 and is_router2) or (is_router1 and is_switch2):
        if is_switch1:
            sw = cihaz1_adi
            rt = cihaz2_adi
        else:
            sw = cihaz2_adi
            rt = cihaz1_adi

        sw_id = get_id(sw)
        rt_id = get_id(rt)

        switch_ip = ""
        router_ip = f"10.100.{sw_id}.{rt_id}"
        mask      = "255.255.255.240"

        if cihaz1_adi == sw:
            cihaz1_ip = switch_ip
            cihaz2_ip = router_ip
        else:
            cihaz1_ip = router_ip
            cihaz2_ip = switch_ip

    return cihaz1_ip, cihaz2_ip, mask


# ── Yazma Fonksiyonları ────────────────────────────────────────────────

def yaz_containerlab_yaml(desktop_path, topology_name, cihaz_bilgisi, links_lines):
    yaml_path = os.path.join(desktop_path, f"{topology_name}.yml")
    with open(yaml_path, 'w', encoding='utf-8') as f:
        f.write(f"name: {topology_name}\n")
        f.write(f"topology:\n")
        f.write(f"  nodes:\n")
        for node, info in sorted(cihaz_bilgisi.items()):
            f.write(f"    {node}:\n")
            f.write(f"      kind: {info['kind']}\n")
            f.write(f"      image: {info['image']}\n")
            if info['type']:
                f.write(f"      type: {info['type']}\n")
            f.write(f"      mgmt-ipv4: {info['mgmt_ipv4']}\n")
        f.write(f"\n  links:\n")
        f.write("\n".join(links_lines))


def yaz_network_details(ans_path, ansible_data):
    with open(os.path.join(ans_path, "vars", "network_details.yml"), 'w') as f:
        f.write("loopback:\n  base: \"172.32\"\n  mask: \"255.255.255.0\"\n\nnetwork_config:\n")
        for node, interfaces in sorted(ansible_data.items()):
            f.write(f"  {node}:\n    interfaces:\n")
            for i in interfaces:
                f.write(f"      - {{ name: \"{i['name']}\", ip: \"{i['ip']}\", mask: \"{i['mask']}\", desc: \"{i['desc']}\" }}\n")


def yaz_ansible_cfg(ans_path):
    with open(os.path.join(ans_path, "ansible.cfg"), 'w') as f:
        f.write("[defaults]\nhost_key_checking = False\n")


def yaz_hosts_yml(ans_path, cihaz_bilgisi):
    with open(os.path.join(ans_path, "inventory", "hosts.yml"), 'w') as f:
        f.write("all:\n  vars:\n    ansible_connection: network_cli\n    ansible_network_os: cisco.ios.ios\n")
        f.write("    ansible_user: admin\n    ansible_password: admin\n    ansible_httpapi_use_proxy: false\n")
        f.write("    ansible_ssh_common_args: '-o StrictHostKeyChecking=no'\n\n  children:\n")
        for group, prefix in [("routers", "R"), ("switches", "S")]:
            f.write(f"    {group}:\n      hosts:\n")
            filtered = {k: v for k, v in cihaz_bilgisi.items() if k.upper().startswith(prefix)}
            for node, info in sorted(filtered.items()):
                id_key = "router_id" if prefix == "R" else "switch_id"
                f.write(f"        {node}: {{ ansible_host: {info['mgmt_ipv4']}, {id_key}: {info['id']} }}\n")


def yaz_loopback_j2(ans_path):
    with open(os.path.join(ans_path, "templates", "loopback.j2"), 'w') as f:
        f.write("{% set id = inventory_hostname[1:] | int %}\n")
        f.write("interface Loopback1\n ip address {{ loopback.base }}.{{ id }}.{{ id }} {{ loopback.mask }}\n")


def yaz_interfaces_j2(ans_path):
    with open(os.path.join(ans_path, "templates", "interfaces.j2"), 'w') as f:
        f.write("line vty 0 4\n")
        f.write(" exec-timeout 500 0\n")
        f.write("!\n")
        f.write("{% for intf in network_config[inventory_hostname].interfaces %}\n")
        f.write("interface {{ intf.name }}\n")
        f.write(" description {{ intf.desc }}\n")
        f.write(" ip address {{ intf.ip }} {{ intf.mask }}\n")
        f.write(" no shutdown\n")
        f.write("!\n")
        f.write("{% endfor %}")


def yaz_deploy_yml(ans_path):
    templates_path = os.path.join(ans_path, "templates")
    j2_dosyalari = sorted([d for d in os.listdir(templates_path) if d.endswith(".j2")])

    with open(os.path.join(ans_path, "playbooks", "deploy.yml"), 'w') as f:
        f.write("---\n")
        f.write("- name: Configure Network Lab Devices\n")
        f.write("  hosts: routers\n")
        f.write("  gather_facts: no\n")
        f.write("  vars_files:\n")
        f.write("    - \"{{ playbook_dir }}/../vars/network_details.yml\"\n\n")
        f.write("  tasks:\n\n")

        for j2 in j2_dosyalari:
            template_name = j2.replace(".j2", "")
            f.write(f"    - name: Apply {template_name} configuration\n")
            f.write("      cisco.ios.ios_config:\n")
            f.write(f"        src: \"../templates/{j2}\"\n")
            f.write("        match: none\n\n")


def ansible_klasorlerini_olustur(ans_path):
    for sub in ["vars", "inventory", "templates", "playbooks"]:
        os.makedirs(os.path.join(ans_path, sub), exist_ok=True)


# ── Ana Fonksiyon ──────────────────────────────────────────────────────

def convert_txt_to_yaml():
    desktop_path = r"C:\Users\TCACALDIR\Desktop\Deneme"
    input_path   = os.path.join(desktop_path, "input.txt")

    if not os.path.exists(input_path):
        print(f"Hata: {input_path} bulunamadı!")
        return

    try:
        topology_name, cihaz_bilgisi, links_lines, ansible_data = dosyayi_isle(input_path)

        ans_path = os.path.join(desktop_path, "ansible")
        ansible_klasorlerini_olustur(ans_path)

        yaz_containerlab_yaml(desktop_path, topology_name, cihaz_bilgisi, links_lines)
        yaz_network_details(ans_path, ansible_data)
        yaz_ansible_cfg(ans_path)
        yaz_hosts_yml(ans_path, cihaz_bilgisi)
        yaz_loopback_j2(ans_path)
        yaz_interfaces_j2(ans_path)
        yaz_deploy_yml(ans_path)

        print("Başarılı! Topoloji, Ansible Inventory, Değişkenler, Template ve Playbook dosyaları oluşturuldu.")

    except Exception as e:
        print(f"Hata: {e}")


if __name__ == "__main__":
    convert_txt_to_yaml()