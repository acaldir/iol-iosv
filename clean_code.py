import os
import re
from collections import defaultdict

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
    "cSR": {
        "kind":    "cisco_csr1000v",
        "image":   "cisco_csr1000v:17.03.08",
        "type":    None,
        "mgmt_ip": "csr_router_mgmt_ip",
    },
}    

mgmt_ip_artirimi = {
    "iol_router_mgmt_ip": 11,
    "iol_switch_mgmt_ip": 51,
    "vios_router_mgmt_ip": 71,
    "viosl2_switch_mgmt_ip": 91,
    "csr_router_mgmt_ip": 121,
}

ROUTER_BASLANGIC_IP = {
    ("R",   "R"):   10,
    ("vR",  "vR"):  20,
    ("cSR", "cSR"): 30,
    ("R",   "vR"):  15,
    ("vR",  "R"):   15,
    ("R",   "cSR"): 25,
    ("cSR", "R"):   25,
    ("vR",  "cSR"): 35,
    ("cSR", "vR"):  35,
}

SWITCH_ROUTER_BASLANGIC_IP = {
    "R":   10,
    "vR":  20,
    "cSR": 30,
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

def is_csr_router(cihaz):
    return get_cihaz_prefix(cihaz) == "cSR"

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

def format_based_vios_port(port: str, node_ismi: str, satir_numarasi: int, vios_tipi) -> str:
    if re.match(r'(?i)^(ethernet|e)', port):
        raise ValueError(
            f"\n!!! PORT HATASI !!! Satır {satir_numarasi}: "
            f"{node_ismi} '{port}' geçersiz. {vios_tipi} cihazlarda sadece GigabitEthernet portları kullanılabilir. Dogru yazim = g0/1 gibi"
        )
    
    gigabit_port_degisimi = port.lower().replace('Gi', '').replace('g', '')

    if '/' in gigabit_port_degisimi:
        parts = gigabit_port_degisimi.split('/')
        interface_sirasi = int(parts[1])
        return f"Gi{interface_sirasi}"
    
    if gigabit_port_degisimi.isdigit():
        return f"Gi/{gigabit_port_degisimi}"
    
    raise ValueError(
        f"\n!!! PORT HATASI !!! Satır {satir_numarasi}: "
        f" {node_ismi} '{port}' geçersiz. {vios_tipi} cihazlarda GiX/Y formatında olmalıdır."
    )

def format_csr_port(port: str, node_ismi: str, satir_numarasi: int) -> str:
    if re.match(r'(?i)^(ethernet|e)', port):
        raise ValueError(
            f"\n!!! PORT HATASI !!! Satır {satir_numarasi}: "
            f"{node_ismi} '{port}' geçersiz. CSR cihazlarda sadece GigabitEthernet portları kullanılabilir. Dogru yazim = g1,g2,g3.... gibi"
        )
    
    gigabit_port_degisimi = port.lower().replace('Gi', '').replace('g', '')

    if '/' in gigabit_port_degisimi:
        interfaces = gigabit_port_degisimi.replace('/', 'Gi')
        return f"Gi{interfaces}"
    
    if gigabit_port_degisimi.isdigit():
        return f"{gigabit_port_degisimi}"
    
    raise ValueError(
        f"\n!!! PORT HATASI !!! Satır {satir_numarasi}: "
        f" {node_ismi} '{port}' geçersiz. CSR cihazlarda GiX formatında olmalıdır."
    )

def format_port(port: str, node_ismi: str, satir_numarasi: int) -> str:
    if is_vios_router(node_ismi):
        return format_based_vios_port(port, node_ismi, satir_numarasi, "vIOS")
    elif is_viosl2_switch(node_ismi):
        return format_based_vios_port(port, node_ismi, satir_numarasi, "vIOSL2")
    elif is_csr_router(node_ismi):
        return format_csr_port(port, node_ismi, satir_numarasi)
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
    ham_links          = []   # ← yeni: ham link kayıtları tutulacak

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

        # IP hesapla (guncellenmis_ipler'i günceller ama ansible_data'ya YOK)
        ip_hesapla(cihaz1_adi, cihaz2_adi)

        link_end_point1 = f"{cihaz1_adi}:{port_display(cihaz1_portu, cihaz1_adi)}"
        link_end_point2 = f"{cihaz2_adi}:{port_display(cihaz2_portu, cihaz2_adi)}"
        links_lines.append(f'    - endpoints: ["{link_end_point1 }", "{link_end_point2}"]')

        # Ham kaydı sakla, sonra ansible_data dolduracağız
        link_index = router_link_sayaci[(min(get_id(cihaz1_adi), get_id(cihaz2_adi)),
                                  max(get_id(cihaz1_adi), get_id(cihaz2_adi)))] - 1
        ham_links.append((cihaz1_adi, cihaz1_portu, cihaz2_adi, cihaz2_portu, link_index))

    # ── Tüm IP'ler artık kesinleşti, ansible_data'yı şimdi doldur ──
    for cihaz1_adi, cihaz1_portu, cihaz2_adi, cihaz2_portu, link_index in ham_links:

        anahtar_d = (cihaz1_adi, cihaz2_adi, link_index)
        anahtar_t = (cihaz2_adi, cihaz1_adi, link_index)

        if anahtar_d in guncellenmis_ipler:
            cihaz1_ip, cihaz2_ip, mask = guncellenmis_ipler[anahtar_d]
        elif anahtar_t in guncellenmis_ipler:
            cihaz2_ip, cihaz1_ip, mask = guncellenmis_ipler[anahtar_t]
        else:
            cihaz1_ip, cihaz2_ip, mask = "", "", "255.255.255.0"
        
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

    return topology_name, cihaz_bilgisi, links_lines, ansible_data
# ── Router ve Switch baglantilari IP atama ─────────────────────────────────────────

router_baglanti_sayaci = defaultdict(list)   # anahtar: "base.x.y" → [(c1,c2), ...]
router_link_sayaci     = defaultdict(int)    # anahtar: (x, y)     → bağlantı sayısı
guncellenmis_ipler     = {}

def CIDR_prefix_uzunluğunu_hesapla(prefix):
    bits = (0xFFFFFFFF >> (32 - prefix)) << (32 - prefix)
    return ".".join([str((bits >> (8 * i)) & 0xFF) for i in reversed(range(4))])

def get_subnet_block_size(prefix):
    return 2 ** (32 - prefix )

def subnet_hesapla(ilk_baglanti_ip_dagitimi, baglanti_index, toplam_baglanti_sayisi):
    """
    ilk_baglanti_ip_dagitimi : "10.1.2"  (ilk /24 subnet'in ilk 3 okteti)
    baglanti_index : 0'dan başlar (0 = 1. bağlantı, 1 = 2. bağlantı, ...)
    toplam_baglanti_sayisi : o subnet'teki toplam bağlantı sayısı
    """
    if toplam_baglanti_sayisi == 1:
        subnetmask = 24
        network_baslangic = 0
    else:
        subnetmask = 25 + (toplam_baglanti_sayisi - 2)
        block_size = get_subnet_block_size(subnetmask)
        network_baslangic = (baglanti_index * block_size)
    
    mask = CIDR_prefix_uzunluğunu_hesapla(subnetmask)
    cihaz1_ip_hesapla = f"{ilk_baglanti_ip_dagitimi}.{network_baslangic + 1}"
    cihaz2_ip_hesapla = f"{ilk_baglanti_ip_dagitimi}.{network_baslangic + 2}"
    return cihaz1_ip_hesapla, cihaz2_ip_hesapla, mask

def get_router_base(cihaz1_prefix, cihaz2_prefix):
    return ROUTER_BASLANGIC_IP.get((cihaz1_prefix, cihaz2_prefix))

def ip_hesapla(cihaz1_adi, cihaz2_adi):
    cihaz1_ip = ""
    cihaz2_ip = ""
    mask      = "255.255.255.0"
    link_index = None          # ← YENİ

    input_cihaz1_prefix = get_cihaz_prefix(cihaz1_adi)
    input_cihaz2_prefix = get_cihaz_prefix(cihaz2_adi)

    is_router1 = input_cihaz1_prefix in ("R", "vR", "cSR")
    is_router2 = input_cihaz2_prefix in ("R", "vR", "cSR")
    is_switch1 = input_cihaz1_prefix in ("SW", "vSW")
    is_switch2 = input_cihaz2_prefix in ("SW", "vSW")

    if is_router1 and is_router2:
        id1 = get_id(cihaz1_adi)
        id2 = get_id(cihaz2_adi)
        x = min(id1, id2)
        y = max(id1, id2)

        base = get_router_base(input_cihaz1_prefix, input_cihaz2_prefix)
        if base is None:
            raise ValueError(f"Router IP atama hatası: '{cihaz1_adi}' ve '{cihaz2_adi}' kombinasyonu için başlangıç IP'si tanımlı değil!")
        
        yonlu_anahtar            = (id1, id2) # Yönlü anahtar: (R1, R2) ile (R2, R1) farklı sayılır
        ilk_baglanti_ip_dagitimi = f"{base}.{id1}.{id2}"

        router_link_sayaci[yonlu_anahtar] += 1
        n = router_link_sayaci[yonlu_anahtar]
        link_index = n - 1     # ← YENİ: buradan al

        #ilk_baglanti_ip_dagitimi = f"{base}.{x}.{y}"

        router_baglanti_sayaci[ilk_baglanti_ip_dagitimi].append((cihaz1_adi, cihaz2_adi))
        toplam = len(router_baglanti_sayaci[ilk_baglanti_ip_dagitimi])

        for i, (c1, c2) in enumerate(router_baglanti_sayaci[ilk_baglanti_ip_dagitimi]):
            yeni_ip1, yeni_ip2, yeni_subnetmask = subnet_hesapla(ilk_baglanti_ip_dagitimi, i, toplam)

            ip_id1 = get_id(c1)
            ip_id2 = get_id(c2)

            if ip_id1 <= ip_id2:
                guncellenmis_ipler[(c1, c2, i)] = (yeni_ip1, yeni_ip2, yeni_subnetmask)
            else:
                guncellenmis_ipler[(c1, c2, i)] = (yeni_ip2, yeni_ip1, yeni_subnetmask)

        cihaz1_ip, cihaz2_ip, mask = guncellenmis_ipler[(cihaz1_adi, cihaz2_adi, link_index)]

    elif (is_switch1 and is_router2) or (is_router1 and is_switch2):
        if is_switch1:
            switch, router = cihaz1_adi, cihaz2_adi
            router_prefix  = input_cihaz2_prefix
        else:
            switch, router = cihaz2_adi, cihaz1_adi
            router_prefix  = input_cihaz1_prefix

        switch_id = get_id(switch)
        router_id = get_id(router)
        base = SWITCH_ROUTER_BASLANGIC_IP.get(router_prefix)
        if base is None:
            raise ValueError(f"Switch-Router IP atama hatası: '{router}' için başlangıç IP'si tanımlı değil!")

        switch_ip = ""
        router_ip = f"{base}.100.{switch_id}.{router_id}"

        if cihaz1_adi == switch:
            cihaz1_ip, cihaz2_ip = switch_ip, router_ip
        else:
            cihaz1_ip, cihaz2_ip = router_ip, switch_ip

    return cihaz1_ip, cihaz2_ip, mask, link_index   # ← link_index eklendi
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
    header = """\
all:
  vars:
    ansible_connection: network_cli
    ansible_network_os: cisco.ios.ios
    ansible_user: admin
    ansible_password: admin
    ansible_httpapi_use_proxy: false
    ansible_ssh_common_args: '-o StrictHostKeyChecking=no'

  children:
"""
    groups = {
        "routers":      (("R", "vR", "cSR"), "router_id"),
        "switches":     (("SW", "vSW"),  "switch_id"),
    }

    satir = [header]
    for groupdaki_cihazlar, (prefix, id_atama) in groups.items():
        satir.append(f"    {groupdaki_cihazlar}:\n      hosts:")

        filtered_cihazlar = (
            (input_cihaz_isimleri, atanacak_ip_adresi)
            for input_cihaz_isimleri, atanacak_ip_adresi in sorted(cihaz_bilgisi.items())
            if input_cihaz_isimleri.startswith(prefix )
        )

        for cihaz, info in filtered_cihazlar:
            satir.append(f"        {cihaz}: {{ ansible_host: {info['mgmt_ipv4']}, {id_atama}: {info['id']} }}")

    path_yolu = os.path.join(ans_path, "inventory", "hosts.yml")
    open(path_yolu, 'w').write("\n".join(satir))   

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
            f.write("        match: none\n")
            f.write("    - tags:\n")
            f.write(f"        - {template_name}\n\n")

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