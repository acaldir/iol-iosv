# Automating Network Lab Environments: A Deep Dive into a Python-Based ContainerLab & Ansible Generator

## Introduction

Building and testing network topologies in a lab environment has traditionally been a time-consuming, error-prone task — especially when it involves configuring multiple virtual routers and switches, assigning IP addresses, and writing boilerplate Ansible playbooks by hand. The Python script analyzed in this article eliminates that friction entirely. It reads a simple, human-readable text file describing a network topology, then automatically generates:

- A **ContainerLab YAML** topology file
- An **Ansible inventory** (`hosts.yml`)
- **Interface configuration variables** (`network_details.yml`)
- **Jinja2 templates** for loopback and interface configs
- A ready-to-run **Ansible playbook** (`deploy.yml`)

This is a significant productivity tool for network engineers working with Cisco virtual devices in lab environments.

---

## Supported Device Types

The script supports five Cisco device types, each mapped to a specific ContainerLab image and management IP pool:

| Prefix | Kind | Image | Role |
|--------|------|-------|------|
| `R` | cisco_iol | L2-17.12.01 | IOL Router |
| `SW` | cisco_iol | 17.12.01 | IOL Switch |
| `vR` | cisco_vios | 15.9.3M6 | vIOS Router |
| `vSW` | cisco_viosl2 | 15.2.2020 | vIOS L2 Switch |
| `cSR` | cisco_csr1000v | 17.03.08 | CSR1000v Router |

Each device type is recognized by its name prefix (e.g., `R1`, `SW3`, `vR2`, `cSR1`). This naming convention is both the input format and the key to all downstream automation.

---

## The Input Format

The script reads a plain text file (`input.txt`) with a very simple structure. Each non-comment line defines a link between two devices:

```
name: my_lab_topology

R1   e0/1   R2   e0/1
R1   e0/2   SW1  e1/0
vR1  g1     cSR1 g2
```

- `name:` sets the topology name
- Lines starting with `#` are ignored (comments)
- Each link line has exactly four tokens: `Device1 Port1 Device2 Port2`

This minimalist format keeps the topology definition readable and maintainable, even for large labs.

---

## Port Validation & Normalization

One of the script's most important features is its strict port validation. Different device types use different port naming conventions, and the script enforces them:

**IOL devices (R, SW)** use Ethernet ports only:
- Valid: `e0/1`, `e1`, `Ethernet0/2`
- Invalid: `g0/1` (GigabitEthernet ports are rejected with a helpful error)
- Ports are normalized to `Ethernet<slot>/<port>` format
- Port indices are automatically converted (e.g., `e5` → `Ethernet1/1`)

**vIOS / vIOSL2 devices (vR, vSW)** use GigabitEthernet ports only:
- Valid: `g1`, `Gi2`, `g0/1`
- Invalid: `e0/1` (Ethernet ports are rejected)
- Ports are normalized to `Gi<N>` format

**CSR1000v devices (cSR)** also use GigabitEthernet ports:
- Valid: `g1`, `g0/1`, `Gi2`
- Normalized to `Gi<slot>/<port>` or `Gi<N>` format

Beyond port type validation, the script also:
- **Prevents reuse of the same port** on the same device across multiple links
- **Blocks use of management ports** (e.g., `Ethernet0/0` for IOL, `Gi0` for vIOS, `Gi1` for CSR) in topology links

Any violation produces a clear, line-numbered error message so engineers can quickly fix their input file.

---

## Automatic Management IP Assignment

Each device is automatically assigned a management IP in the `172.20.20.0/24` range. The script maintains separate counters per device type, so IPs are predictably allocated:

| Device Type | Starting IP |
|-------------|-------------|
| IOL Router (`R`) | 172.20.20.11 |
| IOL Switch (`SW`) | 172.20.20.51 |
| vIOS Router (`vR`) | 172.20.20.71 |
| vIOS L2 Switch (`vSW`) | 172.20.20.91 |
| CSR1000v (`cSR`) | 172.20.20.121 |

Each new device of the same type gets the next available IP by incrementing the counter, making the assignment deterministic and reproducible.

---

## Intelligent IP Address Assignment for Links

The most sophisticated logic in the script is its **automatic point-to-point IP assignment** for router-to-router and router-to-switch links.

### Router-to-Router Links

IP subnets are assigned based on a structured scheme using the device IDs and a type-dependent base octet:

| Connection Type | Base Octet |
|-----------------|------------|
| R ↔ R | 10 |
| vR ↔ vR | 20 |
| cSR ↔ cSR | 30 |
| R ↔ vR | 15 |
| R ↔ cSR | 25 |
| vR ↔ cSR | 35 |

For a link between R1 and R2 (both IOL routers), the subnet base is `10.1.2.x`. The first link gets `.1` and `.2`, and if multiple parallel links exist between the same pair, the subnet is automatically split into smaller blocks (e.g., /25, /26) to accommodate them without overlap.

This means engineers don't need to think about IP planning at all for point-to-point links — the script handles it deterministically.

### Router-to-Switch Links

For links between a switch and a router, the router gets an IP in the format `<base>.100.<switch_id>.<router_id>`. The switch itself doesn't receive an IP (switches don't have routed interfaces by default).

---

## Generated Output Files

### 1. ContainerLab YAML (`<topology_name>.yml`)

This is the primary topology file consumed by ContainerLab. It defines all nodes with their kinds, images, types, and management IPs, then lists all links as endpoint pairs. Example structure:

```yaml
name: my_lab_topology
topology:
  nodes:
    R1:
      kind: cisco_iol
      image: cisco_iol:17.12.01
      mgmt-ipv4: 172.20.20.11
    ...
  links:
    - endpoints: ["R1:Ethernet0/1", "R2:Ethernet0/1"]
```

### 2. Ansible Inventory (`inventory/hosts.yml`)

Groups devices into `routers` and `switches`, with each host entry including its management IP and numeric ID. This feeds directly into Ansible's dynamic variable system.

### 3. Network Variables (`vars/network_details.yml`)

Contains the full interface configuration for every router — interface name, IP address, subnet mask, and a description indicating the connected peer (e.g., `TO_R2`). This file is consumed by the Jinja2 templates at deploy time.

### 4. Jinja2 Templates

Two templates are auto-generated:

- **`loopback.j2`** — Configures a loopback interface (`Loopback1`) with an IP derived from the device's numeric ID (e.g., R3 gets `172.32.3.3/32`)
- **`interfaces.j2`** — Iterates over all interfaces in `network_details.yml` and configures IP addresses, descriptions, and `no shutdown`

### 5. Ansible Playbook (`playbooks/deploy.yml`)

A complete, ready-to-run playbook targeting the `routers` group. It dynamically discovers all `.j2` templates in the templates directory and creates a task for each one, with matching tags for selective deployment.

---

## Error Handling Philosophy

The script takes a "fail fast and clearly" approach to errors. Rather than producing malformed output silently, it raises descriptive exceptions with:

- The **line number** in the input file where the problem occurred
- The **device name** and **port** involved
- A clear explanation of what went wrong and how to fix it

This makes it suitable for use in automated pipelines where silent failures would be costly.

---

## Architectural Strengths

**Separation of concerns** — parsing, IP calculation, and file writing are cleanly separated into distinct functions, making the code easy to extend (e.g., adding a new device type requires only adding an entry to `EKIPMAN_CONFIGS`).

**Deterministic output** — given the same input, the script always produces the same IPs and configurations, making it safe to re-run without side effects.

**Multi-link awareness** — the subnet calculator dynamically adjusts prefix lengths when multiple parallel links exist between the same device pair, a common scenario in redundant lab designs.

**Two-pass IP assignment** — link IPs are finalized only after all links have been parsed (because subnet sizing depends on total link count between a pair). The script stores "raw links" first, then populates Ansible data in a second pass once all IPs are settled.

---

## Conclusion

This script is a well-engineered automation tool that bridges the gap between a simple text-based topology description and a fully configured ContainerLab + Ansible lab environment. For network engineers who frequently spin up Cisco virtual labs, it eliminates hours of repetitive configuration work, enforces consistency, and produces professional-grade infrastructure-as-code artifacts from a minimal input. It's an excellent example of how targeted Python scripting can dramatically accelerate network engineering workflows.
