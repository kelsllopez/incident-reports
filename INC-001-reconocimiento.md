# INC-001 — Reconocimiento de Red

**Ticket:** INC-001  
**Fecha:** 09 de junio de 2026 · Turno matutino  
**Analista:** Katalina Sepúlveda López  
**Severidad:** 🟡 Baja  
**Estado:** ✅ Cerrado  
**MITRE:** T1046 — Network Service Scanning  
**SIEM:** Wazuh 4.7.5  

---

## Descripción

Se detectó actividad de escaneo de red desde `192.168.56.30` (Kali Linux) hacia toda la subred `192.168.56.0/24`. El escaneo identificó activos activos, puertos abiertos y versiones de servicios expuestos en el servidor Windows. Se estableció la línea base de la red durante el primer turno.

---

## Infraestructura afectada

| Activo | IP | Sistema operativo | Rol |
|---|---|---|---|
| kels-VirtualBox | 192.168.56.10 | Ubuntu 22.04 | SIEM Wazuh |
| WIN-J36GU3SVEOC | 192.168.56.20 | Windows Server 2022 | Objetivo |
| kali-linux | 192.168.56.30 | Kali Linux | Atacante (lab) |

---

## Revisión del dashboard Wazuh — Misión 1

Al iniciar el turno se revisó el panel de control con los siguientes resultados:

| Indicador | Estado |
|---|---|
| Alertas críticas (nivel 15+) | 0 |
| Alertas altas (nivel 12–14) | 0 |
| Alertas medias (nivel 7–11) | 0 |
| Alertas bajas (nivel 0–6) | 46 |
| Agentes activos | 1 |
| Agentes desconectados | 0 |

Las 46 alertas de nivel bajo corresponden a eventos rutinarios del sistema (logs de autenticación, tráfico permitido por firewall). No requiere escalamiento.

---

## Escaneo de red — Misión 2

**Comandos ejecutados por el atacante:**
```bash
sudo nmap -sn 192.168.56.0/24        # descubrimiento de hosts
sudo nmap -sS 192.168.56.0/24        # escaneo SYN sigiloso
sudo nmap -sV -sC 192.168.56.20      # detección de versiones y scripts
```

**Hosts activos identificados:**

| IP | SO estimado | Puertos abiertos | Servicios detectados |
|---|---|---|---|
| 192.168.56.10 | Linux | 443/tcp | HTTPS → Wazuh dashboard |
| 192.168.56.20 | Windows | 53, 80, 135, 139, 445, 5985 | DNS, HTTP, RPC, SMB, WinRM |
| 192.168.56.30 | Desconocido | Ninguno TCP visible | Firewall o solo UDP |

**Hallazgos adicionales en 192.168.56.20:**

| Puerto | Estado | Servicio |
|---|---|---|
| 53/tcp | OPEN | DNS — Simple DNS Plus |
| 80/tcp | OPEN | HTTP — Microsoft IIS 10.0 |
| 135/tcp | OPEN | MSRPC — Microsoft Windows RPC |
| 139/tcp | OPEN | NetBIOS Session Service |
| 445/tcp | OPEN | SMB — Microsoft-DS |
| 5985/tcp | OPEN | WinRM — Windows Remote Management |

- **Hostname revelado:** WIN-J36GU3SVEOC  
- **Sistema operativo:** Windows Server 2022 Build 20348 (97% certeza)  
- **SMB Signing:** Habilitado pero NO obligatorio ⚠️  
- **HTTP TRACE:** Habilitado ⚠️  
- **Distancia red:** 1 salto  

---

## Indicadores de compromiso (IOC)

| Activo | Observación | IOC detectado |
|---|---|---|
| 192.168.56.10 | Servicio HTTPS estándar | ❌ No detectados |
| 192.168.56.20 | Servidor Windows con servicios típicos | ❌ No detectados |
| 192.168.56.30 | Activo que no responde a escaneo TCP | ❌ No detectados |

> 🧠 **Nota del analista:** El host `.30` podría ser un gateway, impresora o endpoint con hardening. Se recomienda monitoreo pasivo o escaneo UDP en el próximo turno.

---

## Técnicas MITRE ATT&CK

| ID | Técnica | Descripción |
|---|---|---|
| T1046 | Network Service Scanning | Escaneo de puertos y servicios con Nmap |
| T1595 | Active Scanning | Descubrimiento activo de hosts en la subred |

---

## Recomendaciones

| Prioridad | Acción |
|---|---|
| 🔴 Alta | Deshabilitar HTTP TRACE en IIS |
| 🔴 Alta | Hacer obligatorio SMB Signing |
| 🟡 Media | Restringir WinRM a IPs autorizadas |
| 🟡 Media | Revisar necesidad de NetBIOS (puerto 139) |
| 🟢 Baja | Investigar naturaleza del host 192.168.56.30 |
| 🟢 Baja | Analizar muestra de las 46 alertas nivel bajo |

---

## Cierre formal

| Campo | Valor |
|---|---|
| Estado handover | 🟢 Listo para siguiente turno |
| Ticket de incidente creado | Ninguno |
| Escalamiento requerido | No |
| Clasificación del turno | TURNO TRANQUILO — Sin incidentes |

---

**Firma:** Katalina Sepúlveda López — Analista SOC Nivel 1 — CyberCorp S.A.  
**Fecha:** 09 de junio de 2026
