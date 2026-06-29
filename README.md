# 📁 incident-reports — CyberCorp S.A. SOC Lab

> Reportes de incidente formales documentados durante una semana simulada como **SOC Analyst Nivel 1** en el entorno ficticio CyberCorp S.A.  
> Entorno: Wazuh 4.7.5 · Windows Server 2022 · Kali Linux · VirtualBox  
> Red interna: `192.168.56.0/24` · Dominio: `soc.local`  
> Analista: **Katalina Sepúlveda López**

---

## 🏗️ Infraestructura del laboratorio

| Activo | IP | Rol |
|---|---|---|
| kels-VirtualBox (Ubuntu 22.04) | 192.168.56.10 | SIEM — Wazuh 4.7.5 |
| WIN-J36GU3SVEOC (Windows Server 2022) | 192.168.56.20 | Objetivo — Controlador de Dominio |
| kali-linux | 192.168.56.30 | Atacante (simulado) |

---

## 📋 Índice de incidentes

| ID | Fecha | Tipo de ataque | Severidad | Estado | MITRE principal |
|---|---|---|---|---|---|
| [INC-001](#inc-001--reconocimiento-de-red) | 09 jun 2026 | Reconocimiento de red | 🟡 Baja | ✅ Cerrado | T1046 |
| [INC-002](#inc-002--ataque-de-fuerza-bruta) | 11 jun 2026 | Fuerza bruta SMB | 🔴 Alta | ✅ Cerrado | T1110 |
| [INC-003](#inc-003--movimiento-lateral) | 11 jun 2026 | Movimiento lateral | 🔴 Alta | ✅ Cerrado | T1021 |
| [INC-004](#inc-004--escalada-de-privilegios) | 17 jun 2026 | Escalada de privilegios | 🔴 Crítica | ✅ Cerrado | T1098 |
| [INC-005](#inc-005--persistencia--backdoor) | 18 jun 2026 | Persistencia / Backdoor | 🔴 Crítica | ✅ Cerrado | T1543.003 |

---

## Resumen ejecutivo de la semana

Durante la semana del 09 al 20 de junio de 2026 se detectaron, analizaron y contuvieron **5 incidentes de seguridad** que siguieron una **cadena de ataque progresiva y planificada** desde reconocimiento inicial hasta persistencia avanzada.

```
ETAPA 1 — Reconocimiento       → Nmap desde Kali (T1046)
ETAPA 2 — Acceso inicial       → Fuerza bruta SMB (T1110)
ETAPA 3 — Movimiento lateral   → CrackMapExec + WinRM (T1021)
ETAPA 4 — Escalada privilegios → Cuenta hackersoc → Domain Admins (T1098)
ETAPA 5 — Persistencia         → 4 capas de backdoor (T1543.003)
```

**Vector común:** IP atacante `192.168.56.30` · Credenciales `usuarioprueba:Password123!` · Horario: 16:00–22:00 hrs

| Métrica | Valor |
|---|---|
| Incidentes detectados | 5 |
| Incidentes contenidos | 5 (100%) |
| Tiempo promedio de detección | < 5 min |
| Compromisos de datos confirmados | 0 |
| Reglas Wazuh personalizadas creadas | 5 (IDs 100001–100005) |
| Técnicas MITRE documentadas | 15+ |
| Eventos totales analizados | 1,000+ |

---

## INC-001 · Reconocimiento de red

**Ticket:** INC-001  
**Fecha:** 09 de junio de 2026 · Turno matutino  
**Severidad:** 🟡 Baja  
**Estado:** ✅ Cerrado  
**MITRE:** T1046 — Network Service Scanning

### Descripción

Se detectó actividad de escaneo de red desde `192.168.56.30` (Kali Linux) hacia toda la subred `192.168.56.0/24`. El escaneo identificó activos, puertos abiertos y versiones de servicios expuestos en el servidor Windows.

**Comandos ejecutados por el atacante:**
```bash
nmap -sn 192.168.56.0/24      # descubrimiento de hosts
nmap -sS 192.168.56.0/24      # escaneo SYN sigiloso
nmap -sV -sC 192.168.56.20    # detección de versiones y scripts
```

### Hallazgos técnicos

| Puerto | Estado | Servicio |
|---|---|---|
| 53/tcp | OPEN | DNS — Simple DNS Plus |
| 80/tcp | OPEN | HTTP — Microsoft IIS 10.0 |
| 135/tcp | OPEN | MSRPC — Microsoft Windows RPC |
| 139/tcp | OPEN | NetBIOS Session Service |
| 445/tcp | OPEN | SMB — Microsoft-DS |
| 5985/tcp | OPEN | WinRM — Windows Remote Management |

- **Hostname revelado:** WIN-J36GU3SVEOC  
- **Sistema operativo:** Windows Server 2022 (97% certeza)  
- **SMB Signing:** Habilitado pero NO obligatorio ⚠️  
- **HTTP TRACE:** Habilitado ⚠️

### Evidencia Wazuh

El dashboard registró **46 alertas de nivel bajo** al inicio del turno, todas correspondientes a eventos rutinarios. El escaneo posterior generó un pico visible en el gráfico de actividad exactamente al momento del ataque.

### Recomendaciones

- 🔴 Deshabilitar HTTP TRACE en IIS
- 🔴 Hacer obligatorio SMB Signing
- 🟡 Restringir WinRM a IPs autorizadas
- 🟡 Revisar necesidad de NetBIOS (puerto 139)

---

## INC-002 · Ataque de fuerza bruta

**Ticket:** INC-002  
**Fecha:** 11 de junio de 2026 · 16:32:44  
**Severidad:** 🔴 Alta  
**Estado:** ✅ Cerrado  
**MITRE:** T1110 — Brute Force

### Descripción

Se detectaron múltiples intentos de autenticación fallidos contra el servicio SMB del servidor Windows (`192.168.56.20`). El atacante utilizó herramientas automatizadas desde `192.168.56.30` para intentar adivinar credenciales del usuario `usuarioprueba`.

**Comandos ejecutados por el atacante:**
```bash
smbclient -L //192.168.56.20 -U usuarioprueba --password=contraseñafalsa
for i in {1..20}; do smbclient -L //192.168.56.20 -U usuarioprueba --password=incorrecta$i; done
```

### Evidencia Wazuh

| Campo | Valor |
|---|---|
| Regla Wazuh | 60122 — Logon Failure |
| EventID | 4625 — Login Fallido |
| Nivel Wazuh | 5 |
| IP atacante | 192.168.56.30 (Kali Linux) |
| Usuario objetivo | usuarioprueba |
| Cantidad de intentos | 20+ en menos de 2 minutos |
| Hora inicio | 16:32:44 |
| Resultado | Ataque fallido — Sin acceso |

### Recomendaciones

- 🔴 Bloquear IP `192.168.56.30` en firewall
- 🔴 Configurar Account Lockout Policy (5 intentos máx.)
- 🟡 Cambiar contraseña de `usuarioprueba`
- 🟡 Implementar alerta automática para 5+ EventID 4625

---

## INC-003 · Movimiento lateral

**Ticket:** INC-003  
**Fecha:** 11 de junio de 2026 · 21:44:00  
**Severidad:** 🔴 Alta  
**Estado:** ✅ Cerrado  
**MITRE:** T1021 — Remote Services

### Descripción

El atacante utilizó credenciales válidas (`usuarioprueba:Password123!`) para conectarse al servidor Windows mediante SMB y WinRM. Se realizó enumeración completa de recursos compartidos, usuarios del dominio y escaneo de servicios.

### Cronología del ataque

```
21:44:00 → Kali inició enumeración SMB
21:44:30 → Enumeración de recursos compartidos (ADMIN$, C$, SYSVOL, NETLOGON)
21:44:45 → Enumeración de 14 usuarios del dominio
21:44:50 → Escaneo de red con nmap -p 445
21:45:00 → Verificación y conexión WinRM exitosa
21:50–21:54 → Wazuh registra 125+ eventos EventID 4624
```

**Comandos ejecutados por el atacante:**
```bash
crackmapexec smb 192.168.56.20 -u usuarioprueba -p Password123! --shares
crackmapexec smb 192.168.56.20 -u usuarioprueba -p Password123! --users
nmap -p 445 192.168.56.0/24 --open
crackmapexec winrm 192.168.56.20 -u usuarioprueba -p Password123!
```

### Recursos comprometidos

| Recurso | Riesgo |
|---|---|
| ADMIN$ | Acceso total al sistema |
| C$ | Acceso completo al disco |
| SYSVOL | Políticas de dominio expuestas |
| NETLOGON | Scripts de inicio de sesión |

**Usuarios del dominio enumerados (14):**  
`ksepulveda`, `klopez`, `analista1`, `analista2`, `soc1`, `soc2`, `chefsito`, `anime1`, `anime2`, `Administrador`, `krbtgt`, `Invitado`, `usuarioprueba`, `usuarionpreuba`

### Evidencia Wazuh

| EventID | Cantidad | Significado |
|---|---|---|
| 4624 | 125+ | Logins exitosos desde Kali |
| 5140 | ~15 | Accesos a ADMIN$, C$, SYSVOL |
| 4625 | 0 | Sin intentos fallidos (credenciales correctas) |

**Técnicas MITRE detectadas:** T1078, T1135, T1087, T1046, T1021

### Recomendaciones

- 🔴 Bloquear IP atacante en firewall inmediatamente
- 🔴 Deshabilitar WinRM si no es operacionalmente necesario
- 🔴 Restringir enumeración anónima de usuarios
- 🟡 Implementar segmentación de red
- 🟡 Rotar contraseñas de cuentas expuestas

---

## INC-004 · Escalada de privilegios

**Ticket:** INC-004  
**Fecha:** 17 de junio de 2026 · 21:22:37  
**Severidad:** 🔴 Crítica  
**Estado:** ✅ Cerrado  
**MITRE:** T1098 — Account Manipulation

### Descripción

Se detectó la creación de una cuenta no autorizada (`hackersoc`) y su posterior adición a grupos de privilegios máximos del dominio, incluyendo Domain Admins y Administradores locales. La cuenta obtuvo acceso administrativo completo al dominio `soc.local`.

**Comandos ejecutados:**
```powershell
net user hackersoc Password123! /add /domain
net localgroup Administradores hackersoc /add
net group "Domain Admins" hackersoc /add /domain
```

### Cronología del ataque

```
21:16:06 → EventID 4672 — Privilegios especiales asignados al Administrador
21:22:37 → EventID 4720 — Cuenta hackersoc CREADA
21:23:48 → EventID 4732 — hackersoc agregado a Administradores locales ⚠️
21:35:55 → EventID 4728 — hackersoc agregado a Domain Admins 🚨
22:06:37 → EventID 4726 — Cuenta hackersoc eliminada (contención) ✅
```

### Privilegios obtenidos

`SeSecurityPrivilege` · `SeTakeOwnershipPrivilege` · `SeLoadDriverPrivilege` · `SeBackupPrivilege` · `SeRestorePrivilege` · `SeDebugPrivilege` · `SeImpersonatePrivilege` · `SeEnableDelegationPrivilege`

### Evidencia Wazuh

| EventID | Descripción | Nivel | Hora |
|---|---|---|---|
| 4720 | Cuenta hackersoc creada | — | 21:22:37 |
| 4732 | Agregado a Administradores locales | 🔴 12 (Crítico) | 21:23:48 |
| 4728 | Agregado a Domain Admins | — | 21:35:55 |
| 4672 | Privilegios especiales asignados | — | 21:16:06 |
| 4726 | Cuenta eliminada (contención) | — | 22:06:37 |

**Técnicas MITRE:** T1136, T1078, T1098, T1484, T1531

### Acciones de contención

```powershell
net user hackersoc /delete
net group "Domain Admins" hackersoc /delete /domain
net localgroup Administradores hackersoc /delete
# Verificado en Wazuh con EventID 4726 ✅
```

### Recomendaciones

- 🔴 Auditar TODOS los grupos de administradores del dominio
- 🔴 Alertas automáticas para EventID 4728 nivel CRÍTICO
- 🟡 Principio de mínimo privilegio en todas las cuentas
- 🟡 MFA obligatorio para cuentas administrativas

---

## INC-005 · Persistencia / Backdoor

**Ticket:** INC-005  
**Fecha:** 18 de junio de 2026 · 20:00:00  
**Severidad:** 🔴 Crítica  
**Estado:** ✅ Cerrado  
**MITRE:** T1543.003 — Windows Service

### Descripción

Se detectó la instalación de **4 mecanismos de persistencia simultáneos** en el servidor Windows. El atacante creó un script malicioso camuflado como servicio legítimo de Windows para garantizar acceso continuo aunque fuera detectado.

### Mecanismos de persistencia detectados

| Capa | Tipo | Detalle |
|---|---|---|
| 1 | Archivo malicioso | `C:\Windows\System32\backdoor.ps1` (32 bytes) |
| 2 | Servicio falso | `WindowsUpdateHelper` — Display: "Windows Update Helper" — Inicio: Automático — Cuenta: LocalSystem |
| 3 | Tarea programada | `WindowsSecurityUpdate` — Trigger: AtStartup — Nivel: Highest |
| 4 | Clave de registro | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\SecurityHelper` |

**Comandos ejecutados:**
```powershell
# Capa 1 - Archivo
New-Item -Path "C:\Windows\System32\backdoor.ps1" -ItemType File -Value "# Backdoor simulado para lab SOC"

# Capa 2 - Servicio
New-Service -Name "WindowsUpdateHelper" -BinaryPathName "C:\Windows\System32\backdoor.ps1" -DisplayName "Windows Update Helper" -StartupType Automatic

# Capa 3 - Tarea programada
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File C:\Windows\System32\backdoor.ps1"
$trigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -TaskName "WindowsSecurityUpdate" -Action $action -Trigger $trigger -RunLevel Highest -Force

# Capa 4 - Registro
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHelper" -Value "C:\Windows\System32\backdoor.ps1" -PropertyType String -Force
```

### Cronología

```
20:00:00 → backdoor.ps1 creado en System32         → FIM alerta (Syscheck)
20:00:30 → Servicio WindowsUpdateHelper instalado  → EventID 7045
20:01:00 → Tarea WindowsSecurityUpdate creada      → EventID 4698
20:01:30 → Registro SecurityHelper modificado      → FIM Registry alerta
20:55:06 → Archivo de tareas modificado            → EventID 550 - Syscheck
21:00:00 → Analista detecta y contiene             ✅
```

### Evidencia Wazuh

| EventID / Regla | Descripción | Nivel | MITRE |
|---|---|---|---|
| FIM Syscheck (550) | backdoor.ps1 detectado en System32 | 7 | T1036 |
| 7045 / Regla 61138 | WindowsUpdateHelper instalado | 5 | T1543.003 |
| 4698 | WindowsSecurityUpdate creada | — | T1053.005 |
| FIM Registry (4657) | SecurityHelper en Run | — | T1547.001 |
| 550 | Archivo Tasks modificado | 7 | T1565.001 |

**Configuración FIM aplicada:**
```xml
<agent_config>
  <syscheck>
    <directories check_all="yes" realtime="yes">C:\Windows\System32</directories>
    <directories check_all="yes" realtime="yes">C:\Windows\System32\Tasks</directories>
    <registry_check>
      <registry>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</registry>
    </registry_check>
  </syscheck>
</agent_config>
```

### Acciones de contención

```powershell
Remove-Item "C:\Windows\System32\backdoor.ps1" -Force
Stop-Service "WindowsUpdateHelper" -Force
sc.exe delete "WindowsUpdateHelper"
Unregister-ScheduledTask -TaskName "WindowsSecurityUpdate" -Confirm:$false
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHelper" -Force
# Verificado en Wazuh FIM ✅
```

### Recomendaciones

- 🔴 Auditar todos los servicios instalados en el sistema
- 🔴 Revisar todas las tareas programadas en busca de nombres sospechosos
- 🔴 Auditar claves de registro Run/RunOnce en HKLM y HKCU
- 🟡 Implementar Application Whitelisting
- 🟡 Alertas automáticas para EventID 7045 y 4698

---

## 🔍 Threat Hunting — Día 6 (Sábado)

**Tipo:** Proactive Threat Hunting  
**Fecha:** 20 de junio de 2026  
**Hipótesis ejecutadas:** 7

| Hipótesis | Resultado |
|---|---|
| H1 — Logins en horario inusual (00:00–06:00) | ⚠️ 1 login detectado a las 02:23 AM — usuario `kels` — IP `192.168.1.105` |
| H2 — Cuentas que no deberían loguearse (Invitado, krbtgt) | ✅ 0 eventos — Sin ataque Golden Ticket |
| H3 — Servicios con ejecutables sospechosos | ❌ `LogService` → `backdoor.ps1` en perfil de usuario |
| H4 — Scripts PowerShell en rutas inusuales | ❌ `C:\Users\kels\backdoor.ps1` · `C:\Windows\Temp\temp_install.ps1` |
| H5 — Modificaciones en Registro Run | ❌ `SecurityHelper` → `backdoor.ps1` — 02:23 AM |
| H6 — FIM — Integridad de archivos | ✅ 77 eventos syscheck · hash MD5 cambió: `ffab8f → a6a582` |
| H7 — MITRE ATT&CK tácticas de la semana | Initial Access: 2 · Persistence: 3 · Priv. Escalation: 1 · Defense Evasion: 2 |

---

## 🛡️ Reglas personalizadas Wazuh

Creadas el 20 de junio de 2026 en `/var/ossec/etc/rules/local_rules.xml`:

| Regla | EventID | Detecta | Nivel |
|---|---|---|---|
| 100001 | 7045 | Servicio instalado con script `.ps1` | 12 — Alto |
| 100002 | 4728 | Usuario agregado a Domain Admins | 15 — Crítico |
| 100003 | 60122 | 5+ logins fallidos en 2 minutos (fuerza bruta) | 14 — Alto |
| 100004 | syscheck | Archivo `.ps1` creado en System32 | 12 — Alto |
| 100005 | 4720 | Nueva cuenta de usuario creada | 10 — Medio |

```xml
<group name="cybercorp,windows,persistence,">

  <!-- REGLA 100001 — Servicio con .ps1 -->
  <rule id="100001" level="12">
    <if_group>windows</if_group>
    <field name="win.system.eventID">^7045$</field>
    <field name="win.eventdata.imagePath">\.ps1$</field>
    <description>CYBERCORP ALERTA: Servicio instalado con script PowerShell - Posible backdoor</description>
    <mitre><id>T1543.003</id></mitre>
  </rule>

  <!-- REGLA 100002 — Usuario a Domain Admins -->
  <rule id="100002" level="15">
    <if_group>windows</if_group>
    <field name="win.system.eventID">^4728$</field>
    <description>CYBERCORP CRITICO: Usuario agregado a grupo privilegiado - Posible escalada</description>
    <mitre><id>T1098</id></mitre>
  </rule>

  <!-- REGLA 100003 — Fuerza bruta -->
  <rule id="100003" level="14" frequency="5" timeframe="120">
    <if_matched_sid>60122</if_matched_sid>
    <same_field>win.eventdata.targetUserName</same_field>
    <description>CYBERCORP ALERTA: Multiples logins fallidos - Posible fuerza bruta</description>
    <mitre><id>T1110</id></mitre>
  </rule>

  <!-- REGLA 100004 — .ps1 en System32 -->
  <rule id="100004" level="12">
    <if_group>syscheck</if_group>
    <field name="syscheck.path">C:\\Windows\\System32\\.*\.ps1$</field>
    <field name="syscheck.event">added</field>
    <description>CYBERCORP ALERTA: Script PowerShell creado en System32 - Investigar inmediatamente</description>
    <mitre><id>T1036</id></mitre>
  </rule>

  <!-- REGLA 100005 — Cuenta nueva creada -->
  <rule id="100005" level="10">
    <if_group>windows</if_group>
    <field name="win.system.eventID">^4720$</field>
    <description>CYBERCORP ALERTA: Nueva cuenta de usuario creada - Verificar autorizacion</description>
    <mitre><id>T1136</id></mitre>
  </rule>

</group>
```

---

## 📚 Referencia rápida — EventIDs clave

| EventID | Significado | Severidad SOC |
|---|---|---|
| 4624 | Login exitoso (Logon Success) | Depende del contexto |
| 4625 | Login fallido (Logon Failure) | Media–Alta si es repetido |
| 4672 | Privilegios especiales asignados | Alta |
| 4698 | Tarea programada creada | Alta |
| 4699 | Tarea programada eliminada | Media |
| 4720 | Cuenta nueva creada | Alta |
| 4722 | Cuenta habilitada | Media |
| 4726 | Cuenta eliminada | Media |
| 4728 | Agregado a grupo global (Domain Admins) | Alta |
| 4732 | Agregado a grupo local (Administradores) | Alta |
| 4740 | Cuenta bloqueada | Alta |
| 4657 | Modificación de objeto del Registro | Alta |
| 5140 | Acceso a recurso compartido de red | Media |
| 7045 | Nuevo servicio instalado | Alta |

---

## 📂 Estructura de archivos

```
incident-reports/
├── README.md                  ← este archivo
├── INC-001-reconocimiento.md
├── INC-001-reconocimiento.pdf
├── INC-002-fuerza-bruta.md
├── INC-002-fuerza-bruta.pdf
├── INC-003-movimiento-lateral.md
├── INC-003-movimiento-lateral.pdf
├── INC-004-escalada-privilegios.md
├── INC-004-escalada-privilegios.pdf
├── INC-005-persistencia-backdoor.md
├── INC-005-persistencia-backdoor.pdf
├── informe-semanal-SOC-2026-001.md
├── informe-semanal-SOC-2026-001.pdf
└── wazuh-custom-rules-100001-100005.xml
```

---

## 🔗 Contexto del repositorio

Este directorio es parte del repositorio [`soc-homelab-detections`](../README.md).  
Los reportes fueron generados durante la simulación de una semana laboral completa como SOC Analyst Nivel 1, siguiendo el framework **NIST SP 800-61** para respuesta a incidentes.

**Herramientas utilizadas:** Wazuh · Nmap · CrackMapExec · smbclient · Hydra · PowerShell  
**Framework de referencia:** MITRE ATT&CK · NIST SP 800-61

---

*Documento clasificado como CONFIDENCIAL — Uso exclusivo del equipo SOC — CyberCorp S.A.*  
*Analista: Katalina Sepúlveda López · Período: 09–20 de junio de 2026*