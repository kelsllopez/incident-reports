# INC-003 — Movimiento Lateral

**Ticket:** INC-003  
**Fecha:** 11 de junio de 2026 · 21:44:00  
**Analista:** Katalina Sepúlveda López  
**Severidad:** 🔴 Alta  
**Estado:** ✅ Cerrado  
**MITRE:** T1021 — Remote Services  
**SIEM:** Wazuh 4.7.5  

---

## Descripción

El atacante utilizó credenciales válidas (`usuarioprueba:Password123!`) obtenidas previamente para conectarse al servidor Windows mediante SMB y WinRM. Se realizó enumeración completa de recursos compartidos, usuarios del dominio y escaneo de servicios. El atacante obtuvo acceso a recursos administrativos críticos incluyendo ADMIN$, C$, SYSVOL y NETLOGON.

---

## Infraestructura afectada

| Activo | IP | Sistema | Rol |
|---|---|---|---|
| WIN-J36GU3SVEOC | 192.168.56.20 | Windows Server 2022 | Víctima — Controlador de Dominio |
| kali-linux | 192.168.56.30 | Kali Linux | Atacante |

---

## Cronología del ataque

```
21:44:00 → Kali inició enumeración SMB con credenciales válidas
21:44:30 → Enumeración de recursos compartidos (ADMIN$, C$, SYSVOL, NETLOGON)
21:44:45 → Enumeración de 14 usuarios del dominio soc.local
21:44:50 → Escaneo de red con nmap -p 445 buscando otros hosts SMB
21:45:00 → Verificación de WinRM — autenticación exitosa [~]
21:50–21:54 → Wazuh registra 125+ eventos EventID 4624
```

---

## Comandos ejecutados por el atacante

```bash
# Paso 1 — Verificar herramientas
which crackmapexec
which smbclient

# Paso 2 — Enumerar recursos compartidos SMB
crackmapexec smb 192.168.56.20 -u usuarioprueba -p Password123! --shares

# Paso 3 — Listar usuarios del dominio
crackmapexec smb 192.168.56.20 -u usuarioprueba -p Password123! --users

# Paso 4 — Escanear red buscando SMB abierto
nmap -p 445 192.168.56.0/24 --open

# Paso 5 — Intentar conexión WinRM
crackmapexec winrm 192.168.56.20 -u usuarioprueba -p Password123!
```

---

## Recursos compartidos comprometidos

| Recurso | Permisos | Riesgo |
|---|---|---|
| ADMIN$ | Admin remota | 🔴 Acceso total al sistema |
| C$ | Recurso predeterminado | 🔴 Acceso completo al disco |
| IPC$ | IPC remota | 🟡 Enumeración |
| NETLOGON | Scripts de inicio de sesión | 🔴 Políticas expuestas |
| SYSVOL | Políticas de dominio | 🔴 Políticas de dominio expuestas |

---

## Usuarios del dominio enumerados (14)

```
soc.local\anime2
soc.local\anime1
soc.local\chefsito
soc.local\soc2
soc.local\soc1
soc.local\analista2
soc.local\analista1
soc.local\klopez
soc.local\ksepulveda
soc.local\krbtgt          ← cuenta crítica Kerberos
soc.local\usuarionpreuba  ← badpwdcount: 21
soc.local\Invitado
soc.local\Administrador   ← cuenta de máximos privilegios
soc.local\usuarioprueba   ← cuenta comprometida
```

---

## Evidencia Wazuh

| EventID | Cantidad | Significado |
|---|---|---|
| 4624 | 125+ | Logins exitosos desde Kali |
| 5140 | ~15 | Accesos a ADMIN$, C$, SYSVOL |
| 4625 | 0 | Sin intentos fallidos (credenciales correctas) |

**Regla activada:** 60106 — Windows Logon Success (Nivel 3)

**Filtros usados en Wazuh:**
```
data.win.system.eventID: 4624
192.168.56.30
```

**Resultado WinRM:**
```
SMB   192.168.56.20  5985  WIN-J36GU3SVEOC  [*] Windows Server 2022
HTTP  192.168.56.20  5985  WIN-J36GU3SVEOC  [*] http://192.168.56.20:5985/wsman
WINRM 192.168.56.20  5985  WIN-J36GU3SVEOC  [~] soc.local\usuarioprueba:Password123!
```
> `[~]` = autenticación exitosa. El atacante puede ejecutar comandos PowerShell remotamente.

---

## Indicadores de compromiso (IOC)

| IOC | Tipo | Valor |
|---|---|---|
| IP atacante | Dirección IP | 192.168.56.30 |
| Credenciales usadas | Cuenta | usuarioprueba:Password123! |
| Recursos accedidos | Shares | ADMIN$, C$, SYSVOL, NETLOGON |
| Usuarios expuestos | Cuentas dominio | 14 cuentas de soc.local |
| Puerto WinRM | Puerto | 5985 |

---

## Técnicas MITRE ATT&CK

| ID | Técnica | Descripción |
|---|---|---|
| T1078 | Valid Accounts | Uso de credenciales válidas de usuarioprueba |
| T1078.002 | Domain Accounts | Uso de cuenta de dominio soc.local |
| T1021 | Remote Services | Conexión remota via SMB y WinRM |
| T1135 | Network Share Discovery | Enumeración de recursos compartidos |
| T1087 | Account Discovery | Listado de 14 usuarios del dominio |
| T1046 | Network Service Scanning | Escaneo nmap puerto 445 en subred |

---

## Recomendaciones para Wazuh

| Prioridad | Acción |
|---|---|
| 🔴 Alta | Crear regla personalizada para logons desde IPs no autorizadas |
| 🔴 Alta | Aumentar rule.level para EventID 4624 + acceso a ADMIN$/C$ |
| 🟡 Media | Configurar alerta para enumeración de usuarios (EventID 4799) |
| 🟡 Media | Integrar feed de IPs maliciosas |

## Recomendaciones para la red

| Prioridad | Acción |
|---|---|
| 🔴 Alta | Bloquear IP 192.168.56.30 en firewall |
| 🔴 Alta | Cambiar contraseña de `usuarioprueba` |
| 🟡 Media | Deshabilitar WinRM (puerto 5985) si no es necesario |
| 🟡 Media | Restringir enumeración anónima de usuarios |
| 🟡 Media | Implementar segmentación de red |
| 🟢 Baja | Rotar contraseña de `krbtgt` (requiere planificación) |

---

## Cierre formal

| Campo | Valor |
|---|---|
| Estado | CONTENIDO ✅ |
| Ticket | INC-003 |
| Escalamiento | No requerido |
| Compromisos confirmados | Credenciales `usuarioprueba` — acceso a recursos admin |

---

**Próximo paso:** Día 4 — Escalada de privilegios  

**Firma:** Katalina Sepúlveda López — Analista SOC Nivel 1 — CyberCorp S.A.  
**Fecha:** 11 de junio de 2026
