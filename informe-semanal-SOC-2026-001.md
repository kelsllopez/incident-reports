# Informe Semanal SOC — SOC-WEEKLY-2026-001

**Clasificación:** CONFIDENCIAL — USO INTERNO  
**Documento:** SOC-WEEKLY-2026-001  
**Período analizado:** 09 al 20 de junio de 2026  
**Analista:** Katalina Sepúlveda López  
**Rol:** Analista SOC Nivel 1  
**SIEM utilizado:** Wazuh 4.7.5  
**Infraestructura:** Windows Server 2022 (soc.local)  

---

## Resumen ejecutivo

Durante la semana del 09 al 20 de junio de 2026 se detectaron, analizaron y contuvieron **5 incidentes de seguridad** de diversa severidad en la infraestructura de CyberCorp S.A. Los incidentes siguieron una **cadena de ataque progresiva** que comenzó con reconocimiento de red y escalonó hasta técnicas avanzadas de persistencia. Todos los incidentes fueron contenidos exitosamente sin compromisos confirmados de datos.

| Métrica | Valor |
|---|---|
| Estado final de la semana | 🟢 CONTENIDO |
| Incidentes detectados | 5 |
| Incidentes contenidos | 5 (100%) |
| Compromisos de datos | 0 |
| Agentes monitoreados | 1 (WindowsServer) |
| Reglas personalizadas creadas | 5 |
| Técnicas MITRE documentadas | 15+ |
| Eventos totales analizados | 1,000+ |
| EventIDs estudiados | 12 |
| Hipótesis de hunting ejecutadas | 7 |

---

## Infraestructura monitoreada

**Red interna:** `192.168.56.0/24`

| Activo | IP | Rol |
|---|---|---|
| kels-VirtualBox | 192.168.56.10 | SIEM Wazuh |
| WIN-J36GU3SVEOC | 192.168.56.20 | Windows Server 2022 |
| kali-linux | 192.168.56.30 | Atacante (lab) |

**Dominio:** soc.local  
**Agente Wazuh:** ID 001 — WindowsServer v4.14.5  
**Sistema operativo:** Windows Server 2022 Standard (Build 20348)

---

## Incidente #001 — Reconocimiento de red

| Campo | Valor |
|---|---|
| Ticket | INC-001 |
| Fecha | 09 de junio de 2026 |
| Hora | Turno matutino |
| Severidad | 🟡 Baja |
| Estado | ✅ Cerrado |
| MITRE | T1046 — Network Service Scanning |

**Descripción:** Se detectó actividad de escaneo de red desde `192.168.56.30` (Kali Linux) hacia toda la subred `192.168.56.0/24`. El escaneo identificó activos activos, puertos abiertos y versiones de servicios expuestos en el servidor Windows.

**Puertos detectados en 192.168.56.20:**

| Puerto | Estado | Servicio |
|---|---|---|
| 53/tcp | OPEN | DNS — Simple DNS Plus |
| 80/tcp | OPEN | HTTP — Microsoft IIS 10.0 |
| 135/tcp | OPEN | MSRPC — Microsoft Windows RPC |
| 139/tcp | OPEN | NetBIOS Session Service |
| 445/tcp | OPEN | SMB — Microsoft-DS |
| 5985/tcp | OPEN | WinRM — Windows Remote Mgmt |

- SMB Signing: habilitado pero NO obligatorio ⚠️
- HTTP TRACE: habilitado ⚠️

**Recomendaciones:**
- 🔴 Deshabilitar HTTP TRACE en IIS
- 🔴 Hacer obligatorio SMB Signing
- 🟡 Restringir WinRM a IPs autorizadas
- 🟡 Revisar necesidad de NetBIOS (puerto 139)

---

## Incidente #002 — Ataque de fuerza bruta

| Campo | Valor |
|---|---|
| Ticket | INC-002 |
| Fecha | 11 de junio de 2026 |
| Hora | 16:32:44 |
| Severidad | 🔴 Alta |
| Estado | ✅ Cerrado |
| MITRE | T1110 — Brute Force |

**Descripción:** Se detectaron múltiples intentos de autenticación fallidos contra el servicio SMB del servidor Windows. El atacante utilizó herramientas automatizadas desde `192.168.56.30` para intentar adivinar credenciales del usuario `usuarioprueba`.

**Evidencia Wazuh:**

| Campo | Valor |
|---|---|
| Regla disparada | 60122 — Logon Failure |
| EventID | 4625 — Login Fallido |
| Nivel Wazuh | 5 |
| IP atacante | 192.168.56.30 (Kali Linux) |
| Usuario objetivo | usuarioprueba |
| Intentos | 20+ en menos de 2 minutos |
| Resultado | Ataque fallido — Sin acceso |

**Recomendaciones:**
- 🔴 Bloquear IP 192.168.56.30 en firewall
- 🔴 Configurar Account Lockout Policy (5 intentos)
- 🟡 Cambiar contraseña de `usuarioprueba`
- 🟡 Implementar alerta automática para 5+ EventID 4625

---

## Incidente #003 — Movimiento lateral

| Campo | Valor |
|---|---|
| Ticket | INC-003 |
| Fecha | 11 de junio de 2026 |
| Hora | 21:44:00 |
| Severidad | 🔴 Alta |
| Estado | ✅ Cerrado |
| MITRE | T1021 — Remote Services |

**Descripción:** El atacante utilizó credenciales válidas para conectarse al servidor Windows mediante SMB y WinRM. Se realizó enumeración de recursos compartidos, usuarios del dominio y escaneo de servicios. El atacante obtuvo acceso a recursos administrativos críticos.

**Cronología:**
```
21:44:00 → Enumeración SMB iniciada
21:44:30 → Recursos compartidos enumerados
21:44:45 → 14 usuarios del dominio expuestos
21:44:50 → Escaneo nmap puerto 445 red completa
21:45:00 → Conexión WinRM exitosa
21:50–21:54 → Wazuh registra 125+ eventos EventID 4624
```

**Recursos comprometidos:**

| Recurso | Riesgo |
|---|---|
| ADMIN$ | Acceso total al sistema |
| C$ | Acceso completo al disco |
| SYSVOL | Políticas de dominio expuestas |
| NETLOGON | Scripts de inicio de sesión |

**Usuarios enumerados del dominio soc.local:**  
`ksepulveda`, `klopez`, `analista1`, `analista2`, `soc1`, `soc2`, `chefsito`, `anime1`, `anime2`, `Administrador`, `krbtgt`, `Invitado`, `usuarioprueba`

**Evidencia Wazuh:**

| EventID | Cantidad | Significado |
|---|---|---|
| 4624 | 125+ | Logins exitosos desde Kali |
| 5140 | 15 | Accesos a ADMIN$, C$, SYSVOL |
| 4625 | 0 | Sin intentos fallidos |

**MITRE:** T1078, T1135, T1087, T1046, T1021

**Recomendaciones:**
- 🔴 Bloquear IP atacante en firewall inmediatamente
- 🔴 Deshabilitar WinRM si no es operacionalmente necesario
- 🔴 Restringir enumeración anónima de usuarios
- 🟡 Implementar segmentación de red
- 🟡 Rotar contraseñas de cuentas expuestas

---

## Incidente #004 — Escalada de privilegios

| Campo | Valor |
|---|---|
| Ticket | INC-004 |
| Fecha | 17 de junio de 2026 |
| Hora | 21:22:37 |
| Severidad | 🔴 Crítica |
| Estado | ✅ Cerrado |
| MITRE | T1098 — Account Manipulation |

**Descripción:** Se detectó la creación de una cuenta no autorizada `hackersoc` y su posterior adición a grupos de privilegios máximos del dominio, incluyendo Domain Admins y Administradores locales.

**Cronología:**
```
21:16:06 → EventID 4672 — Privilegios especiales asignados
21:22:37 → EventID 4720 — Cuenta hackersoc CREADA
21:23:48 → EventID 4732 — Agregado a Administradores ⚠️  [Nivel 12]
21:35:55 → EventID 4728 — Agregado a Domain Admins 🚨
22:06:37 → EventID 4726 — Cuenta eliminada (contención) ✅
```

**Privilegios obtenidos:** `SeSecurityPrivilege`, `SeTakeOwnershipPrivilege`, `SeLoadDriverPrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege`, `SeDebugPrivilege`, `SeImpersonatePrivilege`, `SeEnableDelegationPrivilege`

**Acciones de contención:**
- ✅ Cuenta `hackersoc` eliminada
- ✅ Removida de Domain Admins
- ✅ Removida de Administradores locales
- ✅ Contención verificada en Wazuh (EventID 4726)

**MITRE:** T1136, T1078, T1098, T1484, T1531

**Recomendaciones:**
- 🔴 Auditar TODOS los grupos de administradores
- 🔴 Alertas automáticas para EventID 4728 nivel CRÍTICO
- 🟡 Principio de mínimo privilegio en todas las cuentas
- 🟡 MFA obligatorio para cuentas administrativas

---

## Incidente #005 — Persistencia / Backdoor

| Campo | Valor |
|---|---|
| Ticket | INC-005 |
| Fecha | 18 de junio de 2026 |
| Hora | 20:00:00 |
| Severidad | 🔴 Crítica |
| Estado | ✅ Cerrado |
| MITRE | T1543.003 — Windows Service |

**Descripción:** Se detectó la instalación de 4 mecanismos de persistencia en el servidor Windows. El atacante creó un script malicioso camuflado como servicio legítimo de Windows, una tarea programada de inicio automático y una clave de registro de ejecución automática.

**Mecanismos detectados:**

| Capa | Tipo | Nombre |
|---|---|---|
| 1 | Archivo malicioso | `C:\Windows\System32\backdoor.ps1` |
| 2 | Servicio falso | `WindowsUpdateHelper` — Inicio Automático — LocalSystem |
| 3 | Tarea programada | `WindowsSecurityUpdate` — AtStartup — Highest |
| 4 | Clave de registro | `HKLM\...\Run\SecurityHelper` |

**Cronología:**
```
20:00:00 → backdoor.ps1 creado en System32  → FIM alerta
20:00:30 → Servicio WindowsUpdateHelper     → EventID 7045
20:01:00 → Tarea WindowsSecurityUpdate      → EventID 4698
20:01:30 → Registro SecurityHelper          → FIM Registry
20:55:06 → Archivo Tasks modificado         → EventID 550
21:00:00 → Analista detecta y contiene ✅
```

**Evidencia Wazuh:**

| EventID | Descripción | Nivel | MITRE |
|---|---|---|---|
| FIM 550 | backdoor.ps1 en System32 | 7 | T1036 |
| 7045 / Regla 61138 | Servicio instalado | 5 | T1543.003 |
| 4698 | Tarea creada | — | T1053.005 |
| 4657 FIM | Registro modificado | — | T1547.001 |
| 550 | Tasks modificado | 7 | T1565.001 |

**Acciones de contención:**
- ✅ `backdoor.ps1` eliminado de System32
- ✅ Servicio `WindowsUpdateHelper` eliminado
- ✅ Tarea `WindowsSecurityUpdate` eliminada
- ✅ Clave `SecurityHelper` eliminada del Registro
- ✅ Contención verificada en Wazuh FIM

**Recomendaciones:**
- 🔴 Auditar todos los servicios instalados
- 🔴 Revisar todas las tareas programadas
- 🔴 Auditar claves Run/RunOnce completas
- 🟡 Implementar Application Whitelisting
- 🟡 Alertas automáticas EventID 7045

---

## Threat Hunting — Semana completa

**Tipo:** Proactive Threat Hunting  
**Fecha:** 20 de junio de 2026  
**Hipótesis ejecutadas:** 7

| Hipótesis | Resultado |
|---|---|
| H1 — Logins horario inusual (00:00–06:00) | ⚠️ 1 login a las 02:23 AM — usuario `kels` — IP `192.168.1.105` |
| H2 — Cuentas que no deberían loguearse | ✅ 0 eventos Invitado · 0 eventos krbtgt — Sin Golden Ticket |
| H3 — Servicios con ejecutables sospechosos | ❌ `LogService` → `backdoor.ps1` en perfil usuario |
| H4 — Scripts PowerShell en rutas inusuales | ❌ `C:\Users\kels\backdoor.ps1` · `C:\Windows\Temp\temp_install.ps1` |
| H5 — Modificaciones en Registro Run | ❌ `SecurityHelper` → `backdoor.ps1` — 02:23 AM |
| H6 — FIM — Integridad de archivos | ✅ 77 eventos syscheck · hash MD5 cambió `ffab8f → a6a582` |
| H7 — MITRE ATT&CK tácticas de la semana | Initial Access: 2 · Persistence: 3 · Priv. Escalation: 1 · Defense Evasion: 2 |

---

## Reglas personalizadas Wazuh creadas

**Archivo:** `/var/ossec/etc/rules/local_rules.xml`

| Regla | EventID | Detecta | Nivel |
|---|---|---|---|
| 100001 | 7045 | Servicio instalado con `.ps1` | 12 — Alto |
| 100002 | 4728 | Usuario agregado a Domain Admins | 15 — Crítico |
| 100003 | 60122 | 5+ logins fallidos en 2 minutos | 14 — Alto |
| 100004 | syscheck | Archivo `.ps1` creado en System32 | 12 — Alto |
| 100005 | 4720 | Nueva cuenta de usuario creada | 10 — Medio |

---

## Análisis de la cadena de ataque

El atacante siguió una cadena progresiva y planificada durante toda la semana:

```
ETAPA 1 — Reconocimiento
  Nmap → identificó puertos y servicios expuestos
  Vector de entrada: SMB puerto 445

ETAPA 2 — Acceso inicial
  Fuerza bruta SMB → credenciales usuarioprueba:Password123!
  Herramienta: smbclient + intentos manuales

ETAPA 3 — Movimiento lateral
  CrackMapExec → enumeró shares y usuarios
  WinRM → acceso remoto al servidor
  14 cuentas del dominio expuestas

ETAPA 4 — Escalada de privilegios
  Cuenta hackersoc → Domain Admins
  Acceso administrativo total al dominio

ETAPA 5 — Persistencia
  4 capas de backdoor instaladas
  Objetivo: sobrevivir a cambio de contraseñas
```

**Vector común en todos los ataques:**

| Campo | Valor |
|---|---|
| IP atacante | 192.168.56.30 (constante) |
| Credenciales usadas | `usuarioprueba:Password123!` |
| Horario de ataques | 16:00 — 22:00 hrs |

---

## Recomendaciones finales

### 🔴 Crítico — Acción inmediata
1. Bloquear permanentemente IP 192.168.56.30
2. Cambiar TODAS las contraseñas del dominio
3. Auditar grupos administrativos completos
4. Revisar servicios y tareas programadas
5. Implementar MFA en cuentas admin

### 🟡 Importante — Esta semana
6. Hacer obligatorio SMB Signing
7. Deshabilitar WinRM si no es necesario
8. Implementar Account Lockout Policy
9. Restringir enumeración de usuarios AD
10. Configurar Application Whitelisting

### 🟢 Recomendado — Próximo mes
11. Segmentación de red por VLANs
12. Capacitación en phishing para usuarios
13. Pentesting trimestral de infraestructura
14. Implementar LAPS para contraseñas locales
15. Revisar política de acceso remoto

---

## Métricas de la semana

| Métrica | Valor |
|---|---|
| Incidentes detectados | 5 |
| Incidentes contenidos | 5 (100%) |
| Tiempo promedio de detección | < 5 min |
| Compromisos de datos | 0 |
| Agentes monitoreados | 1 |
| Reglas personalizadas creadas | 5 |
| Técnicas MITRE documentadas | 15+ |
| Eventos totales analizados | 1,000+ |
| EventIDs estudiados | 12 |
| Hipótesis de hunting ejecutadas | 7 |

---

## Conclusión

La semana representó una simulación completa de un ciclo de ataque real, desde reconocimiento inicial hasta persistencia avanzada. El equipo SOC demostró capacidad de detección, análisis y contención en todos los escenarios presentados.

El servidor Windows Server 2022 presenta múltiples superficies de ataque que deben ser endurecidas según las recomendaciones indicadas.

La implementación de las reglas personalizadas CYBERCORP (100001–100005) mejora la capacidad de detección para ataques futuros similares, reduciendo el tiempo de respuesta.

---

## Cierre formal

| Campo | Valor |
|---|---|
| Estado de todos los incidentes | CERRADOS ✅ |
| Tickets abiertos | NINGUNO |
| Escalamientos pendientes | NINGUNO |
| Próxima revisión | 27/06/2026 |
| Próximo threat hunting | 27/06/2026 |

---

**Firma del Analista:**  
Katalina Sepúlveda López — Analista SOC Nivel 1 — CyberCorp S.A.  
20 de junio de 2026

**Revisado por:**  
[SOC Team Lead] — CyberCorp S.A. — 20 de junio de 2026

---

*DOCUMENTO CLASIFICADO COMO CONFIDENCIAL*  
*Uso exclusivo del equipo SOC — CyberCorp S.A.*  
*Prohibida su distribución sin autorización*
