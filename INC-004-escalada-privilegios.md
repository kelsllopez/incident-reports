# INC-004 — Escalada de Privilegios

**Ticket:** INC-004  
**Fecha:** 17 de junio de 2026 · 21:22:37  
**Analista:** Katalina Sepúlveda López  
**Severidad:** 🔴 Crítica  
**Estado:** ✅ Cerrado  
**MITRE:** T1098 — Account Manipulation  
**SIEM:** Wazuh 4.7.5  

---

## Descripción

Se detectó la creación de una cuenta no autorizada `hackersoc` y su posterior adición a grupos de privilegios máximos del dominio, incluyendo **Domain Admins** y **Administradores locales**. La cuenta obtuvo acceso administrativo completo al dominio `soc.local` con todos los privilegios de un administrador de dominio. La detección y contención se realizó exitosamente sin compromisos confirmados de datos.

---

## Infraestructura afectada

| Campo | Valor |
|---|---|
| Hostname | WIN-J36GU3SVEOC |
| Sistema | Windows Server 2022 Standard Evaluation |
| IP | 192.168.56.20 |
| Dominio | soc.local |
| Agente Wazuh | 001 — WindowsServer |

---

## Cronología del ataque

```
21:16:06 → EventID 4672 — Privilegios especiales asignados al Administrador
21:22:37 → EventID 4720 — Cuenta hackersoc CREADA
21:23:48 → EventID 4732 — hackersoc agregado a Administradores locales ⚠️  [Nivel 12]
21:35:55 → EventID 4728 — hackersoc agregado a Domain Admins 🚨
22:06:37 → EventID 4726 — Cuenta hackersoc ELIMINADA (contención) ✅
```

---

## Comandos ejecutados por el atacante

```powershell
# Paso 1 — Crear usuario sospechoso
net user hackersoc Password123! /add /domain

# Paso 2 — Agregar a Administradores locales
net localgroup Administradores hackersoc /add

# Paso 3 — Agregar a Domain Admins
net group "Domain Admins" hackersoc /add /domain

# Paso 4 — Verificar que quedó en el grupo
net user hackersoc
net localgroup Administradores

# Paso 5 — Simular actividad del nuevo admin
whoami /priv
net user hackersoc /domain
query user
```

---

## Privilegios obtenidos por hackersoc

```
SeSecurityPrivilege
SeTakeOwnershipPrivilege
SeLoadDriverPrivilege
SeBackupPrivilege
SeRestorePrivilege
SeDebugPrivilege
SeSystemEnvironmentPrivilege
SeEnableDelegationPrivilege
SeImpersonatePrivilege
SeDelegateSessionUserImpersonatePrivilege
```

---

## Evidencia Wazuh

### Búsqueda en Threat Hunting → Events

| EventID | Filtro Wazuh | Descripción | Hora | Nivel |
|---|---|---|---|---|
| 4672 | `data.win.system.eventID: 4672` | Privilegios especiales asignados | 21:16:06 | — |
| 4720 | `data.win.system.eventID: 4720` | Cuenta hackersoc creada | 21:22:37 | — |
| 4732 | `data.win.system.eventID: 4732` | Agregado a Administradores locales | 21:23:48 | 🔴 12 |
| 4728 | `data.win.system.eventID: 4728` | Agregado a Domain Admins | 21:35:55 | — |
| 4726 | `data.win.system.eventID: 4726` | Cuenta eliminada (contención) | 22:06:37 | — |

### Cadena de ataque identificada en Wazuh

```
hackersoc  →  búsqueda en Wazuh

21:16:06 → 4672 - Privilegios especiales (Administrador)
21:22:37 → 4720 - Cuenta hackersoc CREADA
21:23:48 → 4732 - Agregado a Administradores (LOCAL) ⚠️
21:35:55 → 4728 - Agregado a Domain Admins 🚨
22:06:37 → 4726 - Cuenta eliminada (contención) ✅
```

---

## Indicadores de compromiso (IOC)

| IOC | Tipo | Valor |
|---|---|---|
| Cuenta maliciosa | Username | hackersoc |
| Grupo comprometido | Grupo AD | Domain Admins |
| Grupo comprometido | Grupo local | Administradores (Builtin) |
| Actor | Cuenta ejecutora | Administrador |
| Host | Hostname | WIN-J36GU3SVEOC |

---

## Técnicas MITRE ATT&CK

| ID | Técnica | Descripción |
|---|---|---|
| T1136 | Create Account | Creación de cuenta `hackersoc` |
| T1078 | Valid Accounts | Uso de cuenta para obtener privilegios |
| T1098 | Account Manipulation | Agregar `hackersoc` a grupos admin |
| T1484 | Domain Policy Modification | Modificación de políticas del dominio |
| T1531 | Account Access Removal | Eliminación de cuenta (acción de contención) |

---

## Impacto potencial

- 🔴 Acceso administrativo total al dominio `soc.local`
- 🔴 Posible acceso a todos los equipos del dominio
- 🔴 Posible creación de backdoors adicionales
- 🔴 Capacidad de modificar políticas de seguridad
- 🔴 Capacidad de crear, modificar y eliminar usuarios

---

## Acciones de contención

```powershell
# Eliminar usuario malicioso
net user hackersoc /delete

# Remover de Domain Admins
net group "Domain Admins" hackersoc /delete /domain

# Remover de Administradores locales
net localgroup Administradores hackersoc /delete

# Verificar eliminación
net localgroup Administradores
net group "Domain Admins" /domain
```

**Verificación en Wazuh:**
```
data.win.system.eventID: 4726
→ Quién lo hizo: Administrador
→ Qué hizo: Eliminó usuario hackersoc
→ Cuándo: 22:06:37 UTC - 17/06/2026
→ Estado: AUDIT_SUCCESS ✅
→ MITRE: T1531 - Account Access Removal
```

---

## Tabla de EventIDs clave — Referencia día 4

| EventID | Qué significa | Severidad SOC |
|---|---|---|
| 4720 | Cuenta nueva creada | Alta |
| 4722 | Cuenta habilitada | Media |
| 4728 | Agregado a grupo global | Alta |
| 4732 | Agregado a grupo local | Alta |
| 4672 | Privilegios especiales | Alta |
| 4726 | Cuenta eliminada | Media |
| 4740 | Cuenta bloqueada | Alta |

---

## Recomendaciones

### 🔴 Alta Prioridad
1. Auditar TODOS los grupos de administradores del dominio
2. Revisar si se crearon otras cuentas sospechosas
3. Cambiar contraseñas de cuentas privilegiadas

### 🟡 Media Prioridad
4. Implementar alerta automática para EventID 4728, 4732 y 4720
5. Principio de mínimo privilegio en todas las cuentas
6. Configurar monitoreo de cambios en grupos privilegiados

### 🟢 Baja Prioridad
7. Revisar política de contraseñas del dominio
8. Implementar MFA para cuentas administrativas

---

## Lecciones aprendidas

- La detección tardía permite al atacante crear persistencia
- EventID 4728 debe generar alerta nivel ALTO automáticamente
- Monitoreo de grupos privilegiados es crítico en cualquier entorno AD
- `ANONYMOUS LOGON` modificando cuentas es señal de alarma inmediata
- La cadena de ataque completa debe ser visible en el SIEM

---

## Cierre formal

| Campo | Valor |
|---|---|
| Estado | CONTENIDO ✅ |
| Ticket | INC-004 |
| Escalamiento | Reportado a SOC Tier 2 |
| Compromisos confirmados | 0 (cuenta eliminada antes de uso confirmado) |

---

**Firma:** Katalina Sepúlveda López — Analista SOC Nivel 1 — CyberCorp S.A.  
**Fecha:** 17 de junio de 2026
