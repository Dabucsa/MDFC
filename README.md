# 🚀 Azure Sentinel – Base Deployment

Este proyecto automatiza la creación de un **Log Analytics Workspace**, habilita **Microsoft Sentinel**, y conecta los **data connectors base gratuitos**:

- **Azure Activity Logs**
- **Microsoft Entra ID Protection (Identity Protection Alerts)**
- **Microsoft Defender for Cloud (Security Alerts)**
- **Microsoft Defender for Office 365 (Security Alerts)**

---

## 📋 Requisitos

Antes de desplegar, asegúrate de contar con:

- **Permisos en Azure** para:
  - Registrar el *provider* `Microsoft.OperationalInsights`
  - Permisos de Contributor / Owner en la suscripción
- **Tenant ID** de Microsoft Entra (Azure AD), ya que es necesario para los conectores de identidad.
- **Subscription ID** en la que quieres habilitar Defender for Cloud (por defecto usa la actual).
- **Azure CLI** (opcional, si quieres desplegar vía terminal).

---

## ⚙️ Parámetros principales

| Parámetro                 | Descripción                                                   | Default |
|----------------------------|---------------------------------------------------------------|---------|
| `lawName`                 | Nombre del Log Analytics Workspace                            | —       |
| `location`                | Región donde se creará el workspace                           | RG loc. |
| `retentionDays`           | Días de retención de logs                                     | `90`    |
| `enableAzureActivity`     | Habilitar Activity Logs                                       | `true`  |
| `enableIdentityProtection`| Habilitar conector de Entra ID Protection                     | `true`  |
| `tenantId`                | Tenant ID para Entra ID Protection y MDO                     | —       |
| `enableDefenderForCloud`  | Habilitar conector de Defender for Cloud                      | `true`  |
| `mdcSubscriptionId`       | Subscription ID de Defender for Cloud                         | actual  |
| `enableDefenderForOffice365` | Habilitar conector Defender for Office 365 (MDO)           | `true`  |
| `xdrIntegrated`           | Saltar conectores gestionados por XDR (Primary Workspace)     | `true`  |

---

## 🚀 Despliegue

Puedes desplegar directamente a tu suscripción con el botón azul:

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FDabucsa%2FMDFC%2Fmain%2Fdeploysentinel.json)

---

## 💻 Despliegue vía CLI

```bash
az deployment group create \
  --resource-group <RG_NAME> \
  --template-file main.json \
  --parameters lawName=<WORKSPACE_NAME> tenantId=<TENANT_ID>
