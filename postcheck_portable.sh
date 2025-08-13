#!/usr/bin/env bash
set -euo pipefail

# MDFC GCP post-check (Proyecto) - Versión portable
# Valida: APIs, WIF (pool/providers), SAs, bindings, roles custom, auditoría, OS Config
# Uso:
#   ./postcheck.sh -p <PROJECT_ID> -n <PROJECT_NUMBER> -t <ENTRA_TENANT_ID> [-w <WIF_POOL_ID>]
# Ejemplo:
#   ./postcheck.sh -p my-project -n 123456789012 -t 33e01921-4d64-4f8c-a055-5bdaffd5e33d
#
# Notas:
# - Si no pasas -w, el script intentará autodetectar el WIF Pool ID (primer pool encontrado en la org/proyecto).
# - El ENTRA_TENANT_ID se valida como GUID (UUID v4/v5 típico).
# - Todo el output se guarda en un log con timestamp en el nombre.

PROJECT_ID=""
PROJECT_NUMBER=""
WIF_POOL_ID=""
ENTRA_TENANT_ID=""
LOG="postcheck_$(date +%F_%H%M%S).log"

# Estilos de salida
ok()   { echo -e "\e[32m[ OK ]\e[0m $*"; }
warn() { echo -e "\e[33m[WARN]\e[0m $*"; }
bad()  { echo -e "\e[31m[FAIL]\e[0m $*"; }
note() { echo -e "\e[36m[NOTE]\e[0m $*"; }
info() { echo -e "\e[34m[INFO]\e[0m $*"; }

pass=0; fail=0; warnc=0; notes=0
mark_ok()   { ok "$@"; pass=$((pass+1)); }
mark_fail() { bad "$@"; fail=$((fail+1)); }
mark_warn() { warn "$@"; warnc=$((warnc+1)); }
mark_note() { note "$@"; notes=$((notes+1)); }

usage(){
  cat <<EOF
Uso: $0 -p PROJECT_ID -n PROJECT_NUMBER -t ENTRA_TENANT_ID [-w WIF_POOL_ID]
Ej:  $0 -p my-project -n 123456789012 -t 33e01921-4d64-4f8c-a055-5bdaffd5e33d
EOF
  exit 1
}

while getopts "p:n:w:t:h" o; do
  case "${o}" in
    p) PROJECT_ID="${OPTARG}";;
    n) PROJECT_NUMBER="${OPTARG}";;
    w) WIF_POOL_ID="${OPTARG}";;
    t) ENTRA_TENANT_ID="${OPTARG}";;
    h|*) usage;;
  esac
done

# Validaciones iniciales
[[ -z "$PROJECT_ID" || -z "$PROJECT_NUMBER" || -z "$ENTRA_TENANT_ID" ]] && usage
# Validar formato GUID del tenant
if [[ ! "$ENTRA_TENANT_ID" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
  bad "ENTRA_TENANT_ID no parece un GUID válido: $ENTRA_TENANT_ID"
  exit 1
fi

# Autodetección del WIF_POOL_ID si no se pasa
if [[ -z "$WIF_POOL_ID" ]]; then
  # Listar pools y tomar el primero (puedes ajustar el criterio si manejas varios)
  WIF_POOL_ID=$(gcloud iam workload-identity-pools list \
    --location=global --project "$PROJECT_ID" \
    --format="value(name)" | awk -F/ '{print $6}' | head -n1 || true)
  if [[ -z "$WIF_POOL_ID" ]]; then
    bad "No se pudo detectar automáticamente el WIF_POOL_ID. Pásalo con -w."
    exit 1
  fi
  note "WIF_POOL_ID autodetectado: $WIF_POOL_ID"
fi

# Iniciar log desde aquí
exec > >(tee -a "$LOG") 2>&1

info "Proyecto: $PROJECT_ID  (#$PROJECT_NUMBER)"
info "WIF Pool ID: $WIF_POOL_ID"
info "Entra Tenant ID (issuer esperado): $ENTRA_TENANT_ID"
echo

# ---------- Config esperada del onboarding ----------
REQ_APIS=(
  "iam.googleapis.com"
  "sts.googleapis.com"
  "cloudresourcemanager.googleapis.com"
  "iamcredentials.googleapis.com"
  "compute.googleapis.com"
  "apikeys.googleapis.com"
  "logging.googleapis.com"
  "serviceusage.googleapis.com"
  "osconfig.googleapis.com"
  "storage-component.googleapis.com"
  # Recomendadas/según uso:
  "pubsub.googleapis.com"
  "artifactregistry.googleapis.com"
  "containeranalysis.googleapis.com"
  "container.googleapis.com"
)

# Providers OIDC esperados -> audience
declare -A PROVIDERS
PROVIDERS=( \
  ["cspm"]="api://6e81e733-9e7f-474a-85f0-385c097f7f52" \
  ["containers"]="api://6610e979-c931-41ec-adc7-b9920c9d52f1" \
  ["containers-streams"]="api://2041288c-b303-4ca0-9076-9612db3beeb2" \
  ["defender-for-servers"]="api://AzureSecurityCenter.MultiCloud.DefenderForServers" \
  ["defender-for-databases-arc-ap"]="api://AzureSecurityCenter.MultiCloud.DefenderForServers" \
  ["data-security-posture-storage"]="api://2723a073-e7ed-4ff8-be05-88acda0c702e" \
  ["ciem-discovery"]="api://mciem-gcp-oidc-app" \
)

# attribute-condition recomendado por provider (solo CIEM en este check)
declare -A ATTR_COND
ATTR_COND=( \
  ["ciem-discovery"]="attribute.appid=='b46c3ac5-9da6-418f-a849-0a07a10b3c6c'" \
)

# Service Accounts creados/actualizados por el onboarding
SAS=(
  "microsoft-defender-cspm"
  "microsoft-defender-containers"
  "ms-defender-containers-stream"
  "microsoft-defender-for-servers"
  "microsoft-databases-arc-ap"
  "mdc-data-sec-posture-storage"
  "mdc-containers-k8s-operator"
  "mdc-containers-artifact-assess"
  "microsoft-defender-ciem"
)

# Roles custom esperados -> permisos clave (muestra mínima representativa)
declare -A CUSTOM_ROLES_PERMS
CUSTOM_ROLES_PERMS=(
  ["MDCCspmCustomRole"]="storage.buckets.getIamPolicy"
  ["MicrosoftDefenderContainersDataCollectionRole"]="pubsub.subscriptions.consume pubsub.subscriptions.get"
  ["MicrosoftDefenderContainersRole"]="logging.sinks.list logging.sinks.get logging.sinks.create logging.sinks.update logging.sinks.delete resourcemanager.projects.getIamPolicy iam.serviceAccounts.get iam.workloadIdentityPoolProviders.get"
  ["MDCAgentlessScanningRole"]="compute.disks.createSnapshot compute.instances.get"
  ["MDCDataSecurityPostureStorageRole"]="storage.objects.list storage.objects.get storage.buckets.get"
  ["MDCGkeClusterWriteRole"]="container.clusters.update"
  ["MDCGkeContainerResponseActionsRole"]="container.pods.update container.pods.delete container.networkPolicies.create container.networkPolicies.update container.networkPolicies.delete"
  ["MDCGkeContainerInventoryCollectionRole"]="container.nodes.proxy container.secrets.list"
  ["MDCWritingGarAssessmentsRole"]="artifactregistry.repositories.deleteArtifacts"
)

AGENTLESS_SA="mdc-agentless-scanning@guardians-prod-diskscanning.iam.gserviceaccount.com"
COMPUTE_SYSTEM_SA="service-220551266886@compute-system.iam.gserviceaccount.com"

PRINCIPAL_SET_POOL="principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${WIF_POOL_ID}/*"
ISSUER_URI_TENANT="https://sts.windows.net/${ENTRA_TENANT_ID}"
ISSUER_URI_POOL="https://sts.windows.net/${WIF_POOL_ID}"

# ---------- 1) APIs ----------
info "1) Comprobando APIs habilitadas…"
enabled=$(gcloud services list --enabled --project "$PROJECT_ID" --format="value(config.name)" || true)
for api in "${REQ_APIS[@]}"; do
  if echo "$enabled" | grep -qx "$api"; then
    mark_ok "API habilitada: $api"
  else
    mark_warn "API NO habilitada (recomendado habilitar): $api  ->  gcloud services enable $api --project $PROJECT_ID"
  fi
done
echo

# ---------- 2) WIF: Pool & Providers ----------
info "2) Comprobando Workload Identity Pool y Providers…"
pool_path="projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${WIF_POOL_ID}"
if gcloud iam workload-identity-pools describe "$pool_path" >/dev/null 2>&1; then
  mark_ok "WIF Pool existe: $pool_path"
else
  mark_fail "No existe WIF Pool: $pool_path"
fi

for prov in "${!PROVIDERS[@]}"; do
  aud="${PROVIDERS[$prov]}"

  # issuerUri
  issuer=$(gcloud iam workload-identity-pools providers describe "$prov" \
    --location=global --workload-identity-pool="$WIF_POOL_ID" \
    --project="$PROJECT_ID" --format='value(oidc.issuerUri)' 2>/dev/null || echo "")
  if [[ -z "$issuer" ]]; then
    mark_fail "[$prov] no se pudo leer issuerUri (provider podría no existir o falta permiso)"
  else
    if [[ "$issuer" == "$ISSUER_URI_TENANT" ]]; then
      mark_ok "[$prov] issuerUri apunta al Tenant ID de Entra ($ENTRA_TENANT_ID)"
    elif [[ "$issuer" == "$ISSUER_URI_POOL" ]]; then
      mark_note "[$prov] issuerUri apunta al ID del pool ($WIF_POOL_ID). Funciona, pero se recomienda usar el Tenant ID ($ENTRA_TENANT_ID)."
    else
      mark_warn "[$prov] issuerUri inesperado: $issuer (esperado: Tenant $ENTRA_TENANT_ID o Pool $WIF_POOL_ID)"
    fi
  fi

  # audience
  if gcloud iam workload-identity-pools providers describe "$prov" \
      --location=global --workload-identity-pool="$WIF_POOL_ID" \
      --project="$PROJECT_ID" --format='value(oidc.allowedAudiences)' \
      | tr ';' '\n' | grep -q "$aud"; then
    mark_ok "[$prov] allowedAudiences contiene: $aud"
  else
    mark_fail "[$prov] allowedAudiences NO contiene esperado: $aud"
  fi

  # attribute-mapping mínimo (google.subject) recomendado
  mapping=$(gcloud iam workload-identity-pools providers describe "$prov" \
      --location=global --workload-identity-pool="$WIF_POOL_ID" \
      --project="$PROJECT_ID" --format='yaml(attributeMapping)' 2>/dev/null || true)
  if [[ -n "$mapping" ]]; then
    if grep -q "google.subject: assertion.sub" <<<"$mapping"; then
      mark_ok "[$prov] attributeMapping incluye google.subject"
    else
      mark_warn "[$prov] attributeMapping no incluye google.subject=assertion.sub (recomendado)"
    fi
  else
    mark_warn "[$prov] no tiene attributeMapping (recomendado)"
  fi

  # attribute-condition requerida (solo si definimos una esperada)
  if [[ -n "${ATTR_COND[$prov]:-}" ]]; then
    cond="${ATTR_COND[$prov]}"
    cond_val=$(gcloud iam workload-identity-pools providers describe "$prov" \
      --location=global --workload-identity-pool="$WIF_POOL_ID" \
      --project="$PROJECT_ID" --format='value(attributeCondition)' 2>/dev/null || echo "")
    if [[ "$cond_val" == "$cond" ]]; then
      mark_ok "[$prov] attributeCondition presente: $cond"
    else
      mark_fail "[$prov] falta attributeCondition recomendado: $cond"
    fi
  fi
done
echo

# ---------- 3) Service Accounts y bindings WIF ----------
info "3) Comprobando Service Accounts y binding de impersonation (roles/iam.workloadIdentityUser)…"
for name in "${SAS[@]}"; do
  sa="${name}@${PROJECT_ID}.iam.gserviceaccount.com"
  if gcloud iam service-accounts describe "$sa" --project "$PROJECT_ID" >/dev/null 2>&1; then
    mark_ok "SA existe: $sa"
    if gcloud iam service-accounts get-iam-policy "$sa" --project "$PROJECT_ID" --format="yaml" | grep -q "$PRINCIPAL_SET_POOL"; then
      mark_ok "  -> impersonation via principalSet (POOL) OK (${PRINCIPAL_SET_POOL})"
    else
      mark_fail "  -> falta binding roles/iam.workloadIdentityUser con principalSet del POOL (${PRINCIPAL_SET_POOL})"
    fi
  else
    mark_fail "SA NO existe: $sa"
  fi
done
echo

# ---------- 4) Roles custom y permisos ----------
info "4) Comprobando roles CUSTOM y permisos clave…"
for role in "${!CUSTOM_ROLES_PERMS[@]}"; do
  if gcloud iam roles describe "$role" --project "$PROJECT_ID" >/tmp/_role.yaml 2>/dev/null; then
    want="${CUSTOM_ROLES_PERMS[$role]}"
    missing=0
    for perm in $want; do
      if grep -q "$perm" /tmp/_role.yaml; then :; else
        missing=1; mark_fail "[$role] falta permiso: $perm"
      fi
    done
    [[ $missing -eq 0 ]] && mark_ok "[$role] permisos esperados presentes"
  else
    mark_fail "Role custom faltante: $role"
  fi
done
echo

# ---------- 5) Auditoría (Data Access) para container.googleapis.com ----------
info "5) Comprobando AuditConfigs para container.googleapis.com (ADMIN_READ/DATA_READ/DATA_WRITE)…"
gcloud projects get-iam-policy "$PROJECT_ID" --format="yaml(auditConfigs)" >/tmp/_audit.yaml || true
if grep -q "service: container.googleapis.com" /tmp/_audit.yaml; then
  need=(ADMIN_READ DATA_READ DATA_WRITE)
  okflags=0
  for f in "${need[@]}"; do
    if grep -A4 "service: container.googleapis.com" /tmp/_audit.yaml | grep -q "$f"; then
      okflags=$((okflags+1))
    else
      mark_fail "AuditConfig container.googleapis.com: falta $f"
    fi
  done
  [[ $okflags -eq 3 ]] && mark_ok "AuditConfig container.googleapis.com: ADMIN_READ/DATA_READ/DATA_WRITE habilitados"
else
  mark_fail "No hay AuditConfig para container.googleapis.com"
fi
echo

# ---------- 6) Logs Router -> Pub/Sub publisher ----------
info "6) Comprobando que cloud-logs@system.gserviceaccount.com tenga roles/pubsub.publisher…"
if gcloud projects get-iam-policy "$PROJECT_ID" \
  --flatten="bindings[].members" \
  --filter="bindings.members:serviceAccount:cloud-logs@system.gserviceaccount.com" \
  --format="value(bindings.role)" | grep -q "^roles/pubsub.publisher$"; then
  mark_ok "cloud-logs@system.gserviceaccount.com -> roles/pubsub.publisher OK"
else
  mark_fail "Falta roles/pubsub.publisher para cloud-logs@system.gserviceaccount.com"
fi
echo

# ---------- 7) OS Config ----------
info "7) Comprobando OS Config (API y metadata enable-osconfig)…"
if gcloud services list --enabled --project "$PROJECT_ID" --format="value(config.name)" | grep -q "^osconfig.googleapis.com$"; then
  mark_ok "API osconfig habilitada"
else
  mark_fail "API osconfig NO habilitada"
fi
if gcloud compute project-info describe --project "$PROJECT_ID" | grep -q "enable-osconfig.*TRUE"; then
  mark_ok "Metadata enable-osconfig=TRUE presente"
else
  mark_warn "No se encontró metadata enable-osconfig=TRUE (verifica en project-info)"
fi
echo

# ---------- 8) Agentless ----------
info "8) Comprobando Agentless (role y bindings)…"
if gcloud iam roles describe "MDCAgentlessScanningRole" --project "$PROJECT_ID" >/dev/null 2>&1; then
  mark_ok "Role MDCAgentlessScanningRole existe"
else
  mark_fail "Falta role MDCAgentlessScanningRole"
fi
if gcloud projects get-iam-policy "$PROJECT_ID" \
  --flatten="bindings[].members" \
  --filter="bindings.members:serviceAccount:${AGENTLESS_SA}" \
  --format="value(bindings.role)" | grep -q "projects/${PROJECT_ID}/roles/MDCAgentlessScanningRole"; then
  mark_ok "Binding Agentless SA -> MDCAgentlessScanningRole OK"
else
  mark_fail "Falta binding Agentless SA -> MDCAgentlessScanningRole"
fi
if gcloud projects get-iam-policy "$PROJECT_ID" \
  --flatten="bindings[].members" \
  --filter="bindings.members:serviceAccount:${COMPUTE_SYSTEM_SA}" \
  --format="value(bindings.role)" | grep -q "^roles/cloudkms.cryptoKeyEncrypterDecrypter$"; then
  mark_ok "Compute System SA tiene cloudkms.cryptoKeyEncrypterDecrypter (CMEK listo)"
else
  mark_warn "No se encontró cloudkms.cryptoKeyEncrypterDecrypter para ${COMPUTE_SYSTEM_SA} (solo necesario si usas CMEK)"
fi
echo

# ---------- 9) DSPM ----------
info "9) Comprobando DSPM (SA y role)…"
if gcloud projects get-iam-policy "$PROJECT_ID" \
  --flatten="bindings[].members" \
  --filter="bindings.members:serviceAccount:mdc-data-sec-posture-storage@${PROJECT_ID}.iam.gserviceaccount.com" \
  --format="value(bindings.role)" | grep -q "projects/${PROJECT_ID}/roles/MDCDataSecurityPostureStorageRole"; then
  mark_ok "DSPM SA -> MDCDataSecurityPostureStorageRole OK"
else
  mark_fail "DSPM: falta binding de role custom a SA"
fi
echo

# ---------- 10) GAR Assessment ----------
info "10) Comprobando Artifact Assessment (roles en SA)…"
AA_SA="mdc-containers-artifact-assess@${PROJECT_ID}.iam.gserviceaccount.com"
need_roles=("roles/storage.objectUser" "roles/artifactregistry.writer" "projects/${PROJECT_ID}/roles/MDCWritingGarAssessmentsRole")
for r in "${need_roles[@]}"; do
  if gcloud projects get-iam-policy "$PROJECT_ID" \
    --flatten="bindings[].members" \
    --filter="bindings.members:serviceAccount:${AA_SA}" \
    --format="value(bindings.role)" | grep -q "^${r}$"; then
    mark_ok "ArtifactAssess: ${AA_SA} tiene $r"
  else
    mark_fail "ArtifactAssess: falta $r en ${AA_SA}"
  fi
done
echo

# ---------- 11) CIEM ----------
info "11) Comprobando CIEM (provider + roles en SA)…"
CIEM_SA="microsoft-defender-ciem@${PROJECT_ID}.iam.gserviceaccount.com"
# issuer ya fue validado arriba con nota especial

# audience y attributeCondition
if gcloud iam workload-identity-pools providers describe "ciem-discovery" \
  --location=global --workload-identity-pool="$WIF_POOL_ID" --project="$PROJECT_ID" >/tmp/_ciem.yaml 2>/dev/null; then
  if grep -A3 "allowedAudiences:" /tmp/_ciem.yaml | grep -q "api://mciem-gcp-oidc-app"; then
    mark_ok "CIEM audience OK (api://mciem-gcp-oidc-app)"
  else
    mark_fail "CIEM audience no encontrado (api://mciem-gcp-oidc-app)"
  fi
  if grep -q "attributeCondition: ${ATTR_COND["ciem-discovery"]}" /tmp/_ciem.yaml; then
    mark_ok "CIEM attributeCondition OK (${ATTR_COND["ciem-discovery"]})"
  else
    mark_fail "CIEM falta attributeCondition (${ATTR_COND["ciem-discovery"]})"
  fi
  # mapping recomendado
  if grep -q "google.subject: assertion.sub" /tmp/_ciem.yaml; then
    mark_ok "CIEM attributeMapping incluye google.subject"
  else
    mark_warn "CIEM attributeMapping no incluye google.subject=assertion.sub (recomendado)"
  fi
else
  mark_fail "CIEM provider no existe"
fi

# Roles de la SA
if gcloud projects get-iam-policy "$PROJECT_ID" \
  --flatten="bindings[].members" \
  --filter="bindings.members:serviceAccount:${CIEM_SA}" \
  --format="value(bindings.role)" | grep -q "^roles/iam.securityReviewer$"; then
  mark_ok "CIEM SA tiene roles/iam.securityReviewer"
else
  mark_fail "CIEM SA no tiene roles/iam.securityReviewer"
fi
if gcloud projects get-iam-policy "$PROJECT_ID" \
  --flatten="bindings[].members" \
  --filter="bindings.members:serviceAccount:${CIEM_SA}" \
  --format="value(bindings.role)" | grep -q "^roles/viewer$"; then
  mark_ok "CIEM SA tiene roles/viewer"
else
  mark_fail "CIEM SA no tiene roles/viewer"
fi
echo

# ---------- Resumen ----------
echo
info "===== RESUMEN ====="
echo "PASS: $pass | FAIL: $fail | WARN: $warnc | NOTES: $notes"
[[ $fail -gt 0 ]] && bad "Revisa los FAIL anteriores. Log: $LOG" || ok "Todo se ve consistente. Log: $LOG"
