{{- define "codex-gitlab-review.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "codex-gitlab-review.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "codex-gitlab-review.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "codex-gitlab-review.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "codex-gitlab-review.namespace" -}}
{{- default "default" .Release.Namespace -}}
{{- end -}}

{{- define "codex-gitlab-review.serviceFqdn" -}}
{{- printf "%s.%s.svc.%s" (include "codex-gitlab-review.fullname" .) (include "codex-gitlab-review.namespace" .) (.Values.clusterDomain | default "cluster.local") -}}
{{- end -}}

{{- define "codex-gitlab-review.bindPort" -}}
{{- $bindAddr := .bindAddr | default "" -}}
{{- $defaultPort := .defaultPort -}}
{{- if $bindAddr -}}
{{- regexFind "[0-9]+$" $bindAddr | default (printf "%v" $defaultPort) -}}
{{- else -}}
{{- printf "%v" $defaultPort -}}
{{- end -}}
{{- end -}}

{{- define "codex-gitlab-review.bindHost" -}}
{{- $bindAddr := .bindAddr | default "" -}}
{{- $defaultHost := .defaultHost | default "0.0.0.0" -}}
{{- if not $bindAddr -}}
{{- $defaultHost -}}
{{- else if regexMatch "^\\[[^]]+\\]:[0-9]+$" $bindAddr -}}
{{- regexFind "^\\[[^]]+\\]" $bindAddr | trimAll "[]" -}}
{{- else -}}
{{- regexFind "^[^:]+" $bindAddr -}}
{{- end -}}
{{- end -}}

{{- define "codex-gitlab-review.bindHostIsWildcard" -}}
{{- $host := .host -}}
{{- if or (eq $host "0.0.0.0") (eq $host "::") (eq $host "0:0:0:0:0:0:0:0") -}}
true
{{- else -}}
false
{{- end -}}
{{- end -}}

{{- define "codex-gitlab-review.gitlabDiscoveryMcpPort" -}}
{{- include "codex-gitlab-review.bindPort" (dict "bindAddr" .Values.config.codex.gitlabDiscoveryMcp.bindAddr "defaultPort" .Values.service.mcpPort) -}}
{{- end -}}

{{- define "codex-gitlab-review.gitlabDiscoveryMcpBindHost" -}}
{{- include "codex-gitlab-review.bindHost" (dict "bindAddr" .Values.config.codex.gitlabDiscoveryMcp.bindAddr "defaultHost" "0.0.0.0") -}}
{{- end -}}

{{- define "codex-gitlab-review.gitlabDiscoveryMcpBindHostIsWildcard" -}}
{{- include "codex-gitlab-review.bindHostIsWildcard" (dict "host" (include "codex-gitlab-review.gitlabDiscoveryMcpBindHost" .)) -}}
{{- end -}}

{{- define "codex-gitlab-review.serverBindPort" -}}
{{- include "codex-gitlab-review.bindPort" (dict "bindAddr" .Values.config.server.bindAddr "defaultPort" .Values.service.port) -}}
{{- end -}}

{{- define "codex-gitlab-review.serverBindHost" -}}
{{- include "codex-gitlab-review.bindHost" (dict "bindAddr" .Values.config.server.bindAddr "defaultHost" "0.0.0.0") -}}
{{- end -}}

{{- define "codex-gitlab-review.serverBindHostIsWildcard" -}}
{{- include "codex-gitlab-review.bindHostIsWildcard" (dict "host" (include "codex-gitlab-review.serverBindHost" .)) -}}
{{- end -}}
