{{/* Expand the name of the chart. */}}
{{- define "ko.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Fullname suffixed with the release. */}}
{{- define "ko.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/* Node agent resource name. */}}
{{- define "ko.nodeAgentName" -}}
{{- printf "%s-node-agent" (include "ko.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/* Container image reference. */}}
{{- define "ko.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion }}
{{- printf "%s:%s" .Values.image.repository $tag }}
{{- end }}

{{/* Common labels. */}}
{{- define "ko.labels" -}}
app.kubernetes.io/name: {{ include "ko.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end }}

{{/* Selector labels: immutable for the DaemonSet lifetime. */}}
{{- define "ko.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ko.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/* Service account name. */}}
{{- define "ko.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "ko.nodeAgentName" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}
