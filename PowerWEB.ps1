# SPDX-License-Identifier: MIT
[CmdletBinding()]
param([switch]$NoShow)
& (Join-Path $PSScriptRoot 'PowerWEB.Workbench.ps1') -NoShow:$NoShow
