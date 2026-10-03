param ([int]$TargetPID, [string]$C2_IP = "127.0.0.1")
Write-Host "[+] Executing SOC Containment Playbook..." -ForegroundColor Yellow
if ($TargetPID) {
    Stop-Process -Id $TargetPID -Force -ErrorAction SilentlyContinue
    Write-Host "[+] Terminated rogue process PID: $TargetPID" -ForegroundColor Green
}
if ($C2_IP) {
    New-NetFirewallRule -DisplayName "SOC-Block-C2-$CX"IP" -Direction Outbound -Action Block -RemoteAddress $C2_IP -Enabled True | Out-Null
    Write-Host "[+] Enforced perimeter outbound firewall block for: $C2_IP" -ForegroundColor Green
}
Write-Host "[+] Containment protocol complete." -ForegroundColor Green