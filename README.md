DeviceTvmSoftwareVulnerabilities
| where VulnerabilitySeverityLevel == 'Critical' // Enter the severity of the vulnerability
| where OSPlatform == "Windows10" // Enter your Windows operating system (10,11)
| join kind=inner (
    DeviceTvmSoftwareEvidenceBeta
    | project DiskPaths, RegistryPaths, SoftwareVendor, SoftwareName, SoftwareVersion, DeviceId
) on SoftwareVendor, SoftwareName, SoftwareVersion, DeviceId
| project DeviceName, DeviceId, SoftwareName, OSPlatform, SoftwareVersion, VulnerabilitySeverityLevel,
tostring(DiskPaths), 
tostring(RegistryPaths), CveId
| summarize VulnerabilityCount = count() by DeviceName, DeviceId, SoftwareName, OSPlatform, SoftwareVersion, 
tostring(DiskPaths), 
tostring(RegistryPaths), CveId, VulnerabilitySeverityLevel
| sort by VulnerabilityCount desc
