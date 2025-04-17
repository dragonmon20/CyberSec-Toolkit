# Windows Recall Feature Management

This README provides information about managing the Windows Recall feature using the Deployment Image Servicing and Management (DISM) command-line tool.

## Overview

The Windows Recall feature is a system component that can be checked, disabled, or enabled using DISM commands. These commands allow administrators to manage this feature on Windows systems.

## Commands

### Check Recall Feature Status

```powershell
Dism /Online /Get-Featureinfo /Featurename:Recall
```

This command displays detailed information about the current state of the Recall feature on the running Windows installation. The output includes whether the feature is enabled or disabled, along with other relevant information about the feature.

### Disable Recall Feature

```powershell
Dism /Online /Disable-Feature /Featurename:Recall
```

This command disables the Recall feature on the current running Windows installation. After running this command, the Recall functionality will be turned off.

### Enable Recall Feature

```powershell
Dism /Online /Enable-Feature /Featurename:Recall
```

This command enables the Recall feature on the current running Windows installation. After running this command, the Recall functionality will be turned on.

## Notes

- These commands must be run with administrator privileges
- Changes may require a system restart to take effect
- The "/Online" parameter specifies that you're working with the currently running operating system

## Usage Examples

### To check if Recall is currently enabled:

1. Open Command Prompt as Administrator
2. Run: `Dism /Online /Get-Featureinfo /Featurename:Recall`
3. Review the output to determine the feature state

### To disable Recall:

1. Open Command Prompt as Administrator
2. Run: `Dism /Online /Disable-Feature /Featurename:Recall`
3. Follow any prompts (such as restart requests)

### To enable Recall:

1. Open Command Prompt as Administrator
2. Run: `Dism /Online /Enable-Feature /Featurename:Recall`
3. Follow any prompts (such as restart requests)
