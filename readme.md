# VMBuilder.ps1

PowerShell script for provisioning HyperV virtual machines from templates, with support for domain integration and batch creation.

## 🧾 Features

- **Create** virtual machines from predefined templates.
- **Destroy** existing virtual machines and remove associated files.
- **AD Join/Leave**: Optionally join or remove VMs from an Active Directory domain.
- **Multiple VM creation**: Specify the number of VMs to create in one operation.
- **Support for different OS templates**:
  - `WindowsVMBuilder`
  - `UbuntuVMBuilder`

### Creation steps

- creates a new VM replicated from template
- executes a user-provided update script on the created VM
- joins created VM to AD if option is activated
- copies user-provided files on created VM file system
- copies and executes user-provided scripts on created VM file system 

## Templates

The template is an existing HyperV virtual machine, with:
- one administrative user set.
- SSH access (user/password).
- if **windows** based
-- gsudo installed: https://winget.run/pkg/gerardog/gsudo

## ⚙️ Usage

```powershell
.\VMBuilder.ps1 -ConfigName "MyConfig" [-Nb 3] [-Create] [-Destroy] [-AD]
```

### Parameters

| Name        | Type    | Description                                                                 |
|-------------|---------|-----------------------------------------------------------------------------|
| `ConfigName`| String  | Name of the configuration folder containing all VM parameters               |
| `Nb`        | Int     | (Optional) Number of VMs to create. Default is `1`                          |
| `Create`    | Switch  | If set, creates the VM(s)                                                   |
| `Destroy`   | Switch  | If set, destroys the VM(s) and cleans up associated files                  |
| `AD`        | Switch  | If set with `-Create`, joins VM(s) to domain; with `-Destroy`, removes them |

> 💡 **Note**: If the source VHD is in use, ensure the VM is stopped and all snapshots are deleted before proceeding.

## 🏗 Structure

- Base class: `VMBuilder`
- Subclasses:
  - `UbuntuVMBuilder`
  - `WindowsVMBuilder`
- Use of static method `GetBuilders` to instantiate the correct builder based on the OS.

## 📁 Configuration

The script expects a configuration directory named after the `ConfigName` parameter, which defines all VM provisioning parameters (e.g., template name, network, credentials, etc.).

Two samples are provided, for **linux** and **windows**, with:
- **data** directory containing files copied to created VM
- **scripts** directory containing shell scripts executed after VM creation
- **update.sh** or **update.ps1** to update created VM
- **get-infos.sh** or **get-infos.ps1** to get useful informations like version numbers, access tokens, ... depending on packages installed on created VM. These informations are stored in **logs** directory

## 📌 Requirements

- PowerShell
- putty on machine running VMBuilder.ps1
- HyperV
- Appropriate permissions to join/leave Active Directory (if using `-AD`)

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.
