# VMBuilder.ps1

A PowerShell script to provision Hyper-V virtual machines from templates, with support for Active Directory integration and batch creation.

## 🧾 Features

- **Create** virtual machines from predefined templates.
- **Destroy** existing virtual machines and remove associated files.
- **AD Join/Leave**: Optionally join or remove VMs from an Active Directory domain.
- **Batch creation**: Specify the number of VMs to create in a single operation.
- **Support for multiple OS templates**:
  - `WindowsVMBuilder`
  - `UbuntuVMBuilder`

### VM Creation Workflow

- Creates a new VM by cloning a predefined template.
- Executes a user-provided update script on the created VM.
- Optionally joins the VM to an Active Directory domain.
- Copies user-provided files to the VM file system.
- Copies and executes user-provided scripts on the VM.

## 🧰 Templates

A template is an existing Hyper-V virtual machine with:

- One preconfigured administrative user.
- SSH access (username/password).
- For **Windows** templates:
  - `gsudo` installed (https://winget.run/pkg/gerardog/gsudo)
- For **Linux** templates:
  - The following line in `/etc/sudoers`:
    ```bash
    <user> ALL=(root) NOPASSWD: /tmp/init.sh
    ```

## ⚙️ Usage

```powershell
.\VMBuilder.ps1 -ConfigName "MyConfig" [-Nb 3] [-Create] [-Destroy] [-AD]
```

### Parameters

| Name         | Type    | Description                                                                 |
|--------------|---------|-----------------------------------------------------------------------------|
| `ConfigName` | String  | Name of the configuration folder containing all VM parameters               |
| `Nb`         | Int     | (Optional) Number of VMs to create. Default is `1`                          |
| `Create`     | Switch  | If specified, creates the VM(s)                                             |
| `Destroy`    | Switch  | If specified, destroys the VM(s) and cleans up associated files             |
| `AD`         | Switch  | Used with `-Create` to join VMs to AD, or with `-Destroy` to remove them    |

> 💡 **Note**: If the source VHD is in use, make sure the VM is stopped and all snapshots are deleted before proceeding.

## 🏗 Architecture

- Base class: `VMBuilder`
- Subclasses:
  - `UbuntuVMBuilder`
  - `WindowsVMBuilder`
- Uses the static method `GetBuilders` to instantiate the correct builder based on the OS.

## 📁 Configuration

The script expects a configuration directory named after the `ConfigName` parameter. This directory defines all provisioning parameters (template name, network settings, credentials, etc.).

Two sample configurations are provided: one for **Linux** and one for **Windows**.

Each configuration contains:

- A **data** directory: files to be copied to the VM.
- A **scripts** directory: shell or PowerShell scripts to run after VM creation.
- `update.sh` or `update.ps1`: used to apply updates on the created VM.
- `get-infos.sh` or `get-infos.ps1`: gathers information such as version numbers or access tokens, depending on the packages installed. Results are stored in the **logs** directory.

### Linux Sample

- Based on an Ubuntu 24 Server template.
- **scripts**:
  - Docker setup using Snap
  - Docker Compose installation
- **data**: includes a `compose.yaml` file

### Windows Sample

- Based on a Windows 11 Pro template.
- **scripts**: installs [RustDesk](https://rustdesk.com/)
- **data**: includes the RustDesk setup files

## 📌 Requirements

- PowerShell
- [PuTTY](https://www.putty.org/)
- Hyper-V
- Permissions to join/leave Active Directory (when using `-AD`)

### Tested Environments

- **Host OS**:
  - Windows 11 Pro
  - Windows Server 2022
- **Template OS**:
  - Windows 11 Pro
  - Ubuntu 22.04, 23.10, 24.04

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.
