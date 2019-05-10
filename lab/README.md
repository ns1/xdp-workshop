## Lab VM
This workshop will be done with the aid of a VM running in [Virtual Box v6.0](https://www.virtualbox.org/). The VM itself is an Ubuntu 19.04 based machine that has all of the tooling and development binaries preloaded for use throughout the various exercises we will be exploring.

### Initial Setup
In order to use this VM properly there are a few prerequisites that need to be in place. You will need to download and install [Virtual Box v6.0](https://www.virtualbox.org/wiki/Downloads) for your host platform. Please follow the excelent instructions on their website for the install process.

#### Network Setup

Once you have Virtual Box installed you will need to configure a [Host-Only Network](https://www.virtualbox.org/manual/UserManual.html#network_hostonly), if you don't already have one configured.

##### Check Host Only Network Configuration

To check if you already have a host only network configured, you can either use the GUI like so:

1. Open the VirtualBox GUI
1. Click `File` at the top left
1. In the menu that appears select `Host Network Manager...`
1. A pop up window will appear
1. In the pop up window that just appeared verify if there is any entries in the table within the pop up window named `vboxnet0`.

or via the CLI like so:

```
VBoxManage list hostonlyifs
```

And verify that there is a `vboxnet0` entry returned.

##### Setup Host Only Network Configuration
If you do **not** already have a host only network configured, you can create one either from the GUI like so:

1. Open the VirtualBox GUI
1. Click `File` at the top left
1. In the menu that appears select `Host Network Manager...`
1. A pop up window will appear
1. In the pop up window that just appeared click `Create` at the top left
1. There should now be an entry in the table bellow the `Create` button
1. Select the newly created entry in the table
1. Click `Properties` at the top of the pop up window
1. A tabbed section will appear at the bottom of the pop up window
1. Select the `DHCP Server` tab
1. Check the `Enable Server` checkbox
1. Click the `Apply` button at the bottom of the pop up window
1. Click the `Close` button at the bottom of the pop up window

or via the CLI like so:

```
VBoxManage hostonlyif create
VBoxManage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1
VBoxManage dhcpserver add --ifname vboxnet0 --ip 192.168.56.1 --netmask 255.255.255.0 --lowerip 192.168.56.2 --upperip 192.168.56.254
VBoxManage dhcpserver modify --ifname vboxnet0 --enable
```

### Import the OVA
You can either download the [ova file here]() or build it locally depending on your preferences.

> NOTE: For building the ove file locally see the instructions in the `Build the VM` section bellow.

You can import the OVA file either from the GUI like so:

1. Open the VirtualBox GUI
1. Click `Import` at the top of the window
1. A pop window will appear
1. In the pop up window click the folder icon on the top right next to the text box
1. Navigate to the either downloaded or built OVA file
1. Once found and selected click `Next`
1. On the next page click `Import`
1. Wait for the import process to complete

or via the CLI like so:

```
VBoxManage import ${ova_file_path}
```

### Build the VM
If your preference is to build the VM from scratch you will need to download and install [Packer](https://www.packer.io/) by HashiCorp to facilitate the build process.

Download the version of packer for your host platform [from here](https://www.packer.io/downloads.html), and then install it based on your local configuration. You **must** have Virtual Box already installed and configured from the `Initial Setup` section above.

#### Build Process
The build process relies on a BASH script located at `setup/vm-setup.sh` for review and leverages the packer configuration `vm-definition.json` relative to this directory. It will also inject the SSH credentials located in `ssh/*` into the VM for use throughout the workshop. Review these files accordingly.

> NOTE: Never under any circumstances consider these SSH credentials safe to use outside of this workshop and outside of the sandboxed VM.

The build process is simply running the following commands locally from this directory:
```
packer build vm-definition.json
```

This will start the build process and display the VM during its install. Once complete you will have the built machine both setup in Virtual Box, as well as an OVA file in a subdirectory called `xdp-test-lab-virtualbox`.

### Final configuration and Starting the VM

Once you have either imported the prebuilt OVA or built one locally you can now start the lab VM and begin using it for testing.

#### Setup shared folders
One final step of configuration is needed to finish the process before starting the VM for the first time. We want to share the workshop repo between the host and VM so that you are able to manipulate the source code in the environment you are most comfortable with.

You can share the repo folder via the GUI like so:

1. Open the VirtualBox GUI
1. Select the `xdp-test-lab` machine in the list of the left
1. Click `Settings` on the top of the window
1. A pop up window will appear
1. In the pop up window select `Shared Folders` from the list on the left
1. Click the blue folder icon with a green plus on the right hand side of the empty table
1. Another pop up window will appear
1. Click the drop down error next the `Folder Path` text box.
1. Select `Other`
1. Another pop up window will appear
1. Navigate the root directory of this repo and select it
1. The `Folder Name` text box should be filled out with `xdp-workshop`
1. Check the `Auto-Mount` check box
1. Enter `/home/xdp/workspace/xdp-workshop` in the `Mount point` text box
1. Click `Ok`
1. The pop up window will close
1. Click `Ok`
1. The pop up window will close and leave you at the main VirtualBox GUI

#### Start VM
You can start the VM from the GUI like so:

1. Open the VirtualBox GUI
1. Select the `xdp-test-lab` machine in the list on the left
1. Click `Start` at the top of the window
1. A pop window will appear and the machine will boot into Ubuntu

or via the CLI like so:

```
VBoxManage startvm xdp-test-lab
```

#### Login
You can login to the machine for the first time using the predefined credentials via the window that opens when the machine is started:

User: `xdp`

Password: `xdp`

> NOTE: Never under any circumstances consider these user/password credentials safe to use outside of this workshop and outside of the sandboxed VM.

Once logged in note the IP address returned by running the following command inside the VM:
```
$ ip a s enp0s8 | grep 'inet ' | awk '{print $2}' | sed -e 's:/24::'
```

This IP address may be used for SSH access to the VM throughout the workshop using either the above user/password combination or via the included ssh key `ssh/id_rsa` relative to this directory.