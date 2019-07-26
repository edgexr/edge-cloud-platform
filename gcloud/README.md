You can save money on your development and qa vm instances by stopping them when you are not using them.
The scripts in this directory makes it easy to do so. Also recommend making development and qa vm instances
pre-emptiable to drastically reduce the cost.

This assumes that you have gcloud CLI setup on your machine. If not please do so from https://cloud.google.com/sdk/docs/.
These scripts provide simple way to manage your vm instances from command line. If you find these useful, you can copy
them in your $HOME/bin and put $HOME/bin in your PATH in your ~/.bashrc or ~/.zshrc file depending on whether your 
default shell is bash or zsh.

# To start a vm. You can get the vm name from console.cloud.google.com. Starting a VM can take some time. 
# This is an asynchronous command, so it will exit without waiting for VM to be completely up and running.
gcp_start <vm-name>

#To  check status of a vm.
gcp_status <vm-name>


#To stop a vm
gcp_stop <vm-name>

#Instead of one vm-name you can also give list of vm-names separated by commas.
gcp-stop <vm-name1>,<vm-name2>,<vm-name3>
