Platform9 Managed Kubernetes cluster running on Packet Bare Metal
==================================================
[platform9.com](http://platform9.com)  [@Platform9Sys](http://twitter.com/platform9sys) [packet.net](http://packet.net) [@PacketHost](http://twitter.com/packethost)

This is a [Terraform](http://terraform.io) "Plan" that will build a fully functional 
Kubernetes enviorment on top of Packet hardware. This is not ready for production yet...

Prerequisites
-------------
Make sure that [Terraform is installed.](https://www.terraform.io/intro/getting-started/install.html)

Clone this repo `git clone https://github.com/platform9/packet-k8s.git`

Move into the git repo directory. `cd packet-k8s`

Record your Platform9 OpenStack.rc

This can be collected from the Platform9 UI on the Access & Security section in the API Access Tab.

Your Platfomr9 UI URL and Credentials should have been emailed to you.

Usage
-----
```bash
  terraform init #might require sudo
  terraform plan -var 'key_name={}' -var 'OS_AUTH_URL={}' -var 'OS_REGION_NAME={}' -var 'OS_USERNAME={}' -var 'OS_PASSWORD={}' -var 'OS_TENANT_NAME={}' -var 'OS_TENANT_NAME={}' -var 'PF9_Account_Endpoint={}' -out=my-tf.plan
  # For example:
  # terraform plan -var 'key_name=MySSHKey' -var 'OS_AUTH_URL=https://endpoint.platform9.net/keystone/v2.0' -var 'OS_REGION_NAME=Region1' -var 'OS_USERNAME=user@email.tld' -var 'OS_PASSWORD=S0meP@$$' -var 'OS_TENANT_NAME=service' -var 'PF9_Account_Endpoint=endpoint.platform9.net' -out=my-tf.plan
  terraform apply my-tf.plan
```
