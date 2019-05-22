output "external_ip" {
  value = "${data.azurerm_public_ip.vm.ip_address}"
}
