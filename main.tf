provider "azurerm" {
  features {}
  subscription_id = "9fe14c7a-a14a-423e-8b3c-d59b3153d293"
}

resource "azurerm_kubernetes_cluster" "dids_cluster" {
  name                = "DIDS-K8S-Cluster"
  location            = "East US"
  resource_group_name = "DIDS-ResourceGroup"
  dns_prefix          = "didssecurity"

  default_node_pool {
    name       = "default"
    node_count = 2
    vm_size    = "Standard_DS2_v2"
  }

    identity {
    type         = "UserAssigned"
    identity_ids = ["/subscriptions/9fe14c7a-a14a-423e-8b3c-d59b3153d293/resourceGroups/DIDS-ResourceGroup/providers/Microsoft.ManagedIdentity/userAssignedIdentities/DIDS-Identity"]

  }

}

