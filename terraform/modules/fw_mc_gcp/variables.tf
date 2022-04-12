/**
 * Copyright 2022 MobiledgeX, Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

variable "environ_tag" {
  description = "Environment the module belongs to"
  type        = string
}

variable "gitlab_ip" {
  description = "Gitlab IP"
  type        = string
}

variable "mc_federation_source_ranges" {
  description = "Source CIDRs for MC federation service"
  default     = [ "0.0.0.0/0" ]
}

variable "mc_federation_port" {
  description = "MC federation service port"
  default     = "30001"
}

variable "mc_ldap_port" {
  description = "MC LDAP service port"
  default     = "9389"
}

variable "mc_notify_port" {
  description = "MC notify service port"
  default     = "52001"
}
