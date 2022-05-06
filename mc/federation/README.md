## Federation Interconnect

### Initial Setup

##### Operator sets up Cloudlets

| User Action                  | OP1                   | OP2                   |
| ---------------------------- | --------------------- | --------------------- |
| Operator1 onboards cloudlets | - cloudlet onboarding |                       |
| Operator2 onboards cloudlets |                       | - cloudlet onboarding |

###Federation Planning

##### Operator sets up self federator 

| User Action                                                  | OP1                                     | OP2                                     |
| ------------------------------------------------------------ | --------------------------------------- | --------------------------------------- |
| Operator1 creates self federator (API:`/auth/federator/self/create`) | - defines federator object              |                                         |
|                                                              | - returns federation key                |                                         |
| Operator1 defines AZs (API:`/federator/self/zone/create`)    | - create zone = collection of cloudlets |                                         |
| Operator2 creates self federator (API:`/auth/federator/self/create`) |                                         | - defines federator object              |
|                                                              |                                         | - returns federation key                |
| Operator1 defines AZs (API:`/federator/self/zone/create`)    |                                         | - create zone = collection of cloudlets |

##### Operator sets up partner federation and marks zones to be shared with them

| User Action                                                  | OP1                                                          | OP2                                               |
| ------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------- |
| Operator1 creates partner federation with Operator2 (API:`/auth/federation/create`) | - defines partner federation object                          |                                                   |
|                                                              | - this only adds entry in DB, for federation to be setup, it has be registered (i.e user must call API:`/auth/federation/register`) |                                                   |
| Operator1 marks zones to be shared with partner (API:`/federator/self/zone/share`) | - marks zones to be shared with partner federator            |                                                   |
| Operator2 creates partner federation with Operator1 (API:`/auth/federation/create`) |                                                              | - defines partner federation object               |
|                                                              |                                                              | - this only adds entry in DB                      |
| Operator2 marks zones to be shared with partner (API:`/auth/federator/self/zone/share`) |                                                              | - marks zones to be shared with partner federator |

### Federation Manage

##### Operator registers federation with partner federator

| User Action                                                  | OP1                                                          | OP2                                                          |
| ------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------------------------------------ |
| Operator1 registers federation with partner Operator2 (API:`/auth/federation/register`) | - calls **POST** `/operator/partner`                         |                                                              |
|                                                              |                                                              | - validate federation                                        |
|                                                              |                                                              | - stores partner federation details in DB                    |
|                                                              |                                                              | - set `PartnerRoleAccessToSelfZones` to true as part of federation object |
|                                                              |                                                              | - shares all the zones                                       |
|                                                              | - receives all the zones and stores zone info in DB          |                                                              |
|                                                              | - stores partner federation details in DB                    |                                                              |
|                                                              | - set `PartnerRoleShareZonesWithSelf` to true as part of federation object |                                                              |

##### Operator updates its Federation attributes

| User Action                                                  | OP1                                                          | OP2                                         |
| ------------------------------------------------------------ | ------------------------------------------------------------ | ------------------------------------------- |
| Operator1 updates its federation attributes like MCC/MNC/LocatorEndPoint (API:`/auth/federator/self/update`) | - validate update fields                                     |                                             |
|                                                              | - calls **PUT** `/operator/partner` for all the partner OPs (with whom this OP is sharing zones i.e. role is to **share** zones) about the update of federation attributes |                                             |
|                                                              |                                                              | - validate federation                       |
|                                                              |                                                              | - update federation attributes of OP1 in DB |
|                                                              | - store updated details in DB                                |                                             |

##### Operator shares new zone after federation is setup

| User Action                                                  | OP1                        | OP2                                                          |
| ------------------------------------------------------------ | -------------------------- | ------------------------------------------------------------ |
| Operator2 shares new zone. (API:`/auth/federator/self/zone/share`) |                            | - share zone                                                 |
|                                                              |                            | - calls **POST** `/operator/notify/zone` to notify partner OP (with whom this OP is sharing zones i.e. role is to **share** zones) about this zone |
|                                                              | - validate federation      |                                                              |
|                                                              | - store zone details in DB |                                                              |

##### Operator unshares a zone after federation is setup

| User Action                                                  | OP1                            | OP2                                                          |
| ------------------------------------------------------------ | ------------------------------ | ------------------------------------------------------------ |
| Operator2 unshares a  zone. (API:`/auth/federator/self/zone/unshare`) |                                | - unshare zone                                               |
|                                                              |                                | - ensure that it is not being used/registered by an OP       |
|                                                              |                                | - calls **DELETE** `/operator/notify/zone` to notify partner OP (with whom this OP is sharing zones i.e. role is to **share** zones) about the unsharing of this zone |
|                                                              | - validate federation          |                                                              |
|                                                              | - remove zone from shared list |                                                              |

##### Operator registers a zone after federation is setup

| User Action                                                  | OP1                                | OP2                                            |
| ------------------------------------------------------------ | ---------------------------------- | ---------------------------------------------- |
| Operator1 registers OP2  zone. (API:`/auth/federator/partner/zone/register`) | - check if zone exists             |                                                |
|                                                              | - calls **POST** `/operator/zone`  |                                                |
|                                                              |                                    | - validate federation                          |
|                                                              |                                    | - store registering OP details along with zone |
|                                                              | - store OP details along with zone |                                                |

##### Operator deregisters a zone after federation is setup

| User Action                                                  | OP1                                 | OP2                            |
| ------------------------------------------------------------ | ----------------------------------- | ------------------------------ |
| Operator1 deregisters OP2  zone. (API:`/auth/federator/partner/zone/deregister`) | - check if zone exists              |                                |
|                                                              | - calls **DELETE** `/operator/zone` |                                |
|                                                              |                                     | - validate federation          |
|                                                              |                                     | - delete registered OP details |
|                                                              | - delete registered OP details      |                                |

##### Operator deregisters partner federation

| User Action                                                  | OP1                                                       | OP2                   |
| ------------------------------------------------------------ | --------------------------------------------------------- | --------------------- |
| Operator1 deregisters federation with OP2 (API:`/auth/federation/deregister`) | - validate that all the partner OP zones are deregistered |                       |
|                                                              | - calls **DELETE** `/operator/partner`                    |                       |
|                                                              |                                                           | - validate federation |
|                                                              |                                                           | - delete OP1 details  |
|                                                              | - delete all details of OP2 zones                         |                       |

##### Operator deletes partner federation

| User Action                                                  | OP1                                        | OP2  |
| ------------------------------------------------------------ | ------------------------------------------ | ---- |
| Operator1 remove OP2 as federation partner (API:`/auth/federation/delete`) | - validate that federation is deregistered |      |
|                                                              | - delete OP2 federation details            |      |
