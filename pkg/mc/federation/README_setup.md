# Federation Setup Step-by-Step

### Configuration

Federation will be between two separate platform deployments,
of potentially the same or different providers (one being EdgeCloud in our case).

EdgeCloud also supports a loopback mode, where two different operators on
edge cloud can create a federation between themselves on the same platform deployment.
There's no real point to this besides for testing.

### Setup Variables

The mcctl commands here are parameterized by the following environment variables.
Please set them accordingly.

```bash
# The provider and consumer platform domains. These will be the same for loopback mode.
export DOMAINP=opprov.example.org
export DOMAINC=opcons.example.org
# Federation is done between an operator org on the provider, and an operator org
# on the consumer. Specify those operator orgs here. These must already exist.
export OPPROV=opprov
export OPCONS=opcons
# Federation is multi-region, but in this example we specify just a single region
# on the provider and a single region on the consumer.
export REGIONP=regionp
export REGIONC=regionc
# The name of the cloudlet on the provider that will be shared.
# Must be part of the OPPROV organization.
export CLOUDLET=abc
# These are the names of the federation objects that will be created on
# each platform.
export FEDP=fedprov
export FEDC=fedcons
# A developer org on the consumer will onboard their application to the provider
# and then deploy it on the provider's resources.
# This org must already exist.
export DEVORG=devorg
```

## Create federation provider
```bash
mcctl --addr https://console.$DOMAINP federationprovider create name=$FEDP operatorid=$OPPROV regions=$REGIONP
```
outputs:
```bash
clientid: ***
clientkey: ***
targetaddr: https://console.***
tokenurl: https://console.***//oauth2/token
```
Save these values for use on the consumer. The clientkey cannot be retreived if lost (but can be regenerated).

### Set up federation provider zone bases

Set up the zone definitions from cloudlets. Only one cloudlet per zone is supported.
Run this command for each cloudlet to be shared as a zone.
   - Note: this can also be done later
```bash
mcctl --addr https://console.$DOMAINP federationprovider createzonebase zoneid=$CLOUDLET operatorid=$OPPROV region=$REGIONP cloudlets=$CLOUDLET
```

Check created zone base
```bash
mcctl --addr https://console.$DOMAINP federationprovider showzonebase
```

## Create federation consumer

On the consumer platform, use the credentials recieved out-of-band to connect to the provider platform.
We specify public to ensure cloudlets are visible to developers.
We specify auto-register options so we don't have to manually register zones shared with us.
```bash
mcctl --addr https://console.$DOMAINC federationconsumer create name=$FEDC operatorid=$OPCONS \
	partneraddr=$TARGETADDR partnertokenurl=$TOKENURL providerclientid=$CLIENTID providerclientkey=$CLIENTKEY \
	public=true autoregisterzones=true autoregisterregion=$REGIONC
```

## Check that federation is established

These will show the same federation context id for each, and status will be "Registered".
```bash
mcctl --addr https://console.$DOMAINP federationprovider show
mcctl --addr https://console.$DOMAINC federationconsumer show
```

### Provider share zones with consumer

We created the zone base to map cloudlets to zones.
Now we need to explicitly share a zone with a specific consumer.
On the provider platform:
```bash
mcctl --addr https://console.$DOMAINP federationprovider sharezone providername=$FEDP zones=$CLOUDLET
```

### View shared zones on consumer

Because autoregisterzones was set true, the consumer will automatically register the zone.
Otherwise, the consumer operator would need to run the "federationconsumer register" command.
We check on the consumer oeprator that the zone appears registered.
```bash
mcctl --addr https://console.$DOMAINC federationconsumer showzones
```

We can also see the cloudlet that was created for the zone. This allows users to choose
this cloudlet to deploy their Apps, which will deploy the App on the partner zone.
```bash
mcctl --addr https://console.$DOMAINC cloudlet show region=$REGIONC cloudlet=$CLOUDLET federatedorg=$OPCONS
```

## Onboarding

Before an App can be deployed on the partner, its definition and potentially its images
need to be onboarded (copied) to the partner.

### Image onboarding

This command is run by a developer on the consumer platform.
Images may be public images, or they may be images already uploaded into the
edge cloud platform.

Onboard a public VM image (will be onboarded by reference)
```bash
mcctl --addr https://console.$DOMAINC federation createimage organization=$DEVORG federationname=$FEDC \
  sourcepath=https://cloud-images.ubuntu.com/kinetic/current/kinetic-server-cloudimg-amd64.img \
  type=QCOW2 checksum=d4d5dae810da3bfbd903e830ca8aabed

Onboard a private VM image from the platform (will be uploaded to partner)
```bash
mcctl --addr https://console.$DOMAINC federation createimage organization=$DEVORG federationname=$FEDC \
  sourcepath=https://console.$DOMAINC/storage/v1/artifacts/$DEVORG/tinycore2.iso \
  type=QCOW2 checksum=d88148087fb68e4e1e1c6d5ecadddb45
```

Onboard a public docker image (will be onboarded by reference)
```bash
mcctl --addr https://console.$DOMAINC federation createimage organization=$DEVORG federationname=$FEDC \
  sourcepath=hashicorp/http-echo:0.2.3 type=DOCKER
```

Onboard a private docker image (will be copied)
```bash
mcctl --addr https://console.$DOMAINC federation createimage organization=$DEVORG federationname=$FEDC \
  sourcepath=docker.$DOMAINC/$DEVORG/http-echo:0.2.1 type=DOCKER
```

### Show images

Developer can see their onboarded images
```bash
mcctl --addr https://console.$DOMAINC federation showimages
```

Partner platform can also see onboarded images
```bash
mcctl --addr https://console.$DOMAINP federationprovider showimages
```

### Delete images

Images can be deleted by developer by specifying ID or triplet of {organization, federationname, name}
```bash
mcctl --addr https://console.$DOMAINC federation deleteimage id=da308dcb-6251-41ad-bba8-fa66cdfda2e5
```

```bash
mcctl --addr https://console.$DOMAINC federation deleteimage organization=$DEVORG federationname=$FEDC name=tinycore2.iso
```
