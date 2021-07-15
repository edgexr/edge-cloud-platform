package ormapi

var AppSelectors = []string{
	"cpu",
	"mem",
	"disk",
	"network",
	"connections",
	"udp",
}

var ClusterSelectors = []string{
	"cpu",
	"mem",
	"disk",
	"network",
	"tcp",
	"udp",
}

var CloudletSelectors = []string{
	"network",
	"utilization",
	"ipusage",
}

var CloudletUsageSelectors = []string{
	"resourceusage",
	"flavorusage",
}

var ClientApiUsageSelectors = []string{
	"api",
}

var ClientAppUsageSelectors = []string{
	"latency",
	"deviceinfo",
}

var ClientCloudletUsageSelectors = []string{
	"latency",
	"deviceinfo",
}
