package controller

type NBIAPIs struct {
	allApis *AllApis
}

func NewNBIAPI(allApis *AllApis) *NBIAPIs {
	return &NBIAPIs{
		allApis: allApis,
	}
}
