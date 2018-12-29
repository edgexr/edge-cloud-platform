package mexos

type genericItem struct {
	Item interface{} `json:"items"`
}

type genericItems struct {
	Items []genericItem `json:"items"`
}
