package mexos

/*
//MEXCheckEnvVars sets up environment vars and checks for credentials required for running
func MEXCheckEnvVars(mf *Manifest) error {
	// secrets to be passed via Env var still : MEX_CF_KEY, MEX_CF_USER, MEX_DOCKER_REG_PASS
	// TODO: use `secrets` or `vault`
	for _, evar := range []string{
		"MEX_CF_KEY",
		"MEX_CF_USER",
		"MEX_DOCKER_REG_PASS",
	} {
		if v := mexEnv(mf, evar); v == "" {
			return fmt.Errorf("missing env var %s", evar)
		}
	}
	return nil
}


func mexEnv(mf *Manifest, name string) string {
	v, ok := mf.Values.VaultEnvMap[name]
	if !ok {
		log.DebugLog(log.DebugLevelMexos, "error, env var not exist in vault", "name", name)
		return ""
	}
	return v
}

*/
