package ethrpc

// RegisterApis checks the given modules' availability, generates an allowlist based on the allowed modules,
// and then registers all of the APIs exposed by the services.
func RegisterApis(apis []API, modules []string, srv *Server, exposeAll bool) error {
	// if bad, available := checkModuleAvailability(modules, apis); len(bad) > 0 {
	// 	log.Error("Unavailable modules in HTTP API list", "unavailable", bad, "available", available)
	// }
	// Generate the allow list based on the allowed modules
	allowList := make(map[string]bool)
	for _, module := range modules {
		allowList[module] = true
	}
	// Register all the APIs exposed by the services
	for _, api := range apis {
		if exposeAll || allowList[api.Namespace] || (len(allowList) == 0 && api.Public) {
			if err := srv.RegisterName(api.Namespace, api.Service); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkModuleAvailability checks that all names given in modules are actually
// available API services. It assumes that the MetadataApi module ("rpc") is always available;
// the registration of this "rpc" module happens in NewServer() and is thus common to all endpoints.
// func checkModuleAvailability(modules []string, apis []rpc.API) (bad, available []string) {
// 	availableSet := make(map[string]struct{})
// 	for _, api := range apis {
// 		if _, ok := availableSet[api.Namespace]; !ok {
// 			availableSet[api.Namespace] = struct{}{}
// 			available = append(available, api.Namespace)
// 		}
// 	}
// 	for _, name := range modules {
// 		if _, ok := availableSet[name]; !ok && name != rpc.MetadataApi {
// 			bad = append(bad, name)
// 		}
// 	}
// 	return bad, available
// }
