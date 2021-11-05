	if domainProcessing(r) {
		return r, requeueWaitWhileProcessing
	}
