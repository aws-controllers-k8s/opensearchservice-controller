	if err != nil && isServiceLinkedRoleMissing(err) {
		rm.metrics.RecordAPICall("CREATE", "CreateDomain", err)
		return nil, requeueWaitServiceLinkedRole
	}
