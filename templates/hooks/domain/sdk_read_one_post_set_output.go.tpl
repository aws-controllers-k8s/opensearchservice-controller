	err = rm.setAutoTuneOptions(ctx, ko)
	if err != nil {
		return &resource{ko}, err
	}
	checkDomainStatus(resp, ko)
