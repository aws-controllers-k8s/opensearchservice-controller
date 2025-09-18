	err = rm.setAutoTuneOptions(ctx, ko)
	if err != nil {
		return &resource{ko}, err
	}
	if domainProcessing(&resource{ko}) {
		// Setting resource synced condition to false will trigger a requeue of
		// the resource. No need to return a requeue error here.
		ackcondition.SetSynced(&resource{ko}, corev1.ConditionFalse, nil, nil)
		return &resource{ko}, nil
	}
