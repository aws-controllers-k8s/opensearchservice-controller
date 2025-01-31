	if resp.DomainStatus.AutoTuneOptions != nil && resp.DomainStatus.AutoTuneOptions.State != nil {
		if *resp.DomainStatus.AutoTuneOptions.State == "ERROR" && !isAutoTuneSupported(&resource{ko}){
			// t2,t3 instances does not support AutoTuneOptions.DesiredState: DISABLED
			// set value manually to remove delta
			ko.Spec.AutoTuneOptions.DesiredState = aws.String("DISABLED")
		} else {
			ko.Spec.AutoTuneOptions.DesiredState = resp.DomainStatus.AutoTuneOptions.State
		}
	}

	if domainProcessing(&resource{ko}) {
		// Setting resource synced condition to false will trigger a requeue of
		// the resource. No need to return a requeue error here.
		ackcondition.SetSynced(&resource{ko}, corev1.ConditionFalse, nil, nil)
		return &resource{ko}, nil
	}
