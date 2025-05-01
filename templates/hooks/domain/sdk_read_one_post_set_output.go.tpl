	if resp.DomainStatus.AutoTuneOptions != nil {
		if resp.DomainStatus.AutoTuneOptions.State == svcsdktypes.AutoTuneStateError && !isAutoTuneSupported(&resource{ko}) {
			// t2,t3 instances does not support AutoTuneOptions.DesiredState: DISABLED
			// set value manually to remove delta
			ko.Spec.AutoTuneOptions.DesiredState = aws.String(string(svcsdktypes.AutoTuneStateDisabled))
		} else {
			ko.Spec.AutoTuneOptions.DesiredState = aws.String(string(resp.DomainStatus.AutoTuneOptions.State))
		}
	}

	if domainProcessing(&resource{ko}) {
		// Setting resource synced condition to false will trigger a requeue of
		// the resource. No need to return a requeue error here.
		ackcondition.SetSynced(&resource{ko}, corev1.ConditionFalse, nil, nil)
	} else {
		ackcondition.SetSynced(&resource{ko}, corev1.ConditionTrue, nil, nil)
	}

