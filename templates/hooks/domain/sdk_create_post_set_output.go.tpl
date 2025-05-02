	if resp.DomainStatus.AutoTuneOptions != nil {
		if strings.HasPrefix(string(resp.DomainStatus.AutoTuneOptions.State), "ENABLE") {
			ko.Spec.AutoTuneOptions.DesiredState = aws.String(string(svcsdktypes.AutoTuneStateEnabled))
		} else {
			ko.Spec.AutoTuneOptions.DesiredState = aws.String(string(svcsdktypes.AutoTuneStateDisabled))
		}
	}

	if domainProcessing(&resource{ko}) {
		// Setting resource synced condition to false will trigger a requeue of
		// the resource. No need to return a requeue error here.
		ackcondition.SetSynced(&resource{ko}, corev1.ConditionFalse, nil, nil)
		return &resource{ko}, nil
	}
